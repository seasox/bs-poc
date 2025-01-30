use std::{
    fs::File,
    io::{stdin, BufReader},
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::{self, ConsecAlloc, ConsecAllocator},
    hammerer::{
        blacksmith::{
            blacksmith_config::BlacksmithConfig,
            hammerer::{FuzzSummary, HammeringPattern, PatternAddressMapper},
        },
        make_hammer, HammerStrategy, Hammering,
    },
    memory::{mem_configuration::MemConfiguration, BitFlip, DataPattern},
    retry,
    victim::{self},
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar};
use indicatif_log_bridge::LogWrapper;
use itertools::Itertools;
use log::{info, warn};
use rand::{rngs::StdRng, SeedableRng};

/// CLI arguments for the `bench` binary.
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
    /// The hammering strategy to use.
    #[clap(long = "hammerer", default_value = "blacksmith")]
    hammerer: HammerStrategy,
    /// The number of rounds for benchmarking
    #[arg(long, default_value = "1000")]
    repeat: usize,
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

pub fn init_logging_with_progress() -> anyhow::Result<MultiProgress> {
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let progress = MultiProgress::new();
    LogWrapper::new(progress.clone(), logger).try_init()?;
    Ok(progress)
}

#[derive(Debug)]
#[allow(dead_code)]
struct RoundProfile {
    bit_flips: Vec<BitFlip>,
    pattern: DataPattern,
    duration: Duration,
}
#[derive(Debug)]
#[allow(dead_code)]
struct Profiling {
    rounds: Vec<RoundProfile>,
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
        ConsecAlloc::Hugepage(allocator::hugepage::HugepageAllocator::default());
    let block_size = alloc_strategy.block_size();

    let memory = allocator::alloc_memory(&mut alloc_strategy, mem_config, &pattern.mapping)?;

    let profile_hammer = make_hammer(
        &args.hammerer,
        &pattern.pattern,
        &pattern.mapping,
        mem_config,
        block_size,
        &memory,
        255,
        true,
        None,
    )?;
    let p = progress.add(ProgressBar::new(args.repeat as u64 * 2));
    let dpattern = DataPattern::Random(Box::new(StdRng::from_seed(rand::random())));

    // find affected locations (for targetted checks)
    let results = (0..10)
        .map(|_| {
            let mut victim = victim::MemCheck::new(&memory, dpattern.clone());
            profile_hammer.hammer(&mut victim)
        })
        .collect::<Result<Vec<_>, _>>()?;
    info!("Affected locations: {:?}", results);
    let flips: Vec<BitFlip> = results
        .into_iter()
        .flat_map(|r| r.victim_result)
        .unique_by(|f| f.addr)
        .collect();

    let hammerer = make_hammer(
        &args.hammerer,
        &pattern.pattern.clone(),
        &pattern.mapping.clone(),
        mem_config,
        block_size,
        &memory,
        50,
        false,
        Some(
            flips
                .iter()
                .map(|f| (f.addr & !0x1fff) as *const u8)
                .collect::<Vec<_>>(),
        ),
    )?;
    let each_attempt_hammerer = make_hammer(
        &args.hammerer,
        &pattern.pattern.clone(),
        &pattern.mapping.clone(),
        mem_config,
        block_size,
        &memory,
        50,
        true,
        None,
    )?;
    for (idx, hammerer) in [each_attempt_hammerer, hammerer].iter().enumerate() {
        println!(
            "{}",
            if idx == 0 {
                "Each attempt hammerer"
            } else {
                "Hammerer"
            }
        );
        for _ in 0..args.repeat {
            p.inc(1);
            let start = std::time::Instant::now();
            let mut victim = victim::TargetCheck::new(&memory, dpattern.clone(), flips.clone());
            let result = hammerer.hammer(&mut victim);
            let duration = std::time::Instant::now() - start;
            let bit_flips = match result {
                Ok(result) => {
                    info!(
                        "Profiling hammering round successful at attempt {}: {:?}",
                        result.attempt, result.victim_result
                    );
                    Some(result.victim_result)
                }
                Err(e) => {
                    warn!("Profiling hammering round not successful: {:?}", e);
                    None
                }
            };
            println!(
                "{:?}",
                RoundProfile {
                    bit_flips: bit_flips.unwrap_or_default(),
                    pattern: dpattern.clone(),
                    duration
                }
            );
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
