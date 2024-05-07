use std::{
    collections::{HashMap, HashSet},
    ptr::null,
};

use anyhow::Context;
use bs_poc::{
    forge::HammeringPattern,
    memory::DRAMAddr,
    util::{BlacksmithConfig, MemConfiguration},
};
use clap::Parser;
use itertools::Itertools;
use log::info;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The BlacksmithConfig
    #[clap(long = "config")]
    config: String,
    /// The JSON file containing hammering patterns to load
    #[clap(long = "load-json", default_value = "fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the JSON file
    #[clap(long = "pattern")]
    pattern: Option<String>,
    /// The mapping ID to load from the JSON file (optional, will determine most optimal pattern if omitted)
    #[clap(long = "mapping")]
    mapping: Option<String>,
}

unsafe fn _main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();

    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    // load patterns from JSON
    let patterns = match args.pattern {
        Some(pattern) => vec![HammeringPattern::load_pattern_from_json(
            args.load_json.clone(),
            pattern.clone(),
        )?],
        None => HammeringPattern::load_patterns(args.load_json.clone())?,
    };

    for pattern in patterns {
        let mappings = match &args.mapping {
            Some(mapping) => vec![pattern.find_mapping(&mapping).expect("mapping not found")],
            None => pattern.address_mappings,
        };

        for mapping in mappings {
            info!("Pattern {}", pattern.id);
            info!("Mapping {}", mapping.id);
            let victims = mapping
                .bit_flips
                .into_iter()
                .flatten()
                .map(|f| f.dram_addr)
                .collect::<Vec<_>>();
            info!("Victims: {:?}.", victims);

            let addrs = mapping
                .aggressor_to_addr
                .iter()
                .map(|(_, addr)| addr)
                .chain(victims.iter())
                .collect::<HashSet<_>>();

            let mut sets: HashMap<usize, Vec<DRAMAddr>> = HashMap::new();

            for addr in addrs {
                let virt = addr.to_virt(null(), mem_config) as usize;
                let virt = virt >> 20;
                //info!("{:?}, {:?}", virt, addr);
                let entry = sets.get(&virt);
                let mut entry = match entry {
                    None => Vec::new(),
                    Some(entry) => entry.clone(),
                };
                entry.push(addr.clone());
                sets.insert(virt, entry);
            }

            for k in sets.keys().sorted() {
                info!("{:#02x}: {:?}", k, sets[k]);
            }
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
