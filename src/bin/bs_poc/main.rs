use bs_poc::memory::{DRAMAddr, Memory};
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

    let mut memory = Memory::new();
    memory.alloc(MEM_SIZE)?;

    info!("allocated {} B of memory", MEM_SIZE);

    // check memory.start phys addr

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let hammerer = Hammerer {};
    info!("initialized hammerer");

    //RSA-CRT
    //let mut rng = rand::thread_rng();
    //let mut rsa = RsaCrt::new(&memory, &mut rng)?;
    //let msg = b"hello world";
    //let sig = rsa.sign(msg);
    //let mut check = rsa.verify(msg, &sig);
    let mut check = true;
    let mut retries = 0;
    let mut seed: [u8; 32] = [0; 32];
    info!("start hammering");
    while check {
        seed = rand::random();
        memory.initialize::<StdRng>(seed)?;
        hammerer.hammer_pattern(
            mem_config,
            args.load_json.clone(),
            args.pattern.clone(),
            memory.addr.expect("no address"),
        )?;
        //check = rsa.verify(msg, &sig);
        check = memory.check::<StdRng>(seed)?;
        info!("check: {}", check);
        retries += 1;
    }
    println!("Flipped after {} attempts with seed {:?}", retries, seed);
    Ok(())
}
