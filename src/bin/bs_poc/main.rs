use anyhow::Context;
use bs_poc::memory::Memory;
use bs_poc::victim::RsaCrt;
use clap::Parser;
use libc::c_void;

use bs_poc::forge::Hammerer;

use bs_poc::util::BlacksmithConfig;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = CliArgs::parse();

    const MEM_SIZE: usize = 1 << 30; // 1 GB

    let mut memory = Memory::new();
    memory.alloc(MEM_SIZE)?;
    memory.initialize(0)?;

    // check memory.start phys addr

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let hammerer = Hammerer {};

    //RSA-CRT
    //let mut rng = rand::thread_rng();
    //let mut rsa = RsaCrt::new(&memory, &mut rng)?;
    //let msg = b"hello world";
    //let sig = rsa.sign(msg);
    //let mut check = rsa.verify(msg, &sig);

    let mut check = memory.check(0)?;
    while check {
        hammerer.hammer_pattern(
            config.to_memconfig(),
            args.load_json.clone(),
            args.pattern.clone(),
            memory.addr.expect("no address") as *mut c_void,
        )?;
        //check = rsa.verify(msg, &sig);
        check = memory.check(0)?;
        println!("check: {}", check);
    }

    // TODO check address function (check for expected row conflicts etc.)
    Ok(())
}
