mod forge;
mod jitter;
mod memory;
mod util;
mod victim;

use clap::Parser;
use libc::c_void;
use memory::Memory;
use victim::RsaCrt;

use forge::Hammerer;

use crate::util::BlacksmithConfig;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct CliArgs {
    /// The JSON file containing hammering patterns to load
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

    let mut memory = Memory::new();
    memory.alloc(2048);
    let mut rng = rand::thread_rng();
    let mut rsa = RsaCrt::new(&memory, &mut rng)?;

    let msg = b"hello world";
    let sig = rsa.sign(msg);

    let mut check = rsa.verify(msg, &sig);

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let hammerer = Hammerer {};

    while check {
        hammerer.hammer_pattern(
            config.to_memconfig(),
            args.load_json.clone(),
            args.pattern.clone(),
            memory.addr.expect("no address") as *mut c_void,
        )?;
        check = rsa.verify(msg, &sig);
        println!("Signature check: {}", check);
    }

    Ok(())
}
