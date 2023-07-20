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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    todo!()
}
