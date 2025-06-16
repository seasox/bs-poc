use bs_poc::{
    allocator::{AllocStrategy, ConsecAllocator},
    hammerer::blacksmith::blacksmith_config::BlacksmithConfig,
    memory::{mem_configuration::MemConfiguration, GetConsecPfns},
    util::MB,
};
use clap::{arg, Parser};
use indicatif::MultiProgress;
use log::info;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// Repeat the allocation this many times.
    #[arg(long, short = 'n')]
    repeat: Option<usize>,
    #[arg(long)]
    alloc_strategy: AllocStrategy,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    //const NUM_PAGES: usize = 1 << 21; // 8 GB
    //const ALLOC_SIZE: usize = NUM_PAGES * PAGE_SIZE;
    let args = CliArgs::parse();
    info!("CLI args: {:?}", args);
    let bs_config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config = MemConfiguration::from_blacksmith(&bs_config);
    //0..64 {
    //let bait_before = args.bait_before;
    let progress = MultiProgress::new();
    let mut allocator = args.alloc_strategy.create_allocator(
        mem_config,
        bs_config.threshold,
        Some(progress.clone()),
    );
    for _ in 0..args.repeat.unwrap_or(1) {
        let memory = allocator.alloc_consec_blocks(4 * MB);
        match memory {
            Ok(memory) => {
                println!("{:?}", memory.consec_pfns());
            }
            Err(e) => {
                println!("{:?}", e);
            }
        }
    }
    Ok(())
}
