use std::{
    env,
    io::Read,
    process::Command,
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use anyhow::{bail, Context};
use bs_poc::memory::{LinuxPageMap, VirtToPhysResolver};
use clap::Parser;
use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use log::{debug, info};
use proc_getter::buddyinfo::*;
use std::fs::File;
use std::io::Write;

#[derive(Debug, Parser)]
struct CliArgs {
    ///The bait-alloc mode.
    #[clap(long = "mode", default_value = "bait")]
    mode: BaitMode,
    /// The consecutive check mode.
    #[clap(long = "check-mode", default_value = "pfn")]
    check_mode: CheckConsecutiveMode,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum BaitMode {
    Bait,
    MonitorBuddyInfo,
    Prey,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum CheckConsecutiveMode {
    Pfn,
    None,
}

const PAGE_COUNT: usize = 1000;
const RELEASE_COUNT: usize = 500;
const PREY_PAGE_COUNT: usize = 500;
const PAGE_LEN: usize = 4 * KB;

fn prog() -> Option<String> {
    env::args().next().as_ref().cloned()
}

/// Send a signal `sig` to the process `pid`
fn signal(sig: &str, pid: u32) -> anyhow::Result<()> {
    let mut kill = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .spawn()?;
    kill.wait()?;
    Ok(())
}

const KB: usize = 1 << 10;
const MB: usize = 1 << 20;

/// Read /proc/pagetypeinfo to string
fn read_pagetypeinfo() -> anyhow::Result<String> {
    let mut s = String::new();
    let mut f = std::fs::File::open("/proc/pagetypeinfo")?;
    f.read_to_string(&mut s)?;
    Ok(s)
}

/// Log /proc/pagetypeinfo to debug log
fn log_pagetypeinfo() {
    debug!("{:?}", read_pagetypeinfo());
}

/// A small wrapper around buddyinfo() from proc_getter, which is not convertible to anyhow::Result
fn get_buddyinfo() -> anyhow::Result<Vec<BuddyInfo>> {
    match buddyinfo() {
        Ok(b) => Ok(b),
        Err(e) => bail!("{:?}", e),
    }
}

fn get_normal_page_nums() -> anyhow::Result<[usize; 11]> {
    let zones = get_buddyinfo()?;
    /*
    let mut free_space = 0;
    let zone = zones
        .iter()
        .find(|z| z.zone().eq("Normal"))
        .context("Zone 'Normal' not found")?;
    return Ok(zone.page_nums().clone());*/
    fn add_acc(mut l: [usize; 11], r: &[usize; 11]) -> [usize; 11] {
        for i in 0..11 {
            l[i] += r[i];
        }
        l
    }
    let pages = zones.iter().fold([0; 11], |mut acc, next| {
        acc = add_acc(acc, next.page_nums());
        acc
    });
    Ok(pages)
}

fn diff_arrs<const S: usize>(l: &[usize; S], r: &[usize; S]) -> [i64; S] {
    let mut diffs = [0_i64; S];
    let mut i = 0;
    for (&l, &r) in l.iter().zip(r) {
        diffs[i] = l as i64 - r as i64;
        i += 1;
    }
    diffs
}

unsafe fn mmap_block(len: usize) -> *mut libc::c_void {
    let v = libc::mmap(
        null_mut(),
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );
    assert_ne!(v as i64, -1, "mmap: {}", std::io::Error::last_os_error());
    libc::memset(v, 0x11, len);
    v
}

#[cfg(feature = "spec_hammer")]
unsafe fn determine_locked_2mb_blocks() -> anyhow::Result<usize> {
    let mut locked = usize::MAX;
    for _repetition in 0..10 {
        let mut allocations = [null_mut(); 50000];
        const MAX_REPETITIONS: usize = 10;
        let mut split_allocations = 0;
        for i in 0..50000 {
            //log_pagetypeinfo();
            let buddy_before = get_normal_page_nums()?;
            let v = mmap_block(2 * MB);
            allocations[i] = v;
            let buddy_after = get_normal_page_nums()?;
            let diff = diff_arrs(&buddy_before, &buddy_after);
            locked = min(locked, buddy_before[9]);
            if diff[9] < 0 {
                // the last allocation increased the block count -> we encountered a split
                log_pagetypeinfo();
                split_allocations += 1;
                debug!("  {:?}", buddy_before);
                debug!("- {:?}", buddy_after);
                debug!("= {:?}", diff);
            }
            if split_allocations == MAX_REPETITIONS {
                debug!("Allocated {} blocks before hitting threshold", i);
                break;
            }
        }
        for v in allocations {
            libc::munmap(v, 2 * MB);
        }
    }
    Ok(locked)
}

#[cfg(feature = "spec_hammer")]
unsafe fn mmap_consecutive_2mb_block() -> anyhow::Result<*mut libc::c_void> {
    let locked_2mb_blocks = determine_locked_2mb_blocks()?;
    info!("Locked 2MB blocks: {}", locked_2mb_blocks);
    let mut available_2mb_blocks = usize::MAX;
    let mut allocations = [null_mut(); 50000];
    let mut i = 0;
    while available_2mb_blocks > locked_2mb_blocks {
        let buddy_before = get_normal_page_nums()?;
        let v = mmap_block(2 * MB);
        let buddy_after = get_normal_page_nums()?;
        let diff = diff_arrs(&buddy_before, &buddy_after);
        allocations[i] = v;
        i += 1;
        available_2mb_blocks = get_normal_page_nums()?[9];
        if available_2mb_blocks <= locked_2mb_blocks {
            log_pagetypeinfo();
            debug!("  {:?}", buddy_before);
            debug!("- {:?}", buddy_after);
            debug!("= {:?}", diff);
        }
    }
    debug!("hit thresh");
    let buddy_before = get_normal_page_nums()?;
    let v = mmap_block(2 * MB);
    let buddy_after = get_normal_page_nums()?;
    let diff = diff_arrs(&buddy_before, &buddy_after);
    info!("  {:?}", buddy_before);
    info!("- {:?}", buddy_after);
    info!("= {:?}", diff);
    for ptr in allocations {
        libc::munmap(ptr, 2 * MB);
    }
    Ok(v)
}

#[cfg(feature = "buddyinfo")]
unsafe fn mmap_consecutive_2mb_block() -> anyhow::Result<*mut libc::c_void> {
    fn is_block10_candidate(diff: &[i64; 11]) -> bool {
        if diff[10] != 1 {
            return false;
        }
        let low_order_sum = diff[..8]
            .iter()
            .enumerate()
            .filter(|(_, &n)| n > 0)
            .fold(0, |acc, (order, n)| acc + (1 << order) * n);
        let low_order_sum = low_order_sum as usize * 4 * KB;
        low_order_sum < 2 * MB
    }
    let hugeblock_len = 1024 * MB;
    log_pagetypeinfo();
    debug!("will alloc 1 GB block");
    // Open the file in write mode, creating it if it doesn't exist or truncating it if it does.
    let mut file = File::create("dmesg.log")?;
    // Write an empty string to the file.
    write!(file, "")?;
    let v = mmap_block(hugeblock_len);
    debug!("1 GB allocated");
    let mut pages = [null_mut(); 50000];
    let mut v1 = None;
    let mut diff = [0; 11];
    for i in 0..50000 {
        log_pagetypeinfo();
        let blocks_before = get_normal_page_nums()?;
        let v = mmap_block(2 * MB);
        log_pagetypeinfo();
        let blocks_after = get_normal_page_nums()?;
        diff = diff_arrs(&blocks_before, &blocks_after);
        debug!("  {:?}", blocks_before);
        debug!("- {:?}", blocks_after);
        debug!("= {:?}", diff);
        if is_block10_candidate(&diff) {
            debug!("allocated block from order 10 block");
            v1 = Some(v);
            break;
        } else {
            pages[i] = v;
        }
    }
    assert_ne!(diff[10], 0);

    libc::munmap(v, hugeblock_len);
    for p in pages {
        if p.is_null() {
            continue;
        }
        libc::munmap(p, 2 * MB);
    }

    v1.context("Block allocation failed")
}

trait CheckConsecutiveBlock {
    unsafe fn check_consecutive_block(
        &self,
        v: *const libc::c_void,
        min_size: usize,
    ) -> anyhow::Result<bool>;
}

impl CheckConsecutiveBlock for CheckConsecutiveMode {
    unsafe fn check_consecutive_block(
        &self,
        v: *const libc::c_void,
        min_size: usize,
    ) -> anyhow::Result<bool> {
        return match self {
            Self::Pfn => {
                /// get the first block of consecutive PFNs of a given allocation (requires root)
                unsafe fn get_consec_pfns(v: *const libc::c_void) -> anyhow::Result<Vec<u64>> {
                    let mut resolver = LinuxPageMap::new()?;
                    if (v as u64) & 0xFFF != 0 {
                        bail!("Address is not page-aligned: 0x{:x}", v as u64);
                    }
                    debug!("Get consecutive PFNs for vaddr 0x{:x}", v as u64);
                    let mut phys_prev = resolver.get_phys(v as u64)?;
                    let mut consecs = vec![phys_prev];
                    for offset in (PAGE_LEN..2 * MB).step_by(PAGE_LEN) {
                        let virt = (v as *const u8).add(offset);
                        let phys = resolver.get_phys(virt as u64)?;
                        if phys != phys_prev + PAGE_LEN as u64 {
                            consecs.push(phys_prev + PAGE_LEN as u64);
                            consecs.push(phys);
                        }
                        phys_prev = phys;
                    }
                    consecs.push(phys_prev + PAGE_LEN as u64);
                    debug!("PFN check done");
                    Ok(consecs)
                }

                let consecs = get_consec_pfns(v)?;
                info!("PFNs {:?}", consecs);
                let first_block_bytes = (consecs[1] - consecs[0]) as usize;
                info!(
                    "Allocated a consecutive {} KB block at 0x{:x}",
                    first_block_bytes / 1024,
                    v as u64
                );
                Ok(first_block_bytes >= min_size)
            }
            Self::None => Ok(true),
        };
    }
}

unsafe fn mode_monitor_buddyinfo() -> anyhow::Result<()> {
    loop {
        let before = get_normal_page_nums()?;
        thread::sleep(std::time::Duration::from_secs(1));
        let after = get_normal_page_nums()?;
        let diff = diff_arrs(&before, &after);
        //info!("  {:?}", blocks_before);
        //info!("- {:?}", blocks_after);
        info!("= {:?}", diff);
    }
}

// next: spezifischen speicherbereich unterschieben
unsafe fn mode_bait(checker: CheckConsecutiveMode) -> anyhow::Result<()> {
    //let mut virt = vec![0_u64; 1 << 30];
    //let mut phys = vec![0_u64; 1 << 30];

    //mmap_page_buddy()?;
    //drain_small_pages(2 * MB)?;
    let mut successes = 0;

    for retries in 0..usize::MAX {
        /*log_pagetypeinfo();
        let prog = prog().expect("prog");
        let child = Command::new(prog)
            .stdout(Stdio::piped())
            .args(["--mode", "prey"])
            .spawn()?;*/
        let v = mmap_consecutive_2mb_block()?;
        let success = checker.check_consecutive_block(v, 1 * MB)?;
        libc::munmap(v, 2 * MB);
        if success {
            successes += 1;
        }
        info!(
            "Success rate (>= 1 MB): {}/{}: {:.02}",
            successes,
            retries + 1,
            successes as f32 / (retries + 1) as f32,
        );
        // signal child process
        /*signal("INT", child.id())?;
        let output = child.wait_with_output().expect("child wait");*/
        thread::sleep(std::time::Duration::from_secs(2));
    }
    Ok(())
}

unsafe fn mode_prey(mut resolver: LinuxPageMap) -> anyhow::Result<()> {
    // setup signal handler
    let waiting = Arc::new(AtomicBool::new(true));
    let waiting_sigh = waiting.clone();
    ctrlc::set_handler(move || {
        waiting_sigh.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc setup failed");

    // wait for signal
    while waiting.load(Ordering::SeqCst) {
        thread::sleep(std::time::Duration::from_millis(1));
    }

    // allocate 500 4K pages
    let mut virt = [std::ptr::null_mut(); PREY_PAGE_COUNT];
    let mut phys = [0_u64; PREY_PAGE_COUNT];

    // allocate pages
    for i in 0..PREY_PAGE_COUNT {
        let v = libc::mmap(
            null_mut(),
            PAGE_LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        //let v = libc::malloc(PAGE_LEN);
        libc::memset(v, 0_i32, PAGE_LEN);
        let p = resolver
            .get_phys(v as u64)
            .context("virt_to_phys failed. Are we root?")?;
        phys[i] = p;
        virt[i] = v;
    }

    // log phys addrs to stdout
    for i in 0..PREY_PAGE_COUNT {
        println!("{}", phys[i]);
    }

    for i in 0..PREY_PAGE_COUNT {
        libc::munmap(virt[i], PAGE_LEN);
    }

    Ok(())
}

unsafe fn _main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();

    let resolver = LinuxPageMap::new()?;

    match args.mode {
        BaitMode::Bait => mode_bait(args.check_mode),
        BaitMode::Prey => mode_prey(resolver),
        BaitMode::MonitorBuddyInfo => mode_monitor_buddyinfo(),
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
