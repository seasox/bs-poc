use anyhow::Context;

use crate::hammerer::blacksmith::hammerer::BitFlip;
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::VictimMemory;
use crate::victim::HammerVictim;

pub struct HammerVictimMemCheck<'a> {
    mem_config: MemConfiguration,
    memory: &'a dyn VictimMemory,
    seed: Option<[u8; 32]>,
    flips: Vec<BitFlip>,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(mem_config: MemConfiguration, memory: &'a dyn VictimMemory) -> Self {
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
        self.memory.initialize(seed);
        self.seed = Some(seed);
    }

    fn check(&mut self) -> bool {
        self.flips = self.memory.check(
            self.mem_config,
            self.seed.with_context(|| "no seed").unwrap(),
        );
        !self.flips.is_empty()
    }

    fn stop(self) {}

    fn log_report(&self) {
        let virt_addrs: Vec<String> = self
            .flips
            .iter()
            .map(|bf| {
                format!(
                    "{:?}",
                    bf.dram_addr,
                    //bf.dram_addr.to_virt(base_msb, self.mem_config) as usize
                )
            })
            .collect();
        info!("Addresses with flips: {:?}", virt_addrs);
    }
}
