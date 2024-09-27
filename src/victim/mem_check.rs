use anyhow::Context;

use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::{BitFlip, VictimMemory};
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

impl<'a> HammerVictim<Vec<BitFlip>> for HammerVictimMemCheck<'a> {
    fn init(&mut self) {
        let seed = rand::random();
        self.memory.initialize(seed);
        self.seed = Some(seed);
    }

    fn check(&mut self) -> Option<Vec<BitFlip>> {
        self.flips = self
            .memory
            .check(self.seed.with_context(|| "no seed").unwrap());
        if !self.flips.is_empty() {
            Some(self.flips.clone())
        } else {
            None
        }
    }

    fn stop(self) {}

    fn log_report(&self) {
        let virt_addrs: Vec<String> = self
            .flips
            .iter()
            .map(|bf| format!("{:?}", bf.addr,))
            .collect();
        info!("Addresses with flips: {:?}", virt_addrs);
    }
}
