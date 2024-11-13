use anyhow::{bail, Context};

use crate::memory::{BitFlip, VictimMemory};
use crate::victim::HammerVictim;

pub struct HammerVictimMemCheck<'a> {
    memory: &'a dyn VictimMemory,
    seed: Option<[u8; 32]>,
    flips: Vec<BitFlip>,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck {
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

    fn check(&mut self) -> anyhow::Result<Vec<BitFlip>> {
        self.flips = self
            .memory
            .check(self.seed.with_context(|| "no seed").unwrap());
        if !self.flips.is_empty() {
            Ok(self.flips.clone())
        } else {
            bail!("No flips detected")
        }
    }

    fn stop(self) {
        let virt_addrs: Vec<String> = self
            .flips
            .iter()
            .map(|bf| format!("{:?}", bf.addr,))
            .collect();
        info!("Addresses with flips: {:?}", virt_addrs);
    }
}
