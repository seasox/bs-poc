use anyhow::{bail, Context};

use crate::memory::{BitFlip, VictimMemory};
use crate::victim::HammerVictim;

pub struct HammerVictimMemCheck<'a> {
    memory: &'a dyn VictimMemory,
    seed: Option<[u8; 32]>,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck { memory, seed: None }
    }

    pub fn new_with_seed(memory: &'a dyn VictimMemory, seed: [u8; 32]) -> Self {
        HammerVictimMemCheck {
            memory,
            seed: Some(seed),
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
        let flips = self
            .memory
            .check(self.seed.with_context(|| "no seed").unwrap());
        if !flips.is_empty() {
            Ok(flips.clone())
        } else {
            bail!("No flips detected")
        }
    }

    fn stop(self) {}
}
