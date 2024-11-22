use anyhow::{bail, Context};

use crate::memory::{BitFlip, VictimMemory};
use crate::victim::HammerVictim;

#[derive(Copy, Clone)]
enum MemorySeed {
    Random([u8; 32]),
    Fixed([u8; 32]),
}

impl MemorySeed {
    fn get(&self) -> [u8; 32] {
        match self {
            MemorySeed::Random(seed) => *seed,
            MemorySeed::Fixed(seed) => *seed,
        }
    }
}

pub struct HammerVictimMemCheck<'a> {
    memory: &'a dyn VictimMemory,
    seed: Option<MemorySeed>,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck { memory, seed: None }
    }

    pub fn new_with_seed(memory: &'a dyn VictimMemory, seed: [u8; 32]) -> Self {
        HammerVictimMemCheck {
            memory,
            seed: Some(MemorySeed::Fixed(seed)),
        }
    }

    pub fn seed(&self) -> Option<[u8; 32]> {
        match self.seed {
            Some(MemorySeed::Random(seed)) => Some(seed),
            Some(MemorySeed::Fixed(seed)) => Some(seed),
            None => None,
        }
    }
}

impl<'a> HammerVictim<Vec<BitFlip>> for HammerVictimMemCheck<'a> {
    fn init(&mut self) {
        let seed = match self.seed {
            Some(MemorySeed::Fixed(seed)) => seed,
            _ => {
                let seed = rand::random();
                self.seed = Some(MemorySeed::Random(seed));
                seed
            }
        };
        self.memory.initialize(seed);
    }

    fn check(&mut self) -> anyhow::Result<Vec<BitFlip>> {
        let flips = self
            .memory
            .check(self.seed.with_context(|| "no seed").unwrap().get());
        if !flips.is_empty() {
            Ok(flips.clone())
        } else {
            bail!("No flips detected")
        }
    }

    fn stop(self) {}
}
