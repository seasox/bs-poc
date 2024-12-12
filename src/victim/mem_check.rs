use crate::memory::{BitFlip, DataPattern, VictimMemory};
use crate::victim::HammerVictim;

use super::HammerVictimError;

pub struct HammerVictimMemCheck<'a> {
    memory: &'a dyn VictimMemory,
    pub pattern: DataPattern,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck {
            memory,
            pattern: DataPattern::Random(rand::random()),
        }
    }

    pub fn new_with_seed(memory: &'a dyn VictimMemory, seed: [u8; 32]) -> Self {
        HammerVictimMemCheck {
            memory,
            pattern: DataPattern::Random(seed),
        }
    }

    pub fn new_stripe(memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck {
            memory,
            pattern: DataPattern::StripeOneZero,
        }
    }
}

impl<'a> HammerVictim<Vec<BitFlip>> for HammerVictimMemCheck<'a> {
    fn init(&mut self) {
        self.memory.initialize(self.pattern.clone());
    }

    fn check(&mut self) -> Result<Vec<BitFlip>, HammerVictimError> {
        let flips = self.memory.check(self.pattern.clone());
        if !flips.is_empty() {
            Ok(flips.clone())
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(self) {}
}
