use crate::memory::{BitFlip, DataPattern, VictimMemory};
use crate::victim::HammerVictim;

use super::HammerVictimError;

pub struct HammerVictimMemCheck<'a> {
    memory: &'a dyn VictimMemory,
    pub pattern: DataPattern,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory, pattern: DataPattern) -> Self {
        HammerVictimMemCheck { memory, pattern }
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
