use std::arch::x86_64::_mm_clflush;

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
        debug!("initialize victim");
        self.memory.initialize(self.pattern.clone());
    }

    fn check(&mut self) -> Result<Vec<BitFlip>, HammerVictimError> {
        debug!("check victim");
        let flips = self.memory.check(self.pattern.clone());
        if !flips.is_empty() {
            Ok(flips.clone())
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(self) {}
}

pub struct HammerVictimTargetCheck<'a> {
    memory: &'a dyn VictimMemory,
    pattern: DataPattern,
    targets: Vec<BitFlip>,
}

impl<'a> HammerVictimTargetCheck<'a> {
    pub fn new(memory: &'a dyn VictimMemory, pattern: DataPattern, targets: Vec<BitFlip>) -> Self {
        HammerVictimTargetCheck {
            memory,
            pattern,
            targets,
        }
    }
}

impl<'a> HammerVictim<Vec<BitFlip>> for HammerVictimTargetCheck<'a> {
    fn init(&mut self) {
        debug!("initialize victim");
        self.memory.initialize(self.pattern.clone());
    }

    fn check(&mut self) -> Result<Vec<BitFlip>, HammerVictimError> {
        debug!("check victim");
        let mut flips = vec![];
        for target in &self.targets {
            let value = unsafe {
                _mm_clflush(target.addr as *const u8);
                std::ptr::read_volatile(target.addr as *const u8)
            };
            if value != target.data {
                let bitmask = target.data ^ value;
                flips.push(BitFlip::new(target.addr as *const u8, bitmask, value))
            }
        }
        if !flips.is_empty() {
            Ok(flips)
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(self) {}
}
