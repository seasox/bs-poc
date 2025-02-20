//! This module contains the victim implementations for the hammer attack.
//!
//! A victim is the target of the Rowhammer attack. It can be a memory region or a process. To probe memory regions, the `MemCheck` victim is used. To probe a victim process, the `Process` victim is used.
pub mod mem_check;
pub mod process;
pub mod sphincs_plus;

use core::panic;

use serde::Serialize;
use thiserror::Error;

use crate::memory::BitFlip;

pub use self::mem_check::HammerVictimMemCheck as MemCheck;
pub use self::mem_check::HammerVictimTargetCheck as TargetCheck;
pub use self::process::VictimProcess as Process;
pub use self::sphincs_plus::SphincsPlus;

#[derive(Error, Debug)]
pub enum HammerVictimError {
    #[error("No flips detected")]
    NoFlips,
    #[error("Error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Serialize)]
pub enum VictimResult {
    BitFlips(Vec<BitFlip>),
    String(String),
    Strings(Vec<String>),
}
impl VictimResult {
    pub fn bit_flips(self) -> Vec<BitFlip> {
        match self {
            VictimResult::BitFlips(flips) => flips,
            _ => panic!("Expected bit flips"),
        }
    }
    pub fn string(self) -> String {
        match self {
            VictimResult::String(s) => s,
            _ => panic!("Expected string"),
        }
    }
    pub fn strings(self) -> Vec<String> {
        match self {
            VictimResult::Strings(s) => s,
            _ => panic!("Expected strings"),
        }
    }
}

/// The HammerVictim trait. A victim must implement this trait to be used as a target for the hammer attack.
///
/// The trait provides methods to initialize the victim, check if the hammering was successful, and log the report.
///
pub trait HammerVictim {
    /// start the victim. This methos is called once
    fn start(&mut self) {}
    /// Initialize the victim. This method is called before the hammering starts.
    fn init(&mut self) {}
    /// Check if the hammering was successful. Returns Ok with an optional value of type T describing the result if the hammering was successful, Err with an error otherwise.
    fn check(&mut self) -> Result<VictimResult, HammerVictimError>;
    /// Stop the victim. This method is called after the hammering is done. This consumes the victim.
    fn stop(self);
}
