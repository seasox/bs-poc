//! This module contains the victim implementations for the hammer attack.
//!
//! A victim is the target of the Rowhammer attack. It can be a memory region or a process. To probe memory regions, the `MemCheck` victim is used. To probe a victim process, the `Process` victim is used.
mod dev_mem_check;
pub mod mem_check;
mod page_inject;
pub mod sphincs_plus;

use core::panic;

use serde::Serialize;
use thiserror::Error;

use crate::memory::BitFlip;
use crate::memory::FlippyPage;

pub use self::dev_mem_check::HammerVictimDevMemCheck as DevMemCheck;
pub use self::mem_check::HammerVictimMemCheck as MemCheck;
pub use self::mem_check::HammerVictimTargetCheck as TargetCheck;
pub use self::sphincs_plus::SphincsPlus;

pub use self::page_inject::InjectionConfig;
pub(crate) use self::page_inject::PageInjector;

#[derive(Error, Debug)]
pub enum HammerVictimError {
    #[error("No flips detected")]
    NoFlips,
    #[error("IO Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Victim is not running")]
    NotRunning,
    #[error("Flippy page not found")]
    FlippyPageNotFound,
    #[error("Flippy page offset mismatch: expected {expected}, actual {actual:?}")]
    FlippyPageOffsetMismatch { expected: usize, actual: FlippyPage },
    #[error("PageMapError: {0}")]
    PageMapError(#[from] pagemap::PageMapError),
    #[error("Protocol Error: {0}")]
    ProtocolError(String),
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
            _ => panic!("Invalid variant. Expected BitFlips, got {:?}", self),
        }
    }
}

/// The HammerVictim trait. A victim must implement this trait to be used as a target for the hammer attack.
///
/// The trait provides methods to initialize the victim, check if the hammering was successful, and log the report.
///
pub trait HammerVictim {
    /// start the victim. This methos is called once
    fn start(&mut self) -> Result<(), HammerVictimError>;
    /// Initialize the victim. This method is called before the hammering starts.
    fn init(&mut self);
    /// Check if the hammering was successful. Returns Ok with a VictimResult describing the result if the hammering was successful, Err with an error otherwise.
    fn check(&mut self) -> Result<VictimResult, HammerVictimError>;
    /// Stop the victim. This method is called after the hammering is done.
    fn stop(&mut self);
}
