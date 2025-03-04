//! This module contains the victim implementations for the hammer attack.
//!
//! A victim is the target of the Rowhammer attack. It can be a memory region or a process. To probe memory regions, the `MemCheck` victim is used. To probe a victim process, the `Process` victim is used.
pub mod mem_check;
mod page_inject;
pub mod sphincs_plus;

use core::panic;
use std::process::Child;
use std::process::ChildStdin;
use std::process::ChildStdout;

use anyhow::Context;
use serde::Serialize;
use thiserror::Error;

use crate::memory::BitFlip;
use crate::util::PipeIPC;

pub use self::mem_check::HammerVictimMemCheck as MemCheck;
pub use self::mem_check::HammerVictimTargetCheck as TargetCheck;
pub use self::page_inject::InjectionConfig;
pub use self::page_inject::PageInjector;
pub use self::sphincs_plus::SphincsPlus;

#[derive(Error, Debug)]
pub enum HammerVictimError {
    #[error("No flips detected")]
    NoFlips,
    #[error("Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Victim is not running")]
    NotRunning,
    #[error("Flippy page not found")]
    FlippyPageNotFound,
}

#[derive(Debug, Serialize)]
pub enum VictimResult {
    BitFlips(Vec<BitFlip>),
    SphincsPlus {
        signatures: Vec<String>,
        child_output: String,
    },
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
    /// Check if the hammering was successful. Returns Ok with an optional value of type T describing the result if the hammering was successful, Err with an error otherwise.
    fn check(&mut self) -> Result<VictimResult, HammerVictimError>;
    /// Stop the victim. This method is called after the hammering is done.
    fn stop(&mut self);
}

pub(crate) fn piped_channel(child: &mut Child) -> anyhow::Result<PipeIPC<ChildStdout, ChildStdin>> {
    let child_in = child.stdin.take().context("piped_channel stdin")?;
    let child_out = child.stdout.take().context("piped_channel stdout")?;
    Ok(PipeIPC::new(child_out, child_in))
}
