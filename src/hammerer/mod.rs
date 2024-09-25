//! A module for hammering functionalities in the Rowhammer suite.
//!
//! This module provides two different hammering strategies: `Blacksmith` and `Dummy`.
//! These strategies allow testing the resilience of DRAM to Rowhammer attacks.
//!
//! # Modules
//!
//! - `blacksmith`: Implements the `Blacksmith` hammerer, which uses advanced hammering techniques.
//! - `dummy`: Implements the `Dummy` hammerer, which serves as a baseline or no-op hammerer.
//!
//! # Traits
//!
//! - `Hammering`: The main trait for hammering operations. Any hammerer must implement this trait
//!   to perform the hammering on a given victim.
//!
//! # Types
//!
//! - `HammerResult`: The result returned by hammering operations, defined in the `blacksmith` module.
//! - `HammerVictim`: A trait that represents the target memory being hammered.
pub mod blacksmith;
pub mod dummy;

use crate::victim::HammerVictim;
pub use blacksmith::hammerer::Hammerer as Blacksmith;
pub use dummy::hammerer::Hammerer as Dummy;

/// The Hammering trait. A hammerer must implement this trait to perform hammering.
pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u64) -> anyhow::Result<HammerResult>;
}

#[derive(Debug)]
pub struct HammerResult {
    pub run: u64,
    pub attempt: u8,
}
