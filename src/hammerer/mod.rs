//! # Hammerer
//! This modules contains the logic for performing the Rowhammer attack.
//!
//! This module provides two different hammering strategies: `Blacksmith` and `Dummy`.
//! These strategies allow testing the resilience of DRAM to Rowhammer attacks.
//!
//! # Modules
//!
//! - `blacksmith`: Implements the `Blacksmith` hammerer, which uses advanced hammering techniques.
//! - `dummy`: Implements the `Dummy` hammerer, which flips fixed bits for testing purposes.
//!
//! # Traits
//!
//! - `Hammering`: The main trait for hammering operations. Any hammerer must implement this trait
//!   to perform the hammering on a given victim.
//!
//! # Types
//!
//! - `HammerResult`: The result returned by hammering operations.
//! - `HammerVictim`: A trait that represents the target being hammered. This can be a memory region or interface with a victim process, e.g., using pipe IPC or unix sockets.
pub mod blacksmith;
pub mod dummy;

use crate::victim::HammerVictim;
pub use blacksmith::hammerer::Hammerer as Blacksmith;
pub use dummy::Hammerer as Dummy;

/// The Hammering trait. A hammerer must implement this trait to perform hammering.
pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u64) -> anyhow::Result<HammerResult>;
}

#[derive(Debug)]
pub struct HammerResult {
    pub run: u64,
    pub attempt: u8,
}
