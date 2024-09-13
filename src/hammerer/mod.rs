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
//!
//! # Example
//!
//! ```rust
//! use bs_poc::hammerer::Blacksmith;
//! use bs_poc::memory::mem_configuration::MemConfiguration;
//! use bs_poc::victim::HammerVictimMemCheck;
//!
//! let memory = todo!("Allocate memory");
//! let config = todo!("Load blacksmith config from JSON");
//! let mem_config = MemConfiguration::from_blacksmith(&config);
//! let mut victim = HammerVictimMemCheck::new(mem_config, &memory);
//! let blacksmith = Blacksmith::new(
//!                 mem_config,
//!                 pattern.clone(),
//!                 mapping.clone(),
//!                 &hammering_addrs,
//!                 memory.blocks.iter().collect(),
//!             );
//! let result = blacksmith.hammer(&mut victim, 1000);
//! match result {
//!     Ok(result) => println!("Hammering succeeded: {:?}", result),
//!     Err(e) => eprintln!("Hammering failed: {}", e),
//! }
//! ```
//!
//! In the example above, the `Blacksmith` hammerer is used to hammer the victim memory for up to 1000 runs.

pub mod blacksmith;
pub mod dummy;

use crate::hammerer::blacksmith::hammerer::HammerResult;
use crate::victim::HammerVictim;
pub use blacksmith::hammerer::Hammerer as Blacksmith;
pub use dummy::hammerer::Hammerer as Dummy;

/// The Hammering trait. A hammerer must implement this trait to perform hammering.
pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u64) -> anyhow::Result<HammerResult>;
}
