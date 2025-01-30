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

use crate::{
    memory::{mem_configuration::MemConfiguration, BytePointer, ConsecBlocks},
    victim::{HammerVictim, HammerVictimError},
};
pub use blacksmith::hammerer::Hammerer as Blacksmith;
use blacksmith::hammerer::{HammeringPattern, PatternAddressMapper};
pub use dummy::Hammerer as Dummy;

/// The hammering strategy to use.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum HammerStrategy {
    /// Use a dummy hammerer. This hammerer flips a bit at a fixed offset.
    Dummy,
    /// Use the blacksmith hammerer. This hammerer uses the pattern and mapping determined by `blacksmith` to hammer the target.
    Blacksmith,
}

#[allow(clippy::large_enum_variant)]
pub enum Hammerer<'a> {
    Blacksmith(Blacksmith<'a>),
    Dummy(Dummy),
}

#[allow(clippy::too_many_arguments)]
pub fn make_hammer<'a>(
    hammerer: &HammerStrategy,
    pattern: &HammeringPattern,
    mapping: &PatternAddressMapper,
    mem_config: MemConfiguration,
    block_size: usize,
    memory: &'a ConsecBlocks,
    attempts: u8,
    check_each_attempt: bool,
    read_all_pages_except: Option<Vec<*const u8>>, // read all rows (except victim) after hammering
) -> anyhow::Result<Hammerer<'a>> {
    let block_shift = block_size.ilog2();
    let hammerer: Hammerer<'a> = match hammerer {
        HammerStrategy::Blacksmith => Hammerer::Blacksmith(Blacksmith::new(
            mem_config,
            pattern,
            mapping,
            block_shift as usize,
            memory,
            attempts,
            check_each_attempt,
            read_all_pages_except,
        )?),
        HammerStrategy::Dummy => {
            let flip = mapping.get_bitflips_relocate(mem_config, block_shift as usize, memory);
            let flip = flip.concat().pop().unwrap_or(memory.blocks[0].addr(0x42)) as *mut u8;
            info!(
                "Running dummy hammerer with flip at VA 0x{:02x}",
                flip as usize
            );
            let hammerer = Dummy::new(flip);
            Hammerer::Dummy(hammerer)
        }
    };
    Ok(hammerer)
}

impl Hammering for Hammerer<'_> {
    fn hammer<T>(
        &self,
        victim: &mut dyn HammerVictim<T>,
    ) -> Result<HammerResult<T>, HammerVictimError> {
        match self {
            Hammerer::Blacksmith(blacksmith) => blacksmith.hammer(victim),
            Hammerer::Dummy(dummy) => dummy.hammer(victim),
        }
    }
}

/// The Hammering trait. A hammerer must implement this trait to perform hammering.
pub trait Hammering {
    fn hammer<T>(
        &self,
        victim: &mut dyn HammerVictim<T>,
    ) -> Result<HammerResult<T>, HammerVictimError>;
}

#[derive(Debug)]
pub struct HammerResult<T> {
    pub attempt: u8,
    pub victim_result: T,
}
