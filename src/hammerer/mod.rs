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
mod dev_mem;
pub mod dummy;

use crate::{
    memory::{
        mem_configuration::MemConfiguration, BytePointer, ConsecBlocks, FlipDirection, PhysAddr,
    },
    victim::{HammerVictim, HammerVictimError, VictimResult},
};
pub use blacksmith::hammerer::Hammerer as Blacksmith;
use blacksmith::hammerer::{HammeringPattern, PatternAddressMapper};
pub use dev_mem::DevMemHammerer;
pub use dummy::Hammerer as Dummy;
use serde::Serialize;

/// The hammering strategy to use.
#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
pub enum HammerStrategy {
    /// Use a dummy hammerer. This hammerer flips a bit at a fixed offset.
    Dummy,
    /// Use the blacksmith hammerer. This hammerer uses the pattern and mapping determined by `blacksmith` to hammer the target.
    Blacksmith,
    /// Use the devmem hammerer. This hammerer flips a bit in physical memory using `/dev/mem`.
    DevMem,
}

#[allow(clippy::large_enum_variant)]
pub enum Hammerer<'a> {
    Blacksmith(Blacksmith<'a>),
    Dummy(Dummy),
    DevMem(DevMemHammerer),
}

#[allow(clippy::too_many_arguments)]
pub fn make_hammer<'a>(
    hammerer: &HammerStrategy,
    pattern: &HammeringPattern,
    mapping: &PatternAddressMapper,
    mem_config: MemConfiguration,
    block_size: usize,
    memory: &'a ConsecBlocks,
    attempts: u32,
    check_each_attempt: bool,
    target_pfn: PhysAddr, // target page (physical address) for DevMem hammerer
    flip_direction: FlipDirection, // direction of bit flip for DevMem hammerer
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
        HammerStrategy::DevMem => {
            let hammerer = DevMemHammerer::new(target_pfn, 2, flip_direction);
            Hammerer::DevMem(hammerer)
        }
    };
    Ok(hammerer)
}

impl Hammering for Hammerer<'_> {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult, HammerVictimError> {
        match self {
            Hammerer::Blacksmith(blacksmith) => blacksmith.hammer(victim),
            Hammerer::Dummy(dummy) => dummy.hammer(victim),
            Hammerer::DevMem(dev_mem) => dev_mem.hammer(victim),
        }
    }
}

/// The Hammering trait. A hammerer must implement this trait to perform hammering.
pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult, HammerVictimError>;
}

#[derive(Debug, Serialize)]
pub struct HammerResult {
    pub attempt: u32,
    pub victim_result: VictimResult,
}
