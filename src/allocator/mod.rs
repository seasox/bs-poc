//! Memory allocation strategies for allocating consecutive memory blocks.
//!
//! This module provides different memory allocation strategies for allocating consecutive memory blocks. The strategies include buddy allocation, CoCo, hugepage allocation, mmap, and spoiler.
//!
//! To add a new memory allocation strategy, implement the `ConsecAllocator` trait for the new strategy and add a new variant to the `ConsecAlloc` enum.
pub mod buddyinfo;
pub mod coco;
pub mod hugepage;
pub mod hugepage_rnd;
pub mod mmap;
pub mod pfn;
pub mod spoiler;
pub mod util;

pub use buddyinfo::BuddyInfo;
pub use coco::CoCo;
use hugepage::HugepageAllocator;
pub use hugepage_rnd::HugepageRandomized;
use indicatif::MultiProgress;
pub use mmap::Mmap;
pub use pfn::Pfn;
use serde::Serialize;
pub use spoiler::Spoiler;
use util::compact_mem;

use crate::hammerer::blacksmith::hammerer::PatternAddressMapper;
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::{ConsecBlocks, ConsecCheck, ConsecCheckBankTiming, GetConsecPfns};

/// The type of allocation strategy to use.
#[derive(clap::ValueEnum, Clone, Debug, Serialize)]
pub enum AllocStrategy {
    /// Use `/proc/buddyinfo` to monitor availability of page orders, assume consecutive memory according to the delta in buddyinfo.
    BuddyInfo,
    // Allocate using the CoCo dec mem module: https://git.its.uni-luebeck.de/research-projects/tdx/kmod-coco-dec-mem
    CoCo,
    /// Allocate consecutive memory using huge pages.
    Hugepage,
    /// Allocate consecutive memory using huge pages with randomization. This will return random 4 MB chunks of a 1 GB hugepage.
    HugepageRnd,
    /// Allocate consecutive memory using `bank timing`. This will `mmap` a large buffer and find consecutive memory using bank timing check
    BankTiming,
    /// Allocate a large block of memory and use pagemap to find consecutive blocks
    Pfn,
    /// Allocate consecutive memory using the Spoiler attack. This strategy will measure read-after-write pipeline conflicts to determine consecutive memory.
    Spoiler,
}

impl AllocStrategy {
    pub fn create_allocator(
        &self,
        mem_config: MemConfiguration,
        conflict_threshold: u64,
        progress: Option<MultiProgress>,
    ) -> ConsecAlloc {
        match self {
            AllocStrategy::BuddyInfo => ConsecAlloc::BuddyInfo(BuddyInfo::new(
                ConsecCheck::BankTiming(ConsecCheckBankTiming::new(mem_config, conflict_threshold)),
            )),
            AllocStrategy::CoCo => ConsecAlloc::CoCo(CoCo {}),
            AllocStrategy::BankTiming => ConsecAlloc::Mmap(Mmap::new(
                ConsecCheck::BankTiming(ConsecCheckBankTiming::new(mem_config, conflict_threshold)),
                progress,
            )),
            AllocStrategy::Hugepage => ConsecAlloc::Hugepage(HugepageAllocator::default()),
            AllocStrategy::HugepageRnd => ConsecAlloc::HugepageRnd(HugepageRandomized::new(1)),
            AllocStrategy::Pfn => ConsecAlloc::Pfn(Pfn::new(mem_config, None)),
            AllocStrategy::Spoiler => ConsecAlloc::Spoiler(Box::new(Spoiler::new(
                mem_config,
                conflict_threshold,
                progress,
            ))),
        }
    }
}

/// Allocate memory using an allocation strategy.
///
/// This is the main entry point for users who simply want to allocate some consecutive memory.
///
/// # Safety
///
/// This function is unsafe because it involves raw memory allocations
/// that are not managed by Rust's ownership or borrowing rules. The caller
/// must ensure that the memory is correctly deallocated and not accessed
/// concurrently from multiple threads.
///
/// # Arguments
///
/// * `alloc_strategy` - A mutable allocator object that implements the `ConsecAllocator` trait.
///   This strategy will be used to allocate the consecutive memory blocks.
/// * `mem_config` - The memory configuration specifying parameters like memory size and
///   alignment requirements.
/// * `mapping` - A reference to a `PatternAddressMapper`, which assists in determining the
///   aggressor sets for the given memory configuration.
///
/// # Errors
///
/// This function returns an `anyhow::Result` which is:
/// - `Ok(ConsecBlocks)` containing the allocated memory blocks.
/// - `Err(Error)` if there is any failure during allocation.
///
pub unsafe fn alloc_memory(
    alloc_strategy: &mut ConsecAlloc,
    mem_config: MemConfiguration,
    mapping: &PatternAddressMapper,
) -> anyhow::Result<ConsecBlocks> {
    let block_size = alloc_strategy.block_size();
    let block_shift = block_size.ilog2() as usize;
    let num_sets = mapping.aggressor_sets(mem_config, block_shift).len();

    let compacted = compact_mem();
    match compacted {
        Ok(_) => {}
        Err(e) => warn!("Memory compaction failed: {:?}", e),
    }
    let memory = alloc_strategy.alloc_consec_blocks(num_sets * block_size)?;
    memory.log_pfns(log::Level::Info);
    Ok(memory)
}

pub trait ConsecAllocator {
    fn block_size(&self) -> usize;
    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks>;
}

/// A helper enum to create an allocator from CLI arguments.
///
/// This allows us to circumvent heap allocation.
#[allow(clippy::large_enum_variant)]
pub enum ConsecAlloc {
    BuddyInfo(BuddyInfo),
    CoCo(CoCo),
    Hugepage(HugepageAllocator),
    HugepageRnd(HugepageRandomized),
    Mmap(Mmap),
    Pfn(Pfn),
    Spoiler(Box<Spoiler>),
}

impl ConsecAllocator for ConsecAlloc {
    fn block_size(&self) -> usize {
        match self {
            ConsecAlloc::BuddyInfo(alloc) => alloc.block_size(),
            ConsecAlloc::CoCo(alloc) => alloc.block_size(),
            ConsecAlloc::Hugepage(alloc) => alloc.block_size(),
            ConsecAlloc::HugepageRnd(alloc) => alloc.block_size(),
            ConsecAlloc::Mmap(alloc) => alloc.block_size(),
            ConsecAlloc::Pfn(alloc) => alloc.block_size(),
            ConsecAlloc::Spoiler(alloc) => alloc.block_size(),
        }
    }

    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        match self {
            ConsecAlloc::BuddyInfo(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::CoCo(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::Hugepage(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::HugepageRnd(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::Mmap(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::Pfn(alloc) => alloc.alloc_consec_blocks(size),
            ConsecAlloc::Spoiler(alloc) => alloc.alloc_consec_blocks(size),
        }
    }
}
