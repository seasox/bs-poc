pub mod buddyinfo;
pub mod coco;
pub mod hugepage;
pub mod hugepage_rnd;
pub mod mmap;
pub mod spoiler;
pub mod util;

pub use buddyinfo::BuddyInfo;
pub use coco::CoCo;
use hugepage::HugepageAllocator;
pub use hugepage_rnd::HugepageRandomized;
pub use mmap::Mmap;
pub use spoiler::Spoiler;

pub use util::compact_mem;

use crate::hammerer::blacksmith::hammerer::PatternAddressMapper;
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::ConsecBlocks;

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
    memory.log_pfns();
    Ok(memory)
}

pub trait ConsecAllocator {
    fn block_size(&self) -> usize;
    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks>;
}

/// A helper enum to create an allocator from CLI arguments.
///
/// This allows us to circumvent heap allocation.
pub enum ConsecAlloc {
    BuddyInfo(BuddyInfo),
    CoCo(CoCo),
    Hugepage(HugepageAllocator),
    HugepageRnd(HugepageRandomized),
    Mmap(Mmap),
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
            ConsecAlloc::Spoiler(alloc) => alloc.alloc_consec_blocks(size),
        }
    }
}
