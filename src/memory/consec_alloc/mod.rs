mod buddyinfo;
mod coco;
mod hugepage_rnd;
mod mmap;
mod spoiler;

pub use buddyinfo::ConsecAllocBuddyInfo;
pub use coco::ConsecAllocCoCo;
pub use hugepage_rnd::ConsecAllocHugepageRnd;
pub use mmap::ConsecAllocMmap;
pub use spoiler::ConsecAllocSpoiler;

use crate::memory::{ConsecBlocks, HugepageAllocator};

pub trait ConsecAllocator {
    fn block_size(&self) -> usize;
    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks>;
}

/**
 * A helper enum to create an allocator from CLI arguments. This allows us to circumvent heap allocation
 */
pub enum ConsecAlloc {
    BuddyInfo(ConsecAllocBuddyInfo),
    CoCo(ConsecAllocCoCo),
    Hugepage(HugepageAllocator),
    HugepageRnd(ConsecAllocHugepageRnd),
    Mmap(ConsecAllocMmap),
    Spoiler(ConsecAllocSpoiler),
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

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
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
