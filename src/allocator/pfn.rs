use std::ptr::null_mut;

use anyhow::bail;

use crate::{
    allocator::util::munmap,
    memory::{ConsecBlocks, GetConsecPfns, MemBlock},
    util::MB,
};

use super::{util::mmap, ConsecAllocator};

pub struct Pfn {}

/// Pfn allocator. This finds consecutive PFNs by allocating memory and checking the page map.
/// Useful for testing purposes.
impl Pfn {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for Pfn {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsecAllocator for Pfn {
    fn block_size(&self) -> usize {
        4 * MB
    }

    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        assert_eq!(size % self.block_size(), 0);
        let block_count = size / self.block_size();
        const BUFSIZE: usize = 4096 * MB;
        let mut blocks = vec![];
        while blocks.len() < block_count {
            let x: *mut u8 = mmap(null_mut(), BUFSIZE);
            if x.is_null() {
                bail!("Failed to allocate memory");
            }
            let pfns = (x, BUFSIZE).consec_pfns()?;
            let consec = pfns
                .iter()
                .enumerate()
                .find(|(_, range)| range.end - range.start == self.block_size() as u64);
            match consec {
                None => {
                    unsafe {
                        (x, BUFSIZE).log_pfns();
                        munmap(x, BUFSIZE);
                        info!("Failed to find consecutive PFNs, retrying...");
                    }
                    continue;
                }
                Some((idx, _)) => {
                    let offset: usize = pfns
                        .iter()
                        .take(idx)
                        .map(|range| range.end - range.start)
                        .sum::<u64>() as usize;
                    blocks.push(MemBlock::new(
                        unsafe { x.byte_add(offset as usize) },
                        self.block_size(),
                    ));
                    unsafe {
                        munmap(x, offset);
                        munmap(x.byte_add(offset + 4 * MB), BUFSIZE - offset - 4 * MB);
                    }
                }
            }
        }
        Ok(ConsecBlocks::new(blocks))
    }
}
