use anyhow::bail;

use crate::{
    memory::{ConsecBlocks, ConsecCheck, MemBlock},
    util::MB,
};

use super::ConsecAllocator;

pub struct ConsecAllocBuddyInfo {
    consec_checker: ConsecCheck,
}

impl ConsecAllocBuddyInfo {
    pub fn new(consec_checker: ConsecCheck) -> Self {
        ConsecAllocBuddyInfo { consec_checker }
    }
}

impl ConsecAllocator for ConsecAllocBuddyInfo {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        let block_size = self.block_size();
        if size % block_size != 0 {
            bail!(
                "Size {} must be a multiple of block size {}",
                size,
                block_size
            );
        }
        let num_blocks = size / block_size;
        info!("Allocating {} blocks of size {}", num_blocks, block_size);
        let mut blocks = vec![];
        for _ in 0..num_blocks {
            let block = unsafe { MemBlock::buddyinfo_alloc(block_size, &self.consec_checker)? };
            info!("TODO implement progress bar");
            blocks.push(block);
        }
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        for block in &blocks {
            unsafe { std::ptr::write_bytes(block.ptr as *mut u8, 0, block.len) };
        }
        Ok(ConsecBlocks::new(blocks))
    }
}
