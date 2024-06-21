use anyhow::bail;

use crate::{memory::construct_memory_tuple_timer, util::PAGE_SIZE};

use super::MemBlock;

pub trait AllocChecker {
    fn check(&self, block: &MemBlock, previous_blocks: &[MemBlock]) -> anyhow::Result<bool>;
}

pub struct AllocCheckAnd<A, B> {
    a: A,
    b: B,
}

impl<A: AllocChecker, B: AllocChecker> AllocCheckAnd<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: AllocChecker, B: AllocChecker> AllocChecker for AllocCheckAnd<A, B> {
    fn check(&self, block: &MemBlock, previous_blocks: &[MemBlock]) -> anyhow::Result<bool> {
        Ok(self.a.check(block, previous_blocks)? && self.b.check(block, previous_blocks)?)
    }
}

pub struct AllocCheckPageAligned {}

impl AllocChecker for AllocCheckPageAligned {
    fn check(&self, block: &MemBlock, _previous_blocks: &[MemBlock]) -> anyhow::Result<bool> {
        if (block.ptr as u64) & 0xFFF != 0 {
            bail!("Address is not page-aligned: 0x{:x}", block.ptr as u64);
        }
        Ok(true)
    }
}

pub struct ConsecCheckPfn {}

impl AllocChecker for ConsecCheckPfn {
    fn check(&self, block: &MemBlock, previous_blocks: &[MemBlock]) -> anyhow::Result<bool> {
        /*
         * Check whether the allocation is actually consecutive. The current implementation simply
         * checks for consecutive PFNs using the virt-to-phys pagemap. This needs root permissions.
         * Therefore, this check should be replaced with a timing side channel to verify the address function
         * in the memory block. If the measured timings correspond to the address function, it is very likely that
         * this indeed is a consecutive memory block.
         */
        use crate::memory::{LinuxPageMap, VirtToPhysResolver};
        let mut resolver = LinuxPageMap::new()?;
        let mut blocks = vec![*block];
        for &b in previous_blocks {
            blocks.push(b);
        }
        trace!("Get consecutive PFNs for vaddr 0x{:x}", block.ptr as u64);
        let mut phys_prev = resolver.get_phys(block.ptr as u64)?;
        let mut consecs = vec![phys_prev];
        for offset in (PAGE_SIZE..block.len).step_by(PAGE_SIZE) {
            let virt = unsafe { (block.ptr as *const u8).add(offset) };
            let phys = resolver.get_phys(virt as u64)?;
            if phys != phys_prev + PAGE_SIZE as u64 {
                consecs.push(phys_prev + PAGE_SIZE as u64);
                consecs.push(phys);
            }
            phys_prev = phys;
        }
        consecs.push(phys_prev + PAGE_SIZE as u64);
        trace!("PFN check done");
        let first_block_bytes = (consecs[1] - consecs[0]) as usize;
        info!(
            "Allocated a consecutive {} KB block at [{:#02x}, {:#02x}]",
            first_block_bytes / 1024,
            block.ptr as u64,
            unsafe { block.ptr.add(first_block_bytes) as u64 },
        );
        info!("PFNs {:?}", consecs);
        if first_block_bytes < block.len {
            return Ok(false);
        }
        Ok(true)
    }
}

pub struct AllocCheckSameBank {}

impl AllocChecker for AllocCheckSameBank {
    /// bank check
    fn check(&self, block: &MemBlock, previous_blocks: &[MemBlock]) -> anyhow::Result<bool> {
        const THRESHOLD: u64 = 330;
        let timer = construct_memory_tuple_timer()?;
        let a1 = block.ptr;
        for previous_block in previous_blocks {
            let a2 = previous_block.ptr;
            let time = unsafe { timer.time_subsequent_access_from_ram(a1, a2, 1000) };
            if time < THRESHOLD {
                error!(
                    "Blocks ({:#02x}, {:#02x}) are not on the same bank, timed as {}",
                    a1 as usize, a2 as usize, time
                );
                return Ok(false);
            }
        }
        Ok(true)
    }
}
