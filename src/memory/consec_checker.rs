use anyhow::bail;

use crate::util::PAGE_SIZE;

use super::MemBlock;

pub trait ConsecChecker {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool>;
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ConsecCheck {
    None,
    Pfn,
}

impl ConsecChecker for ConsecCheck {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        match self {
            ConsecCheck::None => consec_check_none(block),
            ConsecCheck::Pfn => consec_check_pfn(block),
        }
    }
}

fn consec_check_none(block: &MemBlock) -> anyhow::Result<bool> {
    if (block.ptr as u64) & 0xFFF != 0 {
        bail!("Address is not page-aligned: 0x{:x}", block.ptr as u64);
    }
    Ok(true)
}

fn consec_check_pfn(block: &MemBlock) -> anyhow::Result<bool> {
    /*
     * Check whether the allocation is actually consecutive. The current implementation simply
     * checks for consecutive PFNs using the virt-to-phys pagemap. This needs root permissions.
     * Therefore, this check should be replaced with a timing side channel to verify the address function
     * in the memory block. If the measured timings correspond to the address function, it is very likely that
     * this indeed is a consecutive memory block.
     */
    use crate::memory::{LinuxPageMap, VirtToPhysResolver};
    let mut resolver = LinuxPageMap::new()?;
    if (block.ptr as u64) & 0xFFF != 0 {
        bail!("Address is not page-aligned: 0x{:x}", block.ptr as u64);
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
    Ok(first_block_bytes >= block.len)
}
