use std::ptr::null_mut;

use anyhow::bail;

use crate::{
    memory::{
        mem_configuration::MemConfiguration, ConsecBlocks, DRAMAddr, GetConsecPfns, MemBlock,
    },
    util::MB,
};

use super::{util::mmap, ConsecAllocator};

pub struct Pfn {
    mem_config: MemConfiguration,
}

/// Pfn allocator. This finds consecutive PFNs by allocating memory and checking the page map.
/// Useful for testing purposes.
impl Pfn {
    pub fn new(mem_config: MemConfiguration) -> Self {
        Self { mem_config }
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
            debug!("phys(x) = {:p}", x.pfn()?);
            let pfns = (x, BUFSIZE).consec_pfns()?;
            (x, BUFSIZE).log_pfns(log::Level::Trace);
            let consecs = pfns
                .iter()
                .enumerate()
                .filter(|(_, range)| (range.end - range.start).as_usize() == self.block_size());
            let mut unmap_ranges = vec![];
            let mut prev_end = x;
            for (idx, _) in consecs {
                if blocks.len() >= block_count {
                    unmap_ranges.push((prev_end, unsafe { x.byte_add(BUFSIZE) }));
                    break;
                }
                let offset: usize = pfns
                    .iter()
                    .take(idx)
                    .map(|range| (range.end - range.start).as_usize())
                    .sum();
                let bank = DRAMAddr::from_virt(pfns[idx].start.into(), &self.mem_config).bank;
                //assert_eq!(bank, 0, "Base bank of 0x{:x} is not zero. The PFN allocation strategy only supports allocation of up to 4 MB (22 bit address alignment), but apparently, some bank bits are above bit 22 (or you found a bug).", pfns[idx].start);
                if bank != 0 {
                    debug!("Bank {} != 0, retrying...", bank);
                    unmap_ranges.push((prev_end, unsafe { x.byte_add(offset) }));
                    continue;
                }
                let start_ptr = unsafe { x.byte_add(offset as usize) };
                blocks.push(MemBlock::new(start_ptr, self.block_size()));
                unmap_ranges.push((prev_end, start_ptr));
                prev_end = unsafe { start_ptr.byte_add(self.block_size()) };
            }
            for unmap_range in unmap_ranges {
                unsafe {
                    libc::munmap(
                        unmap_range.0 as *mut libc::c_void,
                        unmap_range.1 as usize - unmap_range.0 as usize,
                    );
                }
            }
        }
        Ok(ConsecBlocks::new(blocks))
    }
}
