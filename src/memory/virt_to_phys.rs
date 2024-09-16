use anyhow::{bail, Context, Result};

use crate::util::PAGE_SHIFT;

pub trait VirtToPhysResolver {
    fn get_phys(&mut self, virt: u64) -> Result<u64>;
}

/// LinuxPageMap uses /proc/self/pagemap to translate virtual to physical addresses.
/// Requires root rights
pub struct LinuxPageMap {
    pagemap_wrapper: pagemap::PageMap,
}

impl LinuxPageMap {
    pub fn new() -> Result<LinuxPageMap> {
        let pid = std::process::id();
        let res = LinuxPageMap {
            pagemap_wrapper: pagemap::PageMap::new(pid as u64)
                .with_context(|| "failed to open pagemap")?,
        };
        Ok(res)
    }
}

impl VirtToPhysResolver for LinuxPageMap {
    fn get_phys(&mut self, virt: u64) -> Result<u64> {
        //calc virtual address of page containing ptr_to_start
        let vaddr_start_page = virt & !0xFFF;
        let vaddr_end_page = vaddr_start_page + 4095;

        //query pagemap
        let memory_region = pagemap::MemoryRegion::from((vaddr_start_page, vaddr_end_page));
        let entry = self
            .pagemap_wrapper
            .pagemap_region(&memory_region)
            .with_context(|| {
                format!(
                    "failed to query pagemap for memory region {:?}",
                    memory_region
                )
            })?;
        if entry.len() != 1 {
            bail!(format! {
            "Got {} pagemap entries for virtual address 0x{:x}, expected exactly one",
            entry.len(),
            virt})
        }
        if entry[0].pfn()? == 0 {
            bail!(format! {
                "Got invalid PFN 0 for virtual address 0x{:x}. Are we root?",
                virt,
            })
        }

        let pfn = entry[0]
            .pfn()
            .with_context(|| format!("failed to get PFN for pagemap entry {:?}", entry[0]))?;
        let phys_addr = (pfn << PAGE_SHIFT) | (virt & 0xFFF);

        Ok(phys_addr)
    }
}
