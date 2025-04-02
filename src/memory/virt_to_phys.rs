use std::ops::{Add, Sub};

use anyhow::{bail, Context, Result};
use itertools::Itertools;
use pagemap::{MemoryRegion, PageMapError};
use serde::Serialize;

use crate::util::PAGE_SHIFT;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct PhysAddr(usize);

impl PhysAddr {
    pub fn new(addr: usize) -> Self {
        PhysAddr(addr)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }
}

pub trait VirtToPhysResolver {
    fn get_phys(&mut self, virt: u64) -> Result<PhysAddr>;
    fn get_phys_range(&mut self, region: MemoryRegion) -> Result<Vec<PhysAddr>>;
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
    fn get_phys_range(&mut self, memory_region: MemoryRegion) -> Result<Vec<PhysAddr>> {
        let entry = self
            .pagemap_wrapper
            .pagemap_region(&memory_region)
            .with_context(|| {
                format!(
                    "failed to query pagemap for memory region {:?}",
                    memory_region
                )
            })?;
        Ok(entry
            .into_iter()
            .map(|e| e.pfn().map(|p| (p << PAGE_SHIFT)))
            .collect::<Result<Vec<u64>, PageMapError>>()?
            .iter()
            .map(|p| PhysAddr(*p as usize))
            .collect_vec())
    }
    fn get_phys(&mut self, virt: u64) -> Result<PhysAddr> {
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
        let phys_addr = ((pfn << PAGE_SHIFT) | (virt & 0xFFF)) as usize;

        Ok(PhysAddr(phys_addr))
    }
}

impl From<PhysAddr> for usize {
    fn from(addr: PhysAddr) -> usize {
        addr.0
    }
}

impl From<PhysAddr> for *const u8 {
    fn from(addr: PhysAddr) -> *const u8 {
        addr.0 as *const u8
    }
}

impl std::fmt::Pointer for PhysAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:p}", self.0 as *const u8)
    }
}

impl Add<PhysAddr> for PhysAddr {
    type Output = PhysAddr;

    fn add(self, rhs: PhysAddr) -> Self::Output {
        PhysAddr(self.0 + rhs.0)
    }
}

impl Sub<PhysAddr> for PhysAddr {
    type Output = PhysAddr;

    fn sub(self, rhs: PhysAddr) -> Self::Output {
        assert!(self.0 >= rhs.0);
        PhysAddr(self.0 - rhs.0)
    }
}

impl Add<usize> for PhysAddr {
    type Output = PhysAddr;

    fn add(self, rhs: usize) -> Self::Output {
        PhysAddr(self.0 + rhs)
    }
}

impl Sub<usize> for PhysAddr {
    type Output = PhysAddr;

    fn sub(self, rhs: usize) -> Self::Output {
        assert!(self.0 >= rhs);
        PhysAddr(self.0 - rhs)
    }
}
