use anyhow::{Context, Result};
use rand::{Rng, RngCore, SeedableRng};

use crate::jitter::MutAggPointer;

use super::allocator::HugePageAllocator;
use std::{
    alloc::{GlobalAlloc, Layout},
    fmt, mem,
};

pub struct Memory {
    allocator: HugePageAllocator,
    pub addr: Option<MutAggPointer>,
    layout: Option<Layout>,
}

#[derive(Debug)]
pub enum MemoryError {
    AllocFailed,
    ZeroSizeLayout,
}

impl std::error::Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryError::AllocFailed => write!(f, "Allocation failed"),
            MemoryError::ZeroSizeLayout => write!(f, "Zero size layout"),
        }
    }
}

impl Memory {
    pub fn new() -> Self {
        Memory {
            allocator: HugePageAllocator {},
            addr: None,
            layout: None,
        }
    }

    pub fn initialize<R: RngCore + SeedableRng>(&self, seed: R::Seed) -> Result<()> {
        let layout = self.layout.with_context(|| "layout not initialized")?;
        let addr = self.addr.with_context(|| "addr not initialized")?;
        let mut rng = R::from_seed(seed);
        const PAGE_SIZE: usize = 4096; // TODO get from sysconf?

        let num_pages = layout.size() / PAGE_SIZE;
        if layout.size() % 8 != 0 {
            panic!("layout size must be divisble by 8");
        }

        debug!("initialize {} pages with pseudo-random values", num_pages);

        for offset in (0..layout.size()).step_by(PAGE_SIZE) {
            let mut value: [u8; 4096] = [0u8; PAGE_SIZE];
            for i in 0..PAGE_SIZE {
                value[i] = rng.gen();
            }
            unsafe {
                std::ptr::write_volatile(addr.add(offset) as *mut [u8; PAGE_SIZE], value);
            }
            debug!(
                "{} ({}/{}) done",
                offset as f64 / layout.size() as f64,
                offset,
                layout.size()
            );
        }
        debug!("done");
        Ok(())
    }

    pub fn check<R: RngCore + SeedableRng>(&self, seed: R::Seed) -> Result<bool> {
        let layout = self.layout.with_context(|| "layout not initialized")?;
        let addr = self.addr.with_context(|| "addr not initialized")?;
        let mut rng = R::from_seed(seed);
        unsafe {
            for offset in 0..layout.size() {
                let expected = rng.gen::<u8>();
                if *(addr.add(offset) as *const u8) != expected {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Memory {
    pub fn move_object<T>(&self, x: &mut T, offset: usize) -> Option<&mut T> {
        unsafe {
            let addr = self.addr?.add(offset);
            let dst: &mut T = &mut *(addr as *mut T);
            mem::swap(dst, x);
            Some(dst)
        }
    }
    pub fn alloc(&mut self, size: usize) -> Result<()> {
        let layout = Layout::from_size_align(size, 1)?;
        if layout.size() == 0 {
            return Err(anyhow::Error::new(MemoryError::ZeroSizeLayout));
        }
        let dst: *mut u8;
        unsafe {
            dst = self.allocator.alloc(layout);
        }
        if dst.is_null() {
            return Err(anyhow::Error::new(MemoryError::AllocFailed));
        }
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        unsafe { std::ptr::write_bytes(dst, 0, layout.size()) };
        self.addr = Some(dst as MutAggPointer);
        self.layout = Some(layout);
        Ok(())
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        if let (Some(addr), Some(layout)) = (self.addr, self.layout) {
            unsafe {
                self.allocator.dealloc(addr as *mut u8, layout);
            }
        };
    }
}
