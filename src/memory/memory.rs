use anyhow::Result;
use rand::{Rng, RngCore, SeedableRng};

use crate::jitter::AggressorPtr;

use super::allocator::HugePageAllocator;
use libc::{c_void, memcmp};
use std::{
    alloc::{GlobalAlloc, Layout},
    arch::x86_64::_mm_clflush,
    fmt, mem,
};

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

pub struct Memory {
    allocator: HugePageAllocator,
    pub addr: AggressorPtr,
    layout: Layout,
}

impl Memory {
    const PAGE_SIZE: usize = 4096; // TODO get from sysconf?

    pub fn new(size: usize) -> Result<Self> {
        let allocator = HugePageAllocator {};
        let layout = Layout::from_size_align(size, 1)?;
        if layout.size() == 0 {
            return Err(anyhow::Error::new(MemoryError::ZeroSizeLayout));
        }
        let dst: *mut u8;
        unsafe {
            dst = allocator.alloc(layout);
        }
        if dst.is_null() {
            return Err(anyhow::Error::new(MemoryError::AllocFailed));
        }
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        unsafe { std::ptr::write_bytes(dst, 0, layout.size()) };
        let addr = dst as AggressorPtr;
        let layout = layout;

        Ok(Memory {
            allocator,
            addr,
            layout,
        })
    }

    pub fn initialize<R: RngCore + SeedableRng>(&self, seed: R::Seed) -> Result<()> {
        let layout = self.layout;
        let addr = self.addr;
        let mut rng = R::from_seed(seed);

        let num_pages = layout.size() / Self::PAGE_SIZE;
        let len = layout.size();
        if len % 8 != 0 {
            panic!("layout size must be divisible by 8");
        }

        debug!("initialize {} pages with pseudo-random values", num_pages);

        for offset in (0..len).step_by(Self::PAGE_SIZE) {
            let mut value: [u8; Self::PAGE_SIZE] = [0u8; Self::PAGE_SIZE];
            for i in 0..Self::PAGE_SIZE {
                value[i] = rng.gen();
            }
            unsafe {
                std::ptr::write_volatile(addr.add(offset) as *mut [u8; Self::PAGE_SIZE], value);
            }
        }
        debug!("memory init done");
        Ok(())
    }

    pub fn check<R: RngCore + SeedableRng>(&self, seed: R::Seed) -> Result<bool> {
        let layout = self.layout;
        let addr = self.addr;
        let mut rng = R::from_seed(seed);
        unsafe {
            for offset in (0..layout.size()).step_by(Self::PAGE_SIZE) {
                let mut expected: [u8; Self::PAGE_SIZE] = [0u8; Self::PAGE_SIZE];
                for i in 0..Self::PAGE_SIZE {
                    expected[i] = rng.gen();
                }
                _mm_clflush(addr.add(offset));
                let cmp = memcmp(
                    addr.add(offset) as *const c_void,
                    expected.as_ptr() as *const c_void,
                    Self::PAGE_SIZE,
                );
                if cmp != 0 {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Memory {
    pub fn move_object<T>(&self, x: &mut T, offset: usize) -> &mut T {
        unsafe {
            let addr = self.addr.add(offset);
            let dst: &mut T = &mut *(addr as *mut T);
            mem::swap(dst, x);
            dst
        }
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            self.allocator.dealloc(self.addr as *mut u8, self.layout);
        }
    }
}
