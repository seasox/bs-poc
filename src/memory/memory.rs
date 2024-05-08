use anyhow::Result;
use lazy_static::__Deref;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::fmt::Debug;

use crate::{
    jitter::AggressorPtr,
    memory::DRAMAddr,
    util::{MemConfiguration, PAGE_SIZE},
};

use super::allocator::MmapAllocator;
use libc::{c_void, memcmp};
use std::{
    alloc::{GlobalAlloc, Layout},
    arch::x86_64::{_mm_clflush, _mm_mfence},
    fmt,
    pin::Pin,
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

pub trait VictimMemory {
    fn addr(&self, offset: usize) -> *mut u8;
    fn len(&self) -> usize;
    fn initialize(&self, seed: <StdRng as SeedableRng>::Seed) {
        let mut rng = StdRng::from_seed(seed);

        let len = self.len();
        if len % 8 != 0 {
            panic!("memory len must be divisible by 8");
        }
        if len % PAGE_SIZE != 0 {
            panic!(
                "memory len ({}) must be divisible by PAGE_SIZE ({})",
                len, PAGE_SIZE
            );
        }

        debug!("initialize {} bytes with pseudo-random values", len);

        for offset in (0..len).step_by(PAGE_SIZE) {
            let mut value: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
            for i in 0..PAGE_SIZE {
                value[i] = rng.gen();
            }
            unsafe {
                std::ptr::write_volatile(self.addr(offset) as *mut [u8; PAGE_SIZE], value);
            }
        }
        debug!("memory init done");
    }

    fn check(
        &self,
        mem_config: MemConfiguration,
        seed: <StdRng as SeedableRng>::Seed,
    ) -> Vec<BitFlip> {
        let mut rng = StdRng::from_seed(seed);
        let len = self.len();
        assert_eq!(
            len % PAGE_SIZE,
            0,
            "memory len must be divisible by PAGE_SIZE"
        );
        unsafe {
            for page_no in (0..len).step_by(PAGE_SIZE) {
                let mut expected: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
                for i in 0..PAGE_SIZE {
                    expected[i] = rng.gen();
                }
                _mm_clflush(self.addr(page_no));
                _mm_mfence();
                let cmp = memcmp(
                    self.addr(page_no) as *const c_void,
                    expected.as_ptr() as *const c_void,
                    PAGE_SIZE,
                );
                if cmp == 0 {
                    continue;
                }
                debug!(
                    "Found bitflip in page {}. Determining exact flip position",
                    page_no
                );
                let mut ret = vec![];
                for i in 0..expected.len() {
                    let addr = self.addr(page_no + i);
                    _mm_clflush(addr);
                    _mm_mfence();
                    if *addr != expected[i] {
                        ret.push(BitFlip::new(
                            DRAMAddr::from_virt(addr, &mem_config),
                            *addr ^ expected[i],
                            expected[i],
                        ));
                    }
                }
                return ret;
            }
        }
        vec![]
    }
}

impl Memory {
    /// Move an instance of T into the allocated memory region at `offset', overwriting
    /// anything that might reside at `offset', returning a pinned reference to the moved
    /// object. This is an unsafe operation, as it relies on direct pointer operations.
    pub unsafe fn move_object<T: Unpin>(&self, x: T, offset: usize) -> Pin<&mut T> {
        let addr = self.addr.add(offset) as *mut T;
        core::ptr::write(addr, x);
        let pinned = Pin::new(&mut *addr);
        assert_eq!((pinned.deref() as *const T) as usize, addr as usize);
        pinned
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        unsafe {
            self.allocator.dealloc(self.addr as *mut u8, self.layout);
        }
    }
}

#[derive(Debug)]
pub struct Memory {
    allocator: MmapAllocator,
    addr: AggressorPtr,
    layout: Layout,
}

impl Memory {
    pub fn new(size: usize, use_hugepage: bool) -> Result<Self> {
        let allocator = MmapAllocator::new(use_hugepage);
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
}

impl VictimMemory for Memory {
    fn addr(&self, offset: usize) -> *mut u8 {
        unsafe { self.addr.add(offset) as *mut u8 }
    }
    fn len(&self) -> usize {
        return self.layout.size();
    }
}

#[derive(Debug)]
pub struct BitFlip {
    pub dram_addr: DRAMAddr,
    pub flips: u8,
    pub expected: u8,
}

impl BitFlip {
    fn new(dram_addr: DRAMAddr, flips: u8, expected: u8) -> Self {
        BitFlip {
            dram_addr,
            flips,
            expected,
        }
    }
}
