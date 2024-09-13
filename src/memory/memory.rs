use anyhow::Result;
use rand::{rngs::StdRng, Rng, SeedableRng};
use std::fmt::Debug;

use crate::{memory::DRAMAddr, util::PAGE_SIZE};

use super::{LinuxPageMap, PfnResolver, VirtToPhysResolver};
use crate::allocator::hugepage::HugepageAllocator;
use crate::hammerer::blacksmith::hammerer::BitFlip;
use crate::hammerer::blacksmith::jitter::AggressorPtr;
use crate::memory::mem_configuration::MemConfiguration;
use libc::{c_void, memcmp};
use std::{
    alloc::{GlobalAlloc, Layout},
    arch::x86_64::{_mm_clflush, _mm_mfence},
    fmt,
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

pub trait VictimMemory: BytePointer + Initializable + Checkable {}

pub trait BytePointer {
    fn addr(&self, offset: usize) -> *mut u8;
    fn ptr(&self) -> *mut u8;
    fn len(&self) -> usize;
}

/// Trait for initializing memory with random values
pub trait Initializable {
    fn initialize(&self, seed: <StdRng as SeedableRng>::Seed);
    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> u8);
}

/// Trait for checking memory for bitflips
pub trait Checkable {
    fn check(
        &self,
        mem_config: MemConfiguration,
        seed: <StdRng as SeedableRng>::Seed,
    ) -> Vec<BitFlip>;
    fn check_cb(
        &self,
        mem_config: MemConfiguration,
        f: &mut dyn FnMut(usize) -> u8,
    ) -> Vec<BitFlip>;
}

/// A managed memory region that is allocated using HugepageAllocator
#[derive(Debug)]
pub struct Memory {
    allocator: HugepageAllocator,
    addr: AggressorPtr,
    layout: Layout,
}

impl Memory {
    pub fn new(size: usize) -> Result<Self> {
        let allocator = HugepageAllocator::new();
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
        Ok(Memory {
            allocator,
            addr,
            layout,
        })
    }
}

impl VictimMemory for Memory {}

impl BytePointer for Memory {
    fn addr(&self, offset: usize) -> *mut u8 {
        assert!(
            offset < self.layout.size(),
            "Offset {} >= {}",
            offset,
            self.layout.size()
        );
        unsafe { self.addr.byte_add(offset) as *mut u8 }
    }

    fn ptr(&self) -> *mut u8 {
        self.addr as *mut u8
    }

    fn len(&self) -> usize {
        self.layout.size()
    }
}

impl Memory {
    pub fn dealloc(self) {
        unsafe {
            self.allocator.dealloc(self.addr as *mut u8, self.layout);
        }
    }
}

/// Blanket implementations for Initializable trait for VictimMemory
impl<T> Initializable for T
where
    T: VictimMemory,
{
    fn initialize(&self, seed: <StdRng as SeedableRng>::Seed) {
        let mut rng = StdRng::from_seed(seed);
        info!(
            "initialize buffer with pseudo-random values from seed {:?}",
            seed
        );
        self.initialize_cb(&mut |_: usize| rng.gen());
        debug!("memory init done");
    }

    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> u8) {
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

        info!("initialize {} bytes", len);

        for offset in (0..len).step_by(PAGE_SIZE) {
            let mut value: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
            for i in 0..PAGE_SIZE {
                value[i] = f(offset + i);
            }
            unsafe {
                std::ptr::write_volatile(self.addr(offset) as *mut [u8; PAGE_SIZE], value);
            }
        }
        debug!("memory init done");
    }
}

/// Blanket implementation for PfnResolver trait for BytePointer
impl<T: BytePointer> PfnResolver for T {
    fn pfn(&self) -> anyhow::Result<u64> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(self.ptr() as u64)
    }
}

/// Blanket implementation for Checkable trait for VictimMemory
impl<T> Checkable for T
where
    T: VictimMemory,
{
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

    fn check_cb(
        &self,
        mem_config: MemConfiguration,
        f: &mut dyn FnMut(usize) -> u8,
    ) -> Vec<BitFlip> {
        let len = self.len();
        if len % PAGE_SIZE != 0 {
            panic!(
                "memory len ({}) must be divisible by PAGE_SIZE ({})",
                len, PAGE_SIZE
            );
        }

        let mut ret = vec![];
        for offset in (0..len).step_by(PAGE_SIZE) {
            let mut expected: [u8; PAGE_SIZE] = [0u8; PAGE_SIZE];
            for i in 0..PAGE_SIZE {
                expected[i] = f(offset + i);
            }
            unsafe {
                _mm_clflush(self.addr(offset));
                _mm_mfence();
                let cmp = memcmp(
                    self.addr(offset) as *const c_void,
                    expected.as_ptr() as *const c_void,
                    PAGE_SIZE,
                );
                if cmp == 0 {
                    continue;
                }
                debug!(
                    "Found bitflip in page {}. Determining exact flip position",
                    offset
                );
                for i in 0..expected.len() {
                    let addr = self.addr(offset + i);
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
            }
        }
        ret
    }
}
