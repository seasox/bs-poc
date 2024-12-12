//! The `memory` module provides abstractions for memory management, initialization, and checking for bitflips.
//!
//! The `memory` module provides the following abstractions:
//! - `Memory`: A managed memory region that is allocated using HugepageAllocator.
//! - `VictimMemory`: A trait that combines the `BytePointer`, `Initializable`, and `Checkable` traits.
//! - `BytePointer`: A trait for accessing memory as a byte pointer.
//! - `Initializable`: A trait for initializing memory with (random) values.
//! - `Checkable`: A trait for checking memory for bitflips.
//! - `PfnResolver`: A trait for resolving the physical frame number (PFN) of a `self`.
//! - `LinuxPageMap`: A struct that provides a mapping from virtual to physical addresses.
//! - `VirtToPhysResolver`: A trait for resolving the physical address of a provided virtual address.
//!
//! The `memory` module also provides the following helper structs:
//! - `ConsecBlocks`: A struct that represents a collection of consecutive memory blocks.
//! - `MemBlock`: A struct that represents a memory block.
//! - `PfnOffset`: A struct that represents a physical frame number (PFN) offset.
//! - `PfnOffsetResolver`: A struct that resolves the physical frame number (PFN) offset of a provided virtual address.
//! - `Timer`: A struct that provides a timer for measuring memory access times.
//!
//! The `memory` module also provides the following helper functions:
//! - `construct_memory_tuple_timer`: A function that constructs a memory tuple timer.
mod consec_blocks;
mod consec_checker;
mod dram_addr;
mod keyed_cache;
mod memblock;
mod pagemap_info;
mod pfn_offset;
mod pfn_offset_resolver;
mod pfn_resolver;
mod timer;
mod virt_to_phys;

pub mod mem_configuration;

pub use self::consec_blocks::ConsecBlocks;
pub use self::consec_checker::*;
pub use self::dram_addr::DRAMAddr;
pub use self::memblock::*;
pub use self::pagemap_info::PageMapInfo;
pub use self::pfn_offset::PfnOffset;
pub use self::pfn_offset_resolver::PfnOffsetResolver;
pub use self::pfn_resolver::PfnResolver;
pub use self::timer::{construct_memory_tuple_timer, MemoryTupleTimer};
pub use self::virt_to_phys::{LinuxPageMap, VirtToPhysResolver};
use anyhow::Result;
use rand::{rngs::StdRng, Rng};
use serde::Serialize;
use std::fmt::Debug;

use crate::allocator::hugepage::HugepageAllocator;
use crate::util::PAGE_SIZE;

use crate::hammerer::blacksmith::jitter::AggressorPtr;
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

#[allow(clippy::len_without_is_empty)]
pub trait BytePointer {
    fn addr(&self, offset: usize) -> *mut u8;
    fn ptr(&self) -> *mut u8;
    fn len(&self) -> usize;
}

#[derive(Clone, Debug)]
pub enum DataPattern {
    Random(Box<StdRng>),
    StripeZero(/* zeroes: */ Vec<AggressorPtr>),
    StripeOne(/*  ones:   */ Vec<AggressorPtr>),
}

impl DataPattern {
    fn get(&mut self, addr: *const u8) -> [u8; PAGE_SIZE] {
        match self {
            DataPattern::Random(rng) => {
                let mut arr = [0u8; PAGE_SIZE];
                for byte in arr.iter_mut() {
                    *byte = rng.gen();
                }
                arr
            }
            DataPattern::StripeZero(zeroes) => {
                for &row in zeroes.iter() {
                    if (row as usize) == addr as usize & !(0x1FFF) {
                        trace!("setting aggressor page to 0x00 at addr {:p}", addr);
                        return [0x00; PAGE_SIZE];
                    }
                }
                [0xFF; PAGE_SIZE]
            }
            DataPattern::StripeOne(ones) => {
                for &row in ones.iter() {
                    if (row as usize) == addr as usize & !(0x1FFF) {
                        trace!("setting aggressor page to 0xFF at addr {:p}", addr);
                        return [0xFF; PAGE_SIZE];
                    }
                }
                [0x00; PAGE_SIZE]
            }
        }
    }
}

/// Trait for initializing memory with random values
pub trait Initializable {
    fn initialize(&self, pattern: DataPattern);
    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> [u8; PAGE_SIZE]);
}

#[derive(Clone, Copy, Debug, Serialize)]
pub struct BitFlip {
    pub addr: usize,
    pub bitmask: u8,
    pub data: u8,
}

impl BitFlip {
    pub fn new(addr: *const u8, bitmask: u8, data: u8) -> Self {
        BitFlip {
            addr: addr as usize,
            bitmask,
            data,
        }
    }
}

/// Trait for checking memory for bitflips
pub trait Checkable {
    fn check(&self, pattern: DataPattern) -> Vec<BitFlip>;
    fn check_cb(&self, f: &mut dyn FnMut(usize) -> [u8; PAGE_SIZE]) -> Vec<BitFlip>;
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
        let allocator = HugepageAllocator::default();
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
    fn initialize(&self, mut pattern: DataPattern) {
        info!(
            "initialize buffer with pattern {}",
            match pattern {
                DataPattern::Random(_) => "random",
                DataPattern::StripeZero(_) => "stripe zero",
                DataPattern::StripeOne(_) => "stripe one",
            }
        );
        self.initialize_cb(&mut |offset: usize| pattern.get(self.addr(offset)));
    }

    fn initialize_cb(&self, f: &mut dyn FnMut(usize) -> [u8; PAGE_SIZE]) {
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

        debug!("initialize {} bytes", len);

        for offset in (0..len).step_by(PAGE_SIZE) {
            let value = f(offset);
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
    fn check(&self, mut pattern: DataPattern) -> Vec<BitFlip> {
        self.check_cb(&mut |offset: usize| pattern.get(self.addr(offset)))
    }

    fn check_cb(&self, f: &mut dyn FnMut(usize) -> [u8; PAGE_SIZE]) -> Vec<BitFlip> {
        let len = self.len();
        if len % PAGE_SIZE != 0 {
            panic!(
                "memory len ({}) must be divisible by PAGE_SIZE ({})",
                len, PAGE_SIZE
            );
        }

        let mut ret = vec![];
        for offset in (0..len).step_by(PAGE_SIZE) {
            let expected: [u8; PAGE_SIZE] = f(offset);
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
                for (i, &expected) in expected.iter().enumerate() {
                    let addr = self.addr(offset + i);
                    _mm_clflush(addr);
                    _mm_mfence();
                    if *addr != expected {
                        ret.push(BitFlip::new(addr, *addr ^ expected, expected));
                    }
                }
            }
        }
        ret
    }
}
