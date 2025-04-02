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
mod flippy_page;
mod hugepage;
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
pub use self::flippy_page::{find_flippy_page, FlippyPage};
pub use self::hugepage::Hugepage;
pub use self::memblock::*;
pub use self::pagemap_info::PageMapInfo;
pub use self::pfn_offset::PfnOffset;
pub use self::pfn_offset_resolver::PfnOffsetResolver;
pub use self::pfn_resolver::PfnResolver;
pub use self::timer::{construct_memory_tuple_timer, MemoryTupleTimer};
pub use self::virt_to_phys::PhysAddr;
pub use self::virt_to_phys::{LinuxPageMap, VirtToPhysResolver};
use rand::Rng as _;
use serde::Serialize;
use std::arch::x86_64::_mm_clflush;
use std::fmt::Debug;
use std::io::BufWriter;

use crate::util::{Rng, CL_SIZE, PAGE_SIZE, ROW_MASK, ROW_SIZE};

use crate::hammerer::blacksmith::jitter::AggressorPtr;
use libc::{c_void, memcmp};
use std::{arch::x86_64::_mm_mfence, fmt};

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

    fn dump(&self, file: &str) -> std::io::Result<()> {
        use std::fs::File;
        use std::io::Write;
        let file = File::create(file)?;
        let mut writer = BufWriter::new(file);
        for offset in (0..self.len()).step_by(ROW_SIZE) {
            for byte_offset in 0..ROW_SIZE {
                write!(writer, "{:02x}", unsafe {
                    *self.addr(offset + byte_offset)
                })?;
            }
            writer.write_all(b"\n")?;
        }
        writer.flush()?;
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum DataPattern {
    Random(Box<Rng>),
    StripeZero(
        /* zeroes: */ #[serde(skip_serializing)] Vec<AggressorPtr>,
    ),
    StripeOne(
        /*  ones:   */ #[serde(skip_serializing)] Vec<AggressorPtr>,
    ),
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
                    if (row as usize) == addr as usize & !ROW_MASK {
                        trace!("setting aggressor page to 0x00 at addr {:p}", addr);
                        return [0x00; PAGE_SIZE];
                    }
                }
                [0xFF; PAGE_SIZE]
            }
            DataPattern::StripeOne(ones) => {
                for &row in ones.iter() {
                    if (row as usize) == addr as usize & !ROW_MASK {
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

#[derive(Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub struct BitFlip {
    pub addr: usize,
    pub bitmask: u8,
    /// the *expected* data
    pub data: u8,
}

#[derive(Clone, Debug, Serialize, Eq, PartialEq)]
pub enum FlipDirection {
    ZeroToOne,
    OneToZero,
    Multiple(Vec<FlipDirection>),
    None,
    Any,
}

impl core::fmt::Debug for BitFlip {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BitFlip")
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("bitmask", &format_args!("{:#x}", self.bitmask))
            .field("data", &format_args!("{:#x}", self.data))
            .finish()
    }
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

impl BitFlip {
    pub fn flip_direction(&self) -> FlipDirection {
        match self.bitmask.count_ones() {
            0 => FlipDirection::None,
            1 => {
                let flipped = self.bitmask & self.data;
                match flipped {
                    0 => FlipDirection::ZeroToOne,
                    _ => FlipDirection::OneToZero,
                }
            }
            2.. => FlipDirection::Multiple(
                (0..8)
                    .filter_map(|i| {
                        if self.bitmask & (1 << i) != 0 {
                            Some(if self.data & (1 << i) != 0 {
                                FlipDirection::OneToZero
                            } else {
                                FlipDirection::ZeroToOne
                            })
                        } else {
                            None
                        }
                    })
                    .collect(),
            ),
        }
    }
}

/// Trait for checking memory for bitflips
pub trait Checkable {
    fn check(&self, pattern: DataPattern) -> Vec<BitFlip>;
    fn check_cb(&self, f: &mut dyn FnMut(usize) -> [u8; PAGE_SIZE]) -> Vec<BitFlip>;
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
    fn pfn(&self) -> anyhow::Result<PhysAddr> {
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
                for byte_offset in (0..PAGE_SIZE).step_by(CL_SIZE) {
                    _mm_clflush(self.addr(offset + byte_offset));
                }
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

#[test]
fn test_pattern_random_clone() -> anyhow::Result<()> {
    let pattern = DataPattern::Random(Box::new(Rng::from_seed(rand::random())));
    let a = pattern.clone().get(std::ptr::null());
    let b = pattern.clone().get(std::ptr::null());
    assert_eq!(a, b);
    Ok(())
}

#[test]
fn test_bitflip_direction() {
    let flip = BitFlip::new(std::ptr::null(), 0b0000_0000, 0xFF);
    assert_eq!(flip.flip_direction(), FlipDirection::None);
    let flip = BitFlip::new(std::ptr::null(), 0b0000_0001, 0b0000_0001);
    assert_eq!(flip.flip_direction(), FlipDirection::OneToZero);

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0001, 0b1111_1110);
    assert_eq!(flip.flip_direction(), FlipDirection::ZeroToOne);

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0010);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::ZeroToOne, FlipDirection::OneToZero])
    );

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0000);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::ZeroToOne, FlipDirection::ZeroToOne])
    );

    let flip = BitFlip::new(std::ptr::null(), 0b0000_0011, 0b0000_0011);
    assert_eq!(
        flip.flip_direction(),
        FlipDirection::Multiple(vec![FlipDirection::OneToZero, FlipDirection::OneToZero])
    );
}
