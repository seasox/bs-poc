mod consec_blocks;
mod consec_checker;
mod dram_addr;
mod keyed_cache;
mod memblock;
mod memory;
mod pfn_offset;
mod pfn_offset_resolver;
mod timer;
mod virt_to_phys;

pub mod mem_configuration;

pub use self::consec_blocks::ConsecBlocks;
pub use self::consec_checker::*;
pub use self::dram_addr::DRAMAddr;
pub use self::memblock::*;
pub use self::memory::Memory;
pub use self::memory::{BytePointer, Checkable, Initializable, VictimMemory};
pub use self::pfn_offset::PfnOffset;
pub use self::pfn_offset_resolver::PfnOffsetResolver;
pub use self::timer::{construct_memory_tuple_timer, MemoryTupleTimer};
pub use self::virt_to_phys::{LinuxPageMap, VirtToPhysResolver};
pub use crate::allocator::hugepage::HugepageAllocator;
pub use crate::util::pfn_resolver::PfnResolver;
