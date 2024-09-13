mod allocator;
mod consec_blocks;
mod consec_checker;
mod dram_addr;
mod keyed_cache;
mod memblock;
mod memory;
mod pfn_offset;
mod pfn_offset_resolver;
mod pfn_resolver;
mod timer;
mod util;

pub mod consec_alloc;

pub use self::allocator::{HugepageAllocator, LinuxPageMap, VirtToPhysResolver};
pub use self::consec_blocks::ConsecBlocks;
pub use self::consec_checker::*;
pub use self::dram_addr::DRAMAddr;
pub use self::memblock::*;
pub use self::memory::Memory;
pub use self::memory::{BytePointer, Checkable, Initializable, VictimMemory};
pub use self::pfn_offset::PfnOffset;
pub use self::pfn_offset_resolver::PfnOffsetResolver;
pub use self::pfn_resolver::PfnResolver;
pub use self::timer::{construct_memory_tuple_timer, MemoryTupleTimer};
pub use self::util::compact_mem;
