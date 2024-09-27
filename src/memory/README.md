# Module src/memory
The `memory` module provides abstractions for memory management, initialization, and checking for bitflips.

The `memory` module provides the following abstractions:
- `Memory`: A managed memory region that is allocated using HugepageAllocator.
- `VictimMemory`: A trait that combines the `BytePointer`, `Initializable`, and `Checkable` traits.
- `BytePointer`: A trait for accessing memory as a byte pointer.
- `Initializable`: A trait for initializing memory with (random) values.
- `Checkable`: A trait for checking memory for bitflips.
- `PfnResolver`: A trait for resolving the physical frame number (PFN) of a `self`.
- `LinuxPageMap`: A struct that provides a mapping from virtual to physical addresses.
- `VirtToPhysResolver`: A trait for resolving the physical address of a provided virtual address.

The `memory` module also provides the following helper structs:
- `ConsecBlocks`: A struct that represents a collection of consecutive memory blocks.
- `MemBlock`: A struct that represents a memory block.
- `PfnOffset`: A struct that represents a physical frame number (PFN) offset.
- `PfnOffsetResolver`: A struct that resolves the physical frame number (PFN) offset of a provided virtual address.
- `Timer`: A struct that provides a timer for measuring memory access times.

The `memory` module also provides the following helper functions:
- `construct_memory_tuple_timer`: A function that constructs a memory tuple timer.

License: MIT
