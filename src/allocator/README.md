Memory allocation strategies for allocating consecutive memory blocks.

This module provides different memory allocation strategies for allocating consecutive memory blocks. The strategies include buddy allocation, CoCo, hugepage allocation, mmap, and spoiler.

To add a new memory allocation strategy, implement the `ConsecAllocator` trait for the new strategy and add a new variant to the `ConsecAlloc` enum.

License: MIT
