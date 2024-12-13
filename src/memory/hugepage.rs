use std::alloc::{GlobalAlloc, Layout};

use crate::{allocator::hugepage::HugepageAllocator, hammerer::blacksmith::jitter::AggressorPtr};

use super::{BytePointer, MemoryError, VictimMemory};

/// A managed memory region that is allocated using HugepageAllocator
#[derive(Debug)]
pub struct Hugepage {
    allocator: HugepageAllocator,
    addr: AggressorPtr,
    layout: Layout,
}

impl Hugepage {
    pub fn new(size: usize) -> anyhow::Result<Self> {
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
        Ok(Self {
            allocator,
            addr,
            layout,
        })
    }
}

impl VictimMemory for Hugepage {}

impl BytePointer for Hugepage {
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

impl Hugepage {
    pub fn dealloc(self) {
        unsafe {
            self.allocator.dealloc(self.addr as *mut u8, self.layout);
        }
    }
}
