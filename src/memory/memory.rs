use super::allocator::HugePageAllocator;
use std::alloc::{GlobalAlloc, Layout};

pub struct Memory {
    pub addr: Option<*mut u8>,
    layout: Option<Layout>,
}

impl Memory {
    pub fn new() -> Self {
        Memory {
            addr: None,
            layout: None,
        }
    }
}

impl Memory {
    pub fn alloc(&mut self, size: usize) {
        let layout = Layout::array::<char>(size).unwrap();
        let dst: *mut u8;
        unsafe {
            dst = HugePageAllocator {}.alloc(layout);
        }
        self.addr = Some(dst);
        self.layout = Some(layout);
    }

    pub fn dealloc(&mut self) {
        if let (Some(addr), Some(layout)) = (self.addr, self.layout) {
            unsafe {
                HugePageAllocator {}.dealloc(addr, layout);
            }
        };
    }
}
