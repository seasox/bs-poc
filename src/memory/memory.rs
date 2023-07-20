use anyhow::{Context, Error};

use super::allocator::HugePageAllocator;
use std::{
    alloc::{GlobalAlloc, Layout},
    fmt, mem,
    ptr::null_mut,
};

pub struct Memory {
    allocator: HugePageAllocator,
    pub addr: Option<*mut u8>,
    layout: Option<Layout>,
}

#[derive(Debug)]
pub enum MemoryError {
    AllocFailed,
}

impl std::error::Error for MemoryError {}

impl fmt::Display for MemoryError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MemoryError::AllocFailed => write!(f, "Allocation failed"),
        }
    }
}

impl Memory {
    pub fn new() -> Self {
        Memory {
            allocator: HugePageAllocator {},
            addr: None,
            layout: None,
        }
    }

    pub fn initialize(&self, value: u8) -> Result<(), Error> {
        let layout = self.layout.with_context(|| "layout not initialized")?;
        let addr = self.addr.with_context(|| "addr not initialized")?;
        unsafe {
            for offset in 0..layout.size() {
                std::ptr::write(addr.add(offset), value);
            }
        }
        Ok(())
    }

    pub fn check(&self, expected: u8) -> Result<bool, Error> {
        let layout = self.layout.with_context(|| "layout not initialized")?;
        let addr = self.addr.with_context(|| "addr not initialized")?;
        unsafe {
            for offset in 0..layout.size() {
                if *addr.add(offset) != expected {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

impl Memory {
    pub fn move_object<T>(&self, x: &mut T, offset: usize) -> Option<&mut T> {
        unsafe {
            let addr = self.addr?.add(offset);
            let dst: &mut T = &mut *(addr as *mut T);
            mem::swap(dst, x);
            Some(dst)
        }
    }
    pub fn alloc(&mut self, size: usize) -> Result<(), MemoryError> {
        let layout = Layout::array::<u8>(size).unwrap();
        let dst: *mut u8;
        unsafe {
            dst = self.allocator.alloc(layout);
        }
        if dst == null_mut() {
            return Err(MemoryError::AllocFailed);
        }
        self.addr = Some(dst);
        self.layout = Some(layout);
        Ok(())
    }
}

impl Drop for Memory {
    fn drop(&mut self) {
        if let (Some(addr), Some(layout)) = (self.addr, self.layout) {
            unsafe {
                self.allocator.dealloc(addr, layout);
            }
        };
    }
}
