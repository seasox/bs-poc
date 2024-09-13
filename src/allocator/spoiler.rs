use crate::memory::FormatPfns;
use std::fs::OpenOptions;
use std::io::Write;
use std::ptr::null_mut;

use itertools::Itertools;

use super::ConsecAllocator;
use crate::allocator::util::{compact_mem, mmap, munmap};
use crate::util::MB;
use crate::{addr_space, length, memory_addresses, retry};
use crate::{
    memory::{ConsecBlocks, MemBlock},
    util::PAGE_SIZE,
};

pub struct Spoiler {}

impl Spoiler {
    pub fn new() -> Self {
        Self {}
    }
}

/// Trait for converting raw pointers to Rust types
trait FromRaw<T> {
    /// Convert a raw pointer to a Rust type
    fn from_raw(raw_ptr: *mut T) -> Self;
}

type AddrSpace = Vec<*mut u8>;
impl FromRaw<addr_space> for AddrSpace {
    fn from_raw(raw_ptr: *mut addr_space) -> Self {
        let addrs = unsafe { memory_addresses(raw_ptr) };
        let addrs_len = unsafe { length(raw_ptr) } as usize;

        let vec = unsafe { Vec::from_raw_parts(addrs, addrs_len, addrs_len) };
        vec
    }
}

impl ConsecAllocator for Spoiler {
    fn block_size(&self) -> usize {
        1 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        use crate::auto_spoiler;

        const PAGE_COUNT: usize = 256 * 512;

        //let hugeblock_len = 1 << 30;
        //let v = mmap_block(null_mut(), hugeblock_len);

        let mut blocks = vec![];
        const BLOCK_SIZE: usize = 8 * MB;
        for _ in 0..size.div_ceil(BLOCK_SIZE) {
            let search_buffer_size = PAGE_COUNT * PAGE_SIZE;
            let addrs_blocks = retry!(|| {
                compact_mem()?;
                let search_buffer = mmap(null_mut(), search_buffer_size);
                let addr_space = auto_spoiler(search_buffer);
                if addr_space.is_null() {
                    libc::munmap(search_buffer as *mut libc::c_void, search_buffer_size);
                    return Err(anyhow::anyhow!("Failed to get address space"));
                }
                let base = MemBlock::new(search_buffer, 512 * MB);
                let pfns = base.consec_pfns()?.format_pfns();
                debug!("PFN ranges: {}", pfns);
                let mut f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("pfns.txt")
                    .expect("Failed to open pfns.txt");
                writeln!(f, "PFN ranges:\n{}", pfns).expect("Failed to write to pfns.txt");

                let addrs = AddrSpace::from_raw(addr_space);

                let to_munmap = (0..512 * MB)
                    .step_by(PAGE_SIZE)
                    .map(|i| search_buffer.byte_add(i))
                    .filter(|ptr| !addrs.contains(&ptr))
                    .collect_vec();

                for ptr in to_munmap {
                    munmap(ptr, PAGE_SIZE);
                }

                for &addr in &addrs {
                    unsafe { libc::memset(addr as *mut libc::c_void, 0x11, PAGE_SIZE) };
                }

                let addrs_blocks = addrs
                    .into_iter()
                    .map(|addr| MemBlock::new(addr, PAGE_SIZE))
                    .collect_vec();
                Ok(addrs_blocks)
            });
            blocks.extend(addrs_blocks);
        }
        Ok(ConsecBlocks { blocks })
    }
}
