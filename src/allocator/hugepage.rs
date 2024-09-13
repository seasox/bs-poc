use crate::allocator::ConsecAllocator;
use crate::memory::{ConsecBlocks, HugepageSize, MemBlock};
use crate::util::{BASE_MSB, MB};
use anyhow::bail;
use lazy_static::lazy_static;
use libc::{
    MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, MAP_HUGE_1GB, MAP_SHARED, PROT_READ, PROT_WRITE,
};
use std::alloc::{GlobalAlloc, Layout};
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::ptr::null_mut;
// https://www.kernel.org/doc/Documentation/vm/hugetlbpage.txt
//
// The output of "cat /proc/meminfo" will include lines like:
// ...
// HugePages_Total: uuu
// HugePages_Free:  vvv
// HugePages_Rsvd:  www
// HugePages_Surp:  xxx
// Hugepagesize:    yyy kB
// Hugetlb:         zzz kB

// constant.
const MEMINFO_PATH: &str = "/proc/meminfo";
const TOKEN: &str = "Hugepagesize:";

lazy_static! {
    static ref HUGEPAGE_SIZE: isize = {
        let buf = File::open(MEMINFO_PATH).map_or("".to_owned(), |mut f| {
            let mut s = String::new();
            let _ = f.read_to_string(&mut s);
            s
        });
        parse_hugepage_size(&buf)
    };
}

fn parse_hugepage_size(s: &str) -> isize {
    for line in s.lines() {
        if line.starts_with(TOKEN) {
            let mut parts = line[TOKEN.len()..].split_whitespace();

            let p = parts.next().unwrap_or("0");
            let mut hugepage_size = p.parse::<isize>().unwrap_or(-1);

            hugepage_size *= parts.next().map_or(1, |x| match x {
                "kB" => 1024,
                _ => 1,
            });

            return hugepage_size;
        }
    }

    return -1;
}

fn align_to(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}

// hugepage allocator.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Copy, Clone)]
pub struct HugepageAllocator {}

impl HugepageAllocator {
    pub fn new() -> Self {
        HugepageAllocator {}
    }
}

#[cfg(target_arch = "x86_64")]
unsafe impl GlobalAlloc for HugepageAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let len = align_to(layout.size(), *HUGEPAGE_SIZE as usize);
        let mut p = BASE_MSB;
        let mut mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
        mmap_flags |= MAP_HUGETLB | MAP_HUGE_1GB;
        p = libc::mmap(p, len, PROT_READ | PROT_WRITE, mmap_flags, -1, 0);

        if p == MAP_FAILED {
            return null_mut();
        }

        debug!("mmaped to 0x{:02X}", p as u64);
        p as *mut u8
    }

    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        let len = align_to(layout.size(), *HUGEPAGE_SIZE as usize);
        libc::munmap(p as *mut c_void, len);
    }
}

impl ConsecAllocator for HugepageAllocator {
    fn block_size(&self) -> usize {
        *HUGEPAGE_SIZE as usize
    }
    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<super::ConsecBlocks> {
        if size > self.block_size() {
            bail!(
                "Only support allocations up to 0x{:x} bytes",
                self.block_size()
            );
        }
        assert_eq!(self.block_size(), 1024 * MB);
        let block = MemBlock::hugepage(HugepageSize::OneGb)?;
        unsafe { libc::memset(block.ptr as *mut c_void, 0x00, self.block_size()) };
        Ok(ConsecBlocks::new(vec![block]))
    }
}

#[cfg(target_arch = "x86_64")]
#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::allocator::hugepage::HugepageAllocator;
    use std::{mem, ptr};

    #[test]
    fn test_parse_hugepage_size() {
        // correct.
        assert_eq!(parse_hugepage_size("Hugepagesize:1024"), 1024);
        assert_eq!(parse_hugepage_size("Hugepagesize: 2 kB"), 2048);

        // wrong.
        assert_eq!(parse_hugepage_size("Hugepagesize:1kB"), -1);
        assert_eq!(parse_hugepage_size("Hugepagesize: 2kB"), -1);
    }

    #[test]
    fn test_align_to() {
        assert_eq!(align_to(8, 4), 8);
        assert_eq!(align_to(8, 16), 16);
    }

    #[test]
    fn test_allocator() {
        let hugepage_alloc = HugepageAllocator {};

        // u16.
        unsafe {
            let layout = Layout::new::<u16>();
            let p = hugepage_alloc.alloc(layout);
            assert_eq!(p.is_null(), false);
            *p = 20;
            assert_eq!(*p, 20);
            hugepage_alloc.dealloc(p, layout);
        }

        // array.
        unsafe {
            let layout = Layout::array::<char>(2048).unwrap();
            let dst = hugepage_alloc.alloc(layout);
            assert_eq!(dst.is_null(), false);

            let src = String::from("hello rust");
            let len = src.len();
            ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            let s = String::from_raw_parts(dst, len, len);
            assert_eq!(s, src);
            mem::forget(s);

            hugepage_alloc.dealloc(dst, layout);
        }
    }
}
