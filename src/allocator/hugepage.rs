use crate::allocator::ConsecAllocator;
use crate::memory::{ConsecBlocks, HugepageSize, MemBlock};
use crate::util::MB;
use anyhow::bail;
use lazy_static::lazy_static;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
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
            let mut parts = match line.strip_prefix(TOKEN) {
                Some(line) => line.split_whitespace(),
                None => panic!("Invalid line: {}", line),
            };

            let p = parts.next().unwrap_or("0");
            let mut hugepage_size = p.parse::<isize>().unwrap_or(-1);

            hugepage_size *= parts.next().map_or(1, |x| match x {
                "kB" => 1024,
                _ => 1,
            });

            return hugepage_size;
        }
    }

    -1
}

// hugepage allocator.
#[cfg(target_arch = "x86_64")]
#[derive(Debug, Default, Copy, Clone)]
pub struct HugepageAllocator {}

impl ConsecAllocator for HugepageAllocator {
    fn block_size(&self) -> usize {
        *HUGEPAGE_SIZE as usize
    }
    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<super::ConsecBlocks> {
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
    use crate::{allocator::hugepage::HugepageAllocator, memory::BytePointer};
    use std::{alloc::Layout, mem, ptr};

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
    fn test_allocator() {
        let mut hugepage_alloc = HugepageAllocator {};

        // u16.
        unsafe {
            let layout = Layout::new::<u16>();
            let mem = hugepage_alloc
                .alloc_consec_blocks(layout.size())
                .expect("allocation failed");
            let p = mem.ptr();
            assert!(!p.is_null(), "allocation failed");
            *p = 20;
            assert_eq!(*p, 20);
            mem.dealloc();
        }

        // array.
        unsafe {
            let layout = Layout::array::<char>(2048).unwrap();
            let mem = hugepage_alloc
                .alloc_consec_blocks(layout.size())
                .expect("allocation failed");
            let dst = mem.ptr();
            assert!(!dst.is_null(), "allocation failed");

            let src = String::from("hello rust");
            let len = src.len();
            ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
            let s = String::from_raw_parts(dst, len, len);
            assert_eq!(s, src);
            mem::forget(s);

            mem.dealloc();
        }
    }
}
