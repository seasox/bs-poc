use anyhow::{bail, Context, Result};
use lazy_static::lazy_static;
#[cfg(target_arch = "x86_64")]
use libc::{self, c_void, MAP_ANONYMOUS, MAP_FAILED, MAP_HUGETLB, PROT_READ, PROT_WRITE};
use libc::{MAP_HUGE_SHIFT, MAP_SHARED};
use std::{
    alloc::{GlobalAlloc, Layout},
    fs::File,
    io::Read,
    ptr::null_mut,
};

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
#[derive(Debug)]
pub(crate) struct MmapAllocator {
    use_hugepage: bool,
}

impl MmapAllocator {
    pub fn new(use_hugepage: bool) -> Self {
        MmapAllocator { use_hugepage }
    }
}

#[cfg(target_arch = "x86_64")]
unsafe impl GlobalAlloc for MmapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let len = align_to(layout.size(), *HUGEPAGE_SIZE as usize);
        let mut p = 0x2000000000 as *mut c_void;
        let mut mmap_flags = MAP_SHARED | MAP_ANONYMOUS;
        if self.use_hugepage {
            mmap_flags |= MAP_HUGETLB | (30 << MAP_HUGE_SHIFT);
        }
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

#[cfg(target_arch = "x86_64")]
#[cfg(test)]
pub mod tests {
    use super::*;
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
        let hugepage_alloc = MmapAllocator { use_hugepage: true };

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

pub trait VirtToPhysResolver {
    fn get_phys(&mut self, virt: u64) -> Result<u64>;
}

///LinuxPageMap uses /proc/self/pagemap to translate virtual to physical addresses.
/// Requires root rights
pub struct LinuxPageMap {
    pagemap_wrapper: pagemap::PageMap,
}

impl LinuxPageMap {
    pub fn new() -> Result<LinuxPageMap> {
        let pid = std::process::id();
        let res = LinuxPageMap {
            pagemap_wrapper: pagemap::PageMap::new(pid as u64)
                .with_context(|| "failed to open pagemap")?,
        };
        Ok(res)
    }
}

impl VirtToPhysResolver for LinuxPageMap {
    fn get_phys(&mut self, virt: u64) -> Result<u64> {
        //calc virtual address of page containing ptr_to_start
        let vaddr_start_page = virt & !0xFFF;
        let vaddr_end_page = vaddr_start_page + 4095;

        //query pagemap
        let memory_region = pagemap::MemoryRegion::from((vaddr_start_page, vaddr_end_page));
        let entry = self
            .pagemap_wrapper
            .pagemap_region(&memory_region)
            .with_context(|| {
                format!(
                    "failed to query pagemap for memory region {:?}",
                    memory_region
                )
            })?;
        if entry.len() != 1 {
            bail!(format! {
            "Got {} pagemap entries for virtual address 0x{:x}, expected exactly one",
            entry.len(),
            virt})
        }
        if entry[0].pfn()? == 0 {
            bail!(format! {
                "Got invalid PFN 0 for virtual address 0x{:x}. Are we root?",
                virt,
            })
        }

        let pfn = entry[0]
            .pfn()
            .with_context(|| format!("failed to get PFN for pagemap entry {:?}", entry[0]))?;
        let phys_addr = (pfn << 12) | ((virt as u64) & 0xFFF);

        Ok(phys_addr)
    }
}
