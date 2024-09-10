use itertools::Itertools;

use crate::memory::compact_mem;
use crate::util::{KB, MB};
use crate::{length, memory_addresses, retry};
use crate::{
    memory::{ConsecBlocks, MemBlock},
    util::PAGE_SIZE,
};

use super::ConsecAllocator;

pub struct ConsecAllocSpoiler {}

impl ConsecAllocSpoiler {
    pub fn new() -> Self {
        Self {}
    }
}

impl ConsecAllocator for ConsecAllocSpoiler {
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
            let addr_space = retry!(|| {
                compact_mem()?;
                let search_buffer = unsafe {
                    let ptr = libc::mmap(
                        std::ptr::null_mut(),
                        PAGE_COUNT * PAGE_SIZE,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_POPULATE | libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                        -1,
                        0,
                    );
                    if ptr == libc::MAP_FAILED {
                        panic!("Failed to mmap");
                    }
                    std::mem::transmute::<*mut libc::c_void, *mut u8>(ptr)
                };
                let a = auto_spoiler(search_buffer);
                if a.is_null() {
                    libc::munmap(search_buffer as *mut libc::c_void, PAGE_COUNT * PAGE_SIZE);
                    Err(anyhow::anyhow!("Failed to get address space"))
                } else {
                    let base = MemBlock::new(search_buffer, 512 * MB);
                    let pfns = (0..512 * MB - 4 * KB)
                        .step_by(4 * KB)
                        .map(|i| base.byte_add(i).pfn().unwrap())
                        .sorted()
                        .collect_vec();
                    let pfns = pfns.format_pfns();
                    info!("PFN ranges: {}", pfns);
                    let mut f = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open("pfns.txt")
                        .expect("Failed to open pfns.txt");
                    writeln!(f, "PFN ranges:\n{}", pfns).expect("Failed to write to pfns.txt");
                    Ok(a)
                }
            });

            let addrs = memory_addresses(addr_space);
            let addrs_len = length(addr_space) as usize;

            // TODO munmap search_buffer \setminus addrs

            let addrs_blocks = (0..addrs_len)
                .map(|i| MemBlock::new(*addrs.add(i), 4 * KB))
                .collect_vec();
            let cons = ConsecBlocks::new(addrs_blocks.clone());
            cons.log_pfns();
            blocks.extend(addrs_blocks);
        }

        Ok(ConsecBlocks { blocks })
    }
}
