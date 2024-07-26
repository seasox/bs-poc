use std::{ffi::CString, io::Read, process::Command, ptr::null_mut};

#[cfg(feature = "spoiler")]
use crate::memory_addresses;

use crate::{
    retry,
    util::{MB, PAGE_SIZE},
};
use anyhow::{bail, Context};
use lpfs::proc::buddyinfo::BuddyInfo;
use rand::prelude::SliceRandom;
use rand::Rng;
use std::cmp::min;

use super::{AllocChecker, VictimMemory};

pub trait ConsecAllocator {
    fn block_size(&self) -> usize;
    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: &dyn Fn(),
    ) -> anyhow::Result<ConsecBlocks>;
}

pub struct ConsecBlocks {
    pub blocks: Vec<MemBlock>,
}

impl ConsecBlocks {
    pub fn new(blocks: Vec<MemBlock>) -> Self {
        ConsecBlocks { blocks }
    }
    pub fn dealloc(self) {
        for block in self.blocks {
            unsafe { libc::munmap(block.ptr as *mut libc::c_void, block.len) };
        }
    }
}

impl VictimMemory for ConsecBlocks {
    fn addr(&self, offset: usize) -> *mut u8 {
        let mut offset = offset;
        for block in &self.blocks {
            if offset < block.len {
                return unsafe { block.ptr.add(offset) as *mut u8 };
            }
            offset -= block.len;
        }
        unreachable!("block not found for offset {}", offset);
    }

    fn len(&self) -> usize {
        return self.blocks.iter().map(|block| block.len).sum();
    }
}

pub struct ConsecAllocHugepageRnd {
    hugepages: Vec<ConsecBlocks>,
}

impl ConsecAllocHugepageRnd {
    pub fn new(hugepages: Vec<ConsecBlocks>) -> Self {
        ConsecAllocHugepageRnd { hugepages }
    }
}

impl ConsecAllocator for ConsecAllocHugepageRnd {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: &dyn Fn(),
    ) -> anyhow::Result<ConsecBlocks> {
        let hp_size = 1024 * MB;
        let chunk_size = self.block_size();
        let num_chunks = hp_size / chunk_size;
        let total_chunks = self.hugepages.len() * num_chunks;
        let num_blocks = size / chunk_size;

        let mut chunk_indices: Vec<usize> = (0..total_chunks).collect();
        let mut rng = rand::thread_rng();
        chunk_indices.shuffle(&mut rng);
        let selected_indices = &chunk_indices[..num_blocks];
        //let free_indices = &chunk_indices[num_blocks..];

        let blocks = selected_indices
            .iter()
            .map(|index| {
                info!("Hugepage {}", index / num_chunks);
                progress_cb();
                self.hugepages[index / num_chunks].addr((index % num_chunks) * chunk_size)
            })
            .map(|ptr| MemBlock::new(ptr, chunk_size))
            .collect::<Vec<_>>();
        let consecs = ConsecBlocks::new(blocks);
        Ok(consecs)
    }
}

pub struct ConsecAllocCoCo {}

impl ConsecAllocator for ConsecAllocCoCo {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: &dyn Fn(),
    ) -> anyhow::Result<ConsecBlocks> {
        const mod_path: &str = "/dev/coco_dec_mem";
        let c_mod_path = CString::new(mod_path)?;
        let fd = libc::open(c_mod_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd == -1 {
            bail!("Failed to open {}", mod_path);
        }
        let block_size: usize = self.block_size();
        let block_count = (size as f32 / block_size as f32).ceil() as i32;
        let blocks = (0..block_count)
            .map(|_| {
                let v = libc::mmap(
                    std::ptr::null_mut(),
                    block_size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    fd,
                    0,
                );
                if v == libc::MAP_FAILED {
                    bail!("Failed to mmap");
                }
                let block = MemBlock::new(v as *mut u8, 4 * MB);
                libc::memset(block.ptr as *mut libc::c_void, 0, block.len);
                //consec_checker.check(&block)?;
                progress_cb();
                Ok(block)
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        libc::close(fd);
        Ok(ConsecBlocks::new(blocks))
    }
}

pub struct ConsecAllocMmap {
    consec_checker: Box<dyn AllocChecker>,
}

impl ConsecAllocMmap {
    pub fn new(checkers: Box<dyn AllocChecker>) -> Self {
        ConsecAllocMmap {
            consec_checker: checkers,
        }
    }
}

impl ConsecAllocator for ConsecAllocMmap {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: &dyn Fn(),
    ) -> anyhow::Result<ConsecBlocks> {
        assert_eq!(size % self.block_size(), 0);
        let num_blocks = size / self.block_size();
        let mut blocks = Vec::with_capacity(num_blocks);
        const MAX_ALLOCS: usize = 5000;
        let mut allocs: Vec<MemBlock> = Vec::with_capacity(MAX_ALLOCS * num_blocks + 1);
        const DUMMY_ALLOC_SIZE: usize = 4 * 1024 * MB;
        let buf = MemBlock::new(
            mmap_block(null_mut(), DUMMY_ALLOC_SIZE) as *mut u8,
            DUMMY_ALLOC_SIZE,
        );
        allocs.push(buf);
        'next_block: for _ in 0..num_blocks {
            for _ in 0..MAX_ALLOCS {
                let m = mmap_block(null_mut(), self.block_size());
                let block = MemBlock::new(m as *mut u8, self.block_size());
                let is_consec = self.consec_checker.check(&block)?;
                if is_consec {
                    blocks.push(block);
                    progress_cb();
                    continue 'next_block;
                } else {
                    allocs.push(block);
                }
            }
            for alloc in allocs {
                alloc.dealloc();
            }
            bail!("Failed to allocate consecutive blocks");
        }
        for alloc in allocs {
            alloc.dealloc();
        }
        Ok(ConsecBlocks::new(blocks))
    }
}

pub struct ConsecAllocBuddyInfo {
    consec_checker: Box<dyn AllocChecker>,
}

impl ConsecAllocBuddyInfo {
    pub fn new(consec_checker: Box<dyn AllocChecker>) -> Self {
        ConsecAllocBuddyInfo { consec_checker }
    }
}

impl ConsecAllocator for ConsecAllocBuddyInfo {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(
        &mut self,
        size: usize,
        progress_cb: &dyn Fn(),
    ) -> anyhow::Result<ConsecBlocks> {
        let block_size = self.block_size();
        if size % block_size != 0 {
            bail!(
                "Size {} must be a multiple of block size {}",
                size,
                block_size
            );
        }
        let num_blocks = size / block_size;
        info!("Allocating {} blocks of size {}", num_blocks, block_size);
        let mut blocks = vec![];
        for _ in 0..num_blocks {
            let block =
                unsafe { MemBlock::buddyinfo_alloc(block_size, &mut *self.consec_checker)? };
            progress_cb();
            blocks.push(block);
        }
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        for block in &blocks {
            unsafe { std::ptr::write_bytes(block.ptr as *mut u8, 0, block.len) };
        }
        Ok(ConsecBlocks::new(blocks))
    }
}

#[derive(Clone, Copy, Debug)]
pub struct MemBlock {
    /// block pointer
    pub ptr: *mut u8,
    /// block length in bytes
    pub len: usize,
}

impl MemBlock {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        MemBlock { ptr, len }
    }
    pub fn dealloc(self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

impl MemBlock {
    unsafe fn buddyinfo_alloc(
        size: usize,
        consec_checker: &mut dyn AllocChecker,
    ) -> anyhow::Result<MemBlock> {
        if size > 4 * MB {
            return Err(anyhow::anyhow!(
                "Buddyinfo only supports consecutive allocations of up to 4MB."
            ));
        }
        /*
         * there's two things that might fail here:
         * (1) finding a suitable block10 candidate and
         * (2) verifying that the block is actually consecutive (using the MemBlock::check() function)
         */
        let block = retry!(|| {
            let block = MemBlock::find_block10_candidate()?;
            // munmap slice of MemBlock
            unsafe {
                libc::munmap(
                    (block.ptr as *mut u8).add(size) as *mut libc::c_void,
                    block.len - size,
                );
            }
            let block = MemBlock::new(block.ptr, size);
            match consec_checker.check(&block) {
                Ok(true) => Ok(block),
                Ok(false) => {
                    libc::munmap(block.ptr as *mut libc::c_void, block.len);
                    Err(anyhow::anyhow!("Block is not consecutive. Retrying..."))
                }
                Err(e) => {
                    error!("Memory check failed: {:?}", e);
                    libc::munmap(block.ptr as *mut libc::c_void, block.len);
                    Err(e)
                }
            }
        });
        Ok(block)
    }

    fn low_order_bytes(blocks: &[i64; 11], max_order: usize) -> usize {
        if max_order > 10 {
            panic!("Invalid order");
        }
        let mut bytes = 0;
        for i in 0..=max_order {
            bytes += blocks[i] as usize * (1 << i) * PAGE_SIZE;
        }
        bytes
    }

    fn is_block_candidate(diff: &[i64; 11], block_order: usize) -> bool {
        if block_order > 10 {
            panic!("Invalid block order")
        }
        if diff[block_order] != 1 {
            return false;
        }
        let low_order_sum = diff[..block_order]
            .iter()
            .enumerate()
            .filter(|(_, &n)| n > 0)
            .fold(0, |acc, (order, n)| acc + (1 << order) * n);
        let low_order_sum = usize::try_from(low_order_sum).unwrap() * PAGE_SIZE;
        debug!("low order: {}", low_order_sum);
        low_order_sum < 2usize.pow(block_order as u32) * PAGE_SIZE
    }

    unsafe fn find_block10_candidate() -> anyhow::Result<MemBlock> {
        //const HUGEBLOCK_SIZE: usize = 2048 * MB;
        //const ALLOC_SIZE: usize = 4 * MB;
        const MAX_ALLOCS: usize = 65000;
        log_pagetypeinfo();
        loop {
            let mut pages = vec![];
            let mut v1 = None;
            let mut diff: [i64; 11]; // = [0; 11];

            compact_mem()?;
            do_random_allocations();

            //trace!("will alloc hugeblock");
            //let hb = mmap_block(null_mut(), HUGEBLOCK_SIZE);
            //trace!("hugeblock allocated");

            for _ in 0..MAX_ALLOCS {
                log_pagetypeinfo();
                let locked_blocks = all_locked_blocks()?;
                info!("Locked blocks: {}", fmt_arr(locked_blocks));
                let blocks_before = get_normal_page_nums().expect("can't read buddyinfo");
                let free_blocks = diff_arrs(&blocks_before, &locked_blocks);
                info!("Free blocks:   {}", fmt_arr(free_blocks));
                let low_order_bytes = Self::low_order_bytes(&free_blocks, 9);
                info!("Allocating {} bytes", low_order_bytes);
                let v = mmap_block(std::ptr::null_mut(), low_order_bytes);
                pages.push(MemBlock::new(v as *mut u8, low_order_bytes));
                let blocks_before = get_normal_page_nums().expect("can't read buddyinfo");
                let v = mmap_block(std::ptr::null_mut(), 4 * MB);
                log_pagetypeinfo();
                let blocks_after = get_normal_page_nums()?;
                diff = diff_arrs(&blocks_before, &blocks_after);
                //debug!("  {:?}", blocks_before);
                //debug!("- {:?}", blocks_after);
                if diff[10] != 0 {
                    debug!("diff: {:?}", diff);
                }
                if MemBlock::is_block_candidate(&diff, 10) {
                    debug!("allocated block from order 10 block");
                    v1 = Some(v);
                    break;
                } else {
                    pages.push(MemBlock::new(v as *mut u8, 4 * MB));
                }
            }

            // cleanup
            //libc::munmap(hb, HUGEBLOCK_SIZE);
            for a in pages {
                a.dealloc();
            }

            // return
            match v1 {
                Some(v) => {
                    return Ok(MemBlock {
                        ptr: v as *mut u8,
                        len: 4 * MB,
                    })
                }
                None => {
                    debug!("No block10 candidate found. Retrying...");
                }
            };
        }
    }
}

impl MemBlock {
    #[cfg(feature = "spec_hammer")]
    unsafe fn alloc_consec_block(size: usize) -> anyhow::Result<MemBlock> {
        let locked_2mb_blocks = determine_locked_2mb_blocks()?;
        info!("Locked 2MB blocks: {}", locked_2mb_blocks);
        let mut available_2mb_blocks = usize::MAX;
        let mut allocations = [null_mut(); 50000];
        let mut i = 0;
        while available_2mb_blocks > locked_2mb_blocks {
            let buddy_before = get_normal_page_nums()?;
            let v = mmap_block(2 * MB);
            let buddy_after = get_normal_page_nums()?;
            let diff = diff_arrs(&buddy_before, &buddy_after);
            allocations[i] = v;
            i += 1;
            available_2mb_blocks = get_normal_page_nums()?[9];
            if available_2mb_blocks <= locked_2mb_blocks {
                log_pagetypeinfo();
                debug!("  {:?}", buddy_before);
                debug!("- {:?}", buddy_after);
                debug!("= {:?}", diff);
            }
        }
        debug!("hit thresh");
        let buddy_before = get_normal_page_nums()?;
        let v = mmap_block(2 * MB);
        let buddy_after = get_normal_page_nums()?;
        let diff = diff_arrs(&buddy_before, &buddy_after);
        info!("  {:?}", buddy_before);
        info!("- {:?}", buddy_after);
        info!("= {:?}", diff);
        for ptr in allocations {
            libc::munmap(ptr, 2 * MB);
        }
        Ok(v)
    }

    #[cfg(feature = "spoiler")]
    unsafe fn alloc_consec_block(size: usize) -> anyhow::Result<MemBlock> {
        use crate::{auto_spoiler, util::MB};

        const PAGE_COUNT: usize = 256 * 512;

        //let hugeblock_len = 1 << 30;
        //let v = mmap_block(null_mut(), hugeblock_len);

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
        let mut ret = None;
        while ret.is_none() {
            compact_mem()?;
            let x = unsafe { auto_spoiler(search_buffer) };
            if !x.is_null() {
                ret = Some(unsafe { &mut *x });
                continue;
            }
        }

        let ret = ret.unwrap();

        println!("{:?}", ret);

        let addr = memory_addresses(ret);

        //libc::munmap(v, hugeblock_len);

        Ok(MemBlock {
            ptr: addr as *mut libc::c_void,
            len: 8 * MB,
        })
    }
}

unsafe fn mmap_block(addr: *mut libc::c_void, len: usize) -> *mut libc::c_void {
    use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE};

    let v = libc::mmap(
        addr,
        len,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );
    assert_ne!(v as i64, -1, "mmap: {}", std::io::Error::last_os_error());
    libc::memset(v, 0x11, len);
    v
}

fn compact_mem() -> anyhow::Result<()> {
    Command::new("sh")
        .arg("-c")
        .arg("echo 1 | sudo tee /proc/sys/vm/compact_memory")
        .output()?;
    Command::new("sh")
        .arg("-c")
        .arg("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
        .output()?;
    Ok(())
}

unsafe fn do_random_allocations() {
    let mut rng = rand::thread_rng();
    for _ in 0..rng.gen_range(1000..10000) {
        let len = rng.gen_range(PAGE_SIZE..4 * MB);
        let v = unsafe { mmap_block(std::ptr::null_mut(), len) };
        unsafe {
            libc::munmap(v, len);
        }
    }
}

pub unsafe fn all_locked_blocks() -> anyhow::Result<[u64; 11]> {
    let mut locked: [u64; 11] = [0; 11];
    for i in (0..10).rev() {
        locked[i] = determine_locked_blocks(i)?;
    }
    locked[10] = 0;
    Ok(locked)
}

fn fmt_arr<I>(arr: [I; 11]) -> String
where
    I: std::fmt::Display,
{
    let mut table = String::new();
    for value in arr {
        table.push_str(&format!("{:>7}", value));
    }
    table
}

unsafe fn determine_locked_blocks(order: usize) -> anyhow::Result<u64> {
    let mut locked = u64::MAX;
    let alloc_size = (1 << order) * PAGE_SIZE;
    const MAX_ALLOCS: usize = 65000;
    const REPETITIONS: usize = 3;
    //info!("order {}", order);
    for _repetition in 0..REPETITIONS {
        let mut allocations = Vec::with_capacity(MAX_ALLOCS);
        const MAX_REPETITIONS: usize = 10;
        let mut split_allocations = 0;
        for i in 0..MAX_ALLOCS {
            //log_pagetypeinfo();
            let buddy_before = get_normal_page_nums()?;
            let v = mmap_block(std::ptr::null_mut(), alloc_size);
            allocations.push(v);
            let buddy_after = get_normal_page_nums()?;
            let diff = diff_arrs(&buddy_before, &buddy_after);
            locked = min(locked, buddy_before[order]);
            if diff[order] < 0 {
                // the last allocation increased the block count -> we encountered a split
                log_pagetypeinfo();
                split_allocations += 1;
                debug!("  {:?}", buddy_before);
                debug!("- {:?}", buddy_after);
                debug!("= {:?}", diff);
            }
            if split_allocations == MAX_REPETITIONS {
                //info!("split ({}, {})", locked, buddy_before[order]);
                debug!("Allocated {} blocks before hitting threshold", i);
                break;
            }
        }
        for v in allocations {
            libc::munmap(v, alloc_size);
        }
    }
    Ok(locked)
}

/// Read /proc/pagetypeinfo to string
fn read_pagetypeinfo() -> anyhow::Result<String> {
    let mut s = String::new();
    let mut f = std::fs::File::open("/proc/pagetypeinfo")?;
    f.read_to_string(&mut s)?;
    Ok(s)
}

/// Log /proc/pagetypeinfo to trace
fn log_pagetypeinfo() {
    match read_pagetypeinfo() {
        Ok(pti) => trace!("{}", pti),
        Err(_) => {}
    }
}

/// A small wrapper around buddyinfo() from lpfs, which is not convertible to anyhow::Result
fn buddyinfo() -> anyhow::Result<Vec<BuddyInfo>> {
    match lpfs::proc::buddyinfo::buddyinfo() {
        Ok(b) => Ok(b),
        Err(e) => bail!("{:?}", e),
    }
}

pub fn get_normal_page_nums() -> anyhow::Result<[u64; 11]> {
    let zones = buddyinfo()?;
    let zone = zones
        .iter()
        .find(|z| z.zone().eq("Normal"))
        .context("Zone 'Normal' not found")?;
    return Ok(zone.free_areas().clone());
}

pub fn diff_arrs<const S: usize>(l: &[u64; S], r: &[u64; S]) -> [i64; S] {
    let mut diffs: [i64; S] = [Default::default(); S];
    let mut i = 0;
    for (&l, &r) in l.iter().zip(r) {
        diffs[i] = l as i64 - r as i64;
        i += 1;
    }
    diffs
}
