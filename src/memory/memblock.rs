use std::{cell::RefCell, ffi::CString, io::Read, process::Command, ptr::null_mut};

use crate::{
    memory::{DRAMAddr, LinuxPageMap},
    retry,
    util::{MemConfiguration, MB, PAGE_SIZE, ROW_SIZE},
};
use anyhow::{bail, Context};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use lpfs::proc::buddyinfo::BuddyInfo;
use rand::prelude::SliceRandom;
use rand::Rng;
use std::cmp::min;

use super::{AllocChecker, MemoryTupleTimer, VictimMemory, VirtToPhysResolver};

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

#[derive(Clone, Debug)]
pub struct MemBlock {
    /// block pointer
    pub ptr: *mut u8,
    /// block length in bytes
    pub len: usize,
    pfn_offset: RefCell<Option<(Option<usize>, MemConfiguration, u64)>>,
}

impl MemBlock {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        MemBlock {
            ptr,
            len,
            pfn_offset: RefCell::new(None),
        }
    }
    pub fn dealloc(self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

impl MemBlock {
    pub fn byte_add(&self, offset: usize) -> Self {
        assert!(offset < self.len, "{} >= {}", offset, self.len);
        MemBlock {
            ptr: unsafe { self.ptr.byte_add(offset) },
            len: self.len - offset,
            pfn_offset: self.pfn_offset.clone(),
        }
    }
}

pub struct Progress {
    offset: ProgressBar,
    pairs: ProgressBar,
}

impl Progress {
    pub fn from_multi(row_offsets: u64, num_rows: usize, progress_bar: MultiProgress) -> Self {
        let row_pairs_len = (num_rows * (num_rows - 1) / 2) as u64;
        let offset_progress = ProgressBar::new(row_offsets).with_style(
            ProgressStyle::with_template(
                "Offset: [{elapsed_precise} ({eta} remaining)] {bar:40.cyan/blue} {pos:>7}/{len:7}",
            )
            .unwrap(),
        );
        let offset_progress = progress_bar.add(offset_progress);
        let pairs_progress = ProgressBar::new(row_pairs_len).with_style(
            ProgressStyle::with_template(
                "Pairs: [{elapsed_precise} ({eta} remaining)] {bar:40.cyan/blue} {pos:>7}/{len:7}",
            )
            .unwrap(),
        );
        let pairs_progress = progress_bar.add(pairs_progress);
        Progress {
            offset: offset_progress,
            pairs: pairs_progress,
        }
    }
}

impl MemBlock {
    /// Find the PFN-VA offset
    ///
    /// This is brute force, simply trying all row offsets from 0..row_offsets (determined using mem_config)
    /// There probably is a more sophisticated way to implement this, e.g., by examing the bank orders and
    /// filtering for possible "bank periods" after each iteration, but this here should be fast enough for now.
    /// WARNING: This function initializes pfn_offset with the provided mem_config. Calling #pfn_offset(...) with
    ///          different arguments afterwards WILL NOT reset the OnceCell, potentially causing unintended behavior.
    pub fn pfn_offset(
        &self,
        mem_config: &MemConfiguration,
        conflict_threshold: u64,
        timer: &dyn MemoryTupleTimer,
        progress: Option<Progress>,
    ) -> Option<usize> {
        // reuse cached value if applicable
        let mut state = self.pfn_offset.borrow_mut();
        if let Some((offset, cfg, thresh)) = state.as_ref() {
            if cfg == mem_config && *thresh == conflict_threshold {
                return *offset;
            } else {
                *state = None;
            }
        }
        // find PFN offset
        let num_rows = self.len / ROW_SIZE;
        let row_offsets = (1 << mem_config.max_bank_bit) / ROW_SIZE; // the number of rows to iterate before overflowing the bank function
        let row_pairs = (0..num_rows).combinations(2);
        'next_offset: for row_offset in 0..row_offsets {
            let addr_offset = (row_offset as usize * ROW_SIZE) as isize;
            debug!(
                "Checking row offset {} (effective offset: 0x{:x})",
                row_offset, addr_offset
            );
            // update progress
            if let Some(progress) = &progress {
                progress.offset.inc(1);
                progress.pairs.reset();
            }
            // iterate over row pairs
            for row_pair in row_pairs.clone() {
                if let Some(progress) = &progress {
                    progress.pairs.inc(1);
                }
                let row1 = row_pair[0];
                let row2 = row_pair[1];
                let addr1 = unsafe {
                    (self.ptr as *mut u8)
                        .byte_add(((row_offset as usize + row1) * ROW_SIZE) % self.len)
                };
                let addr2 = unsafe {
                    (self.ptr as *mut u8)
                        .byte_add(((row_offset as usize + row2) * ROW_SIZE) % self.len)
                };
                let dram1 = DRAMAddr::from_virt_offset(addr1, addr_offset, &mem_config);
                let dram2 = DRAMAddr::from_virt_offset(addr2, addr_offset, &mem_config);
                let same_bank = dram1.bank == dram2.bank;
                let time = unsafe { timer.time_subsequent_access_from_ram(addr1, addr2, 1000) };
                if (same_bank && time < conflict_threshold)
                    || (!same_bank && time > conflict_threshold)
                {
                    debug!(
                        "Expected {} banks for ({:?}, {:?}), but timed {} {} {}",
                        if same_bank { "same" } else { "differing" },
                        row1,
                        row2,
                        time,
                        if same_bank { "<" } else { ">" },
                        conflict_threshold
                    );
                    debug!(
                        "rows: ({}, {}); addrs: (0x{:x}, 0x{:x}); DRAM: {:?}, {:?}",
                        row1, row2, addr1 as u64, addr2 as u64, dram1, dram2
                    );
                    continue 'next_offset;
                }
            }
            *state = Some((Some(row_offset), mem_config.clone(), conflict_threshold));
            return Some(row_offset);
        }
        None
    }
}

pub trait PfnResolver {
    fn pfn(&self) -> anyhow::Result<u64>;
}

impl PfnResolver for MemBlock {
    fn pfn(&self) -> anyhow::Result<u64> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(self.ptr as u64)
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
                    return Ok(MemBlock::new(v as *mut u8, 4 * MB));
                }
                None => {
                    debug!("No block10 candidate found. Retrying...");
                }
            };
        }
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
