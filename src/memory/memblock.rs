use std::{cell::RefCell, ffi::CString, io::Read, process::Command, ptr::null_mut};

use crate::{
    memory::{DRAMAddr, LinuxPageMap},
    retry,
    util::{MemConfiguration, MB, PAGE_SIZE, ROW_SIZE},
};
use anyhow::{bail, Context};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use libc::{MAP_ANONYMOUS, MAP_HUGETLB, MAP_HUGE_1GB, MAP_HUGE_2MB, MAP_POPULATE, MAP_SHARED};
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
        progress_cb: impl Fn(),
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

impl ConsecBlocks {
    pub fn pfn_align(
        self,
        mem_config: &MemConfiguration,
        conflict_threshold: u64,
        timer: &dyn MemoryTupleTimer,
    ) -> anyhow::Result<Self> {
        let mut blocks = vec![];
        for block in self.blocks {
            blocks.extend(block.pfn_align(mem_config, conflict_threshold, timer)?);
        }
        Ok(ConsecBlocks::new(blocks))
    }

    pub fn log_pfns(&self) {
        for block in &self.blocks {
            let pfns = block.consec_pfns();
            match pfns {
                Ok(pfns) => {
                    let pfns = pfns.format_pfns();
                    info!("PFNs: {}", pfns);
                }
                Err(e) => {
                    error!("Failed to get PFNs: {:?}", e);
                }
            }
        }
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
        progress_cb: impl Fn(),
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
        progress_cb: impl Fn(),
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
        progress_cb: impl Fn(),
    ) -> anyhow::Result<ConsecBlocks> {
        assert_eq!(size % self.block_size(), 0);
        let num_blocks = size / self.block_size();
        let mut blocks = Vec::with_capacity(num_blocks);
        const CANDIDATE_COUNT: usize = 1000; // 1000 * 4 MB = 4 GB
        const DUMMY_ALLOC_SIZE: usize = 4 * 1024 * MB;
        let buf = MemBlock::mmap(DUMMY_ALLOC_SIZE)?;
        while blocks.len() < num_blocks {
            let mut candidates = (0..CANDIDATE_COUNT)
                .map(|_| MemBlock::mmap(self.block_size()).context("mmap").unwrap())
                .collect_vec();
            candidates.shuffle(&mut rand::thread_rng());
            let mut found_consec = false;
            for candidate in candidates {
                if blocks.len() >= num_blocks {
                    candidate.dealloc();
                    continue;
                }
                let is_consec = self.consec_checker.check(&candidate)?;
                if is_consec {
                    blocks.push(candidate);
                    found_consec = true;
                    info!("Found consecutive block");
                    progress_cb();
                } else {
                    candidate.dealloc();
                }
            }
            if blocks.len() < num_blocks && !found_consec {
                warn!(
                    "Failed to find consecutive block in {} candidates. Retrying with new candidates...",
                    CANDIDATE_COUNT
                );
            }
        }
        buf.dealloc();
        assert_eq!(blocks.len(), num_blocks);
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
        progress_cb: impl Fn(),
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

struct Progress {
    offset: ProgressBar,
    pairs: ProgressBar,
}

impl Progress {
    pub fn from_multi(num_rows: u64, progress_bar: &MultiProgress) -> Self {
        let row_pairs_len = (num_rows * (num_rows - 1) / 2) as u64;
        let offset_progress = ProgressBar::new(num_rows).with_style(
            ProgressStyle::with_template(
                "Offset: [{elapsed_precise} ({eta:02} remaining)] {bar:40.cyan/blue} {pos:>7}/{len:7}",
            )
            .unwrap(),
        );
        let offset_progress = progress_bar.add(offset_progress);
        let pairs_progress = ProgressBar::new(row_pairs_len).with_style(
            ProgressStyle::with_template(
                "Pairs:  [{elapsed_precise} ({eta:02} remaining)] {bar:40.cyan/blue} {pos:>7}/{len:7}",
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
    /// Find the PFN-VA offset in rows.
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
        progress: Option<&MultiProgress>,
    ) -> Option<usize> {
        // reuse cached value if applicable
        let mut state = self.pfn_offset.borrow_mut();
        if let Some((offset, cfg, thresh)) = state.as_ref() {
            if offset.is_some() && cfg == mem_config && *thresh == conflict_threshold {
                info!("Reuse cached offset");
                return *offset;
            } else {
                info!("Resetting PFN offset state, parameter change detected");
                *state = None;
            }
        }
        drop(state);
        // find PFN offset
        let num_rows = self.len / ROW_SIZE;
        let max_rows = mem_config.bank_function_period() as usize / 2; // TODO: check if it is valid for all bank functions to divide by two here (I think it is)
        let num_rows = min(num_rows, max_rows);
        let row_pairs = (0..num_rows).combinations(2);
        let progress = progress.map(|p| Progress::from_multi(num_rows as u64, p));

        // do a quick pre-check. Toggling the uppermost bit in the bank function should result in a fast timing.
        if self.len >= num_rows * ROW_SIZE {
            let addr1 = self.ptr;
            let addr2 = self.byte_add(num_rows * ROW_SIZE).ptr;
            let time = unsafe { timer.time_subsequent_access_from_ram(addr1, addr2, 1000) };
            if time > conflict_threshold {
                info!("Pre-check failed. Block is not consecutive");
                return self.retain_state(None, mem_config, conflict_threshold);
            }
        } else {
            debug!("Skip pre-check, block is too small");
        }

        'next_offset: for row_offset in 0..num_rows {
            let addr_offset = (row_offset * ROW_SIZE) as isize;
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
                let offset1 = row_pair[0] * ROW_SIZE;
                let offset2 = row_pair[1] * ROW_SIZE;
                let addr1 = self.byte_add(offset1).ptr;
                let addr2 = self.byte_add(offset2).ptr;
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
                        offset1 / ROW_SIZE,
                        offset2 / ROW_SIZE,
                        time,
                        if same_bank { "<" } else { ">" },
                        conflict_threshold
                    );
                    debug!(
                        "rows: ({}, {}); addrs: (0x{:x}, 0x{:x}); DRAM: {:?}, {:?}",
                        offset1 / ROW_SIZE,
                        offset2 / ROW_SIZE,
                        addr1 as u64,
                        addr2 as u64,
                        dram1,
                        dram2
                    );
                    continue 'next_offset;
                }
            }
            return self.retain_state(Some(row_offset), mem_config, conflict_threshold);
        }
        self.retain_state(None, mem_config, conflict_threshold)
    }

    fn retain_state(
        &self,
        offset: Option<usize>,
        mem_config: &MemConfiguration,
        threshold: u64,
    ) -> Option<usize> {
        let mut state = self.pfn_offset.borrow_mut();
        *state = Some((offset, mem_config.clone(), threshold));
        offset
    }
}

type ConsecPfns = Vec<u64>;

impl MemBlock {
    pub fn consec_pfns(&self) -> anyhow::Result<ConsecPfns> {
        trace!("Get consecutive PFNs for vaddr 0x{:x}", self.ptr as u64);
        let mut phys_prev = self.pfn()?;
        let mut consecs = vec![phys_prev];
        for offset in (PAGE_SIZE..self.len).step_by(PAGE_SIZE) {
            let phys = self.byte_add(offset).pfn()?;
            if phys != phys_prev + PAGE_SIZE as u64 {
                consecs.push(phys_prev + PAGE_SIZE as u64);
                consecs.push(phys);
            }
            phys_prev = phys;
        }
        consecs.push(self.byte_add(self.len).pfn()?);
        trace!("PFN check done");
        Ok(consecs)
    }
}

pub trait FormatPfns {
    fn format_pfns(&self) -> String;
}

impl FormatPfns for ConsecPfns {
    fn format_pfns(&self) -> String {
        let mut pfns = String::from("");
        for (p1, p2) in self.windows(2).map(|w| (w[0], w[1])).step_by(2) {
            pfns += &format!("{:x}..[{} KB]..{:x} ", p1, (p2 - p1 as u64) / 1024, p2);
        }
        pfns
    }
}

impl MemBlock {
    pub fn pfn_align(
        mut self,
        mem_config: &MemConfiguration,
        threshold: u64,
        timer: &dyn MemoryTupleTimer,
    ) -> anyhow::Result<Vec<MemBlock>> {
        let mut blocks = vec![];
        let offset = self.pfn_offset(mem_config, threshold, timer, None);
        match offset {
            None => bail!("no offset"),
            Some(offset) => {
                let block = self.byte_add(offset * ROW_SIZE);
                blocks.push(block);
                self.len = offset * ROW_SIZE;
                blocks.push(self);
            }
        }
        Ok(blocks)
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
            let mut b1 = None;

            compact_mem()?;
            do_random_allocations();

            for _ in 0..MAX_ALLOCS {
                log_pagetypeinfo();
                let locked_blocks = all_locked_blocks()?;
                info!("Locked blocks: {}", fmt_arr(locked_blocks));
                let blocks_before = get_normal_page_nums().expect("can't read buddyinfo");
                let free_blocks = diff_arrs(&blocks_before, &locked_blocks);
                info!("Free blocks:   {}", fmt_arr(free_blocks));
                let low_order_bytes = Self::low_order_bytes(&free_blocks, 9);
                info!("Allocating {} bytes", low_order_bytes);
                let block = MemBlock::mmap(low_order_bytes)?;
                pages.push(block);
                let blocks_before = get_normal_page_nums().expect("can't read buddyinfo");
                let b = MemBlock::mmap(4 * MB)?;
                log_pagetypeinfo();
                let blocks_after = get_normal_page_nums()?;
                let diff = diff_arrs(&blocks_before, &blocks_after);
                //debug!("  {:?}", blocks_before);
                //debug!("- {:?}", blocks_after);
                if diff[10] != 0 {
                    debug!("diff: {:?}", diff);
                }
                if MemBlock::is_block_candidate(&diff, 10) {
                    debug!("allocated block from order 10 block");
                    b1 = Some(b);
                    break;
                } else {
                    pages.push(b);
                }
            }

            // cleanup
            for b in pages {
                b.dealloc();
            }

            // return
            match b1 {
                Some(b) => {
                    return Ok(b);
                }
                None => {
                    debug!("No block10 candidate found. Retrying...");
                }
            };
        }
    }
}

pub enum HugepageSize {
    TWO_MB,
    ONE_GB,
}

impl MemBlock {
    pub fn mmap(size: usize) -> anyhow::Result<Self> {
        let p = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }
        unsafe { libc::memset(p, 0x00, size) };
        Ok(MemBlock::new(p as *mut u8, size))
    }

    pub fn hugepage(size: HugepageSize) -> anyhow::Result<Self> {
        const ADDR: usize = 0x2000000000;
        let hp_size = match size {
            HugepageSize::TWO_MB => 2 * MB,
            HugepageSize::ONE_GB => 1024 * MB,
        };
        let hp_size_flag = match size {
            HugepageSize::TWO_MB => MAP_HUGE_2MB,
            HugepageSize::ONE_GB => MAP_HUGE_1GB,
        };
        let p = unsafe {
            libc::mmap(
                ADDR as *mut libc::c_void,
                hp_size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE | MAP_HUGETLB | hp_size_flag,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }
        Ok(MemBlock::new(p as *mut u8, hp_size))
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

pub fn compact_mem() -> anyhow::Result<()> {
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

#[cfg(test)]
mod tests {
    use crate::{
        memory::{
            construct_memory_tuple_timer, DRAMAddr, HugepageSize, MemBlock, MemoryTupleTimer,
            PfnResolver,
        },
        util::{BlacksmithConfig, MemConfiguration, MB, ROW_SHIFT, ROW_SIZE},
    };

    const CONFIG_FILE: &str = "config/bs-config.json";

    #[test]
    fn test_pfn_offset_mock_timer() -> anyhow::Result<()> {
        struct TestTimer<'a> {
            callback: &'a dyn Fn((*const u8, *const u8)) -> u64,
        }

        impl<'a> MemoryTupleTimer for TestTimer<'a> {
            unsafe fn time_subsequent_access_from_ram(
                &self,
                a: *const u8,
                b: *const u8,
                _rounds: usize,
            ) -> u64 {
                (self.callback)((a, b))
            }
        }

        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        const ADDR: *mut u8 = 0x200000000 as *mut u8;

        // it is not possible to determine the highest bank bit by only using one single memblock.
        let row_offsets = mem_config.bank_function_period() as usize / 2;
        for row_offset in 0..row_offsets {
            let base_addr = ADDR as usize + row_offset * ROW_SIZE;
            let timer = TestTimer {
                callback: &|(a, b)| {
                    let a = a as usize - ADDR as usize;
                    let a = base_addr + a;
                    let b = b as usize - ADDR as usize;
                    let b = base_addr + b;
                    let a = DRAMAddr::from_virt(a as *mut u8, &mem_config);
                    let b = DRAMAddr::from_virt(b as *mut u8, &mem_config);
                    if a.bank == b.bank {
                        config.threshold + 100
                    } else {
                        config.threshold - 100
                    }
                },
            };

            let block = MemBlock::new(ADDR, 4 * MB);
            let offset = block.pfn_offset(&mem_config, config.threshold, &timer, None);

            assert!(offset.is_some());
            assert_eq!(offset.unwrap(), row_offset);
        }

        Ok(())
    }

    #[test]
    fn test_pfn_offset_mmap() -> anyhow::Result<()> {
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let block = MemBlock::mmap(4 * MB)?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        assert!(pfn_offset.is_none());
        block.dealloc();
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_pfn_offset_hugepage() -> anyhow::Result<()> {
        env_logger::init();
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let block = MemBlock::hugepage(HugepageSize::ONE_GB)?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        println!("VA: 0x{:02x}", block.ptr as usize);
        println!("PFN: 0x{:02x}", block.pfn()?);
        assert_eq!(pfn_offset, Some(0));
        block.dealloc();
        Ok(())
    }

    #[test]
    fn test_virt_offset() -> anyhow::Result<()> {
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let bank_bits_mask = (mem_config.bank_function_period() as usize * ROW_SIZE - 1) as isize;
        //let row_offsets = (1 << (mem_config.max_bank_bit + 1 - ROW_SHIFT as u64)) as u64;
        //let mut rng = thread_rng();
        const NUM_TESTCASES: usize = 1_000_000;
        let mut test_cases: Vec<(usize, usize)> = Vec::with_capacity(NUM_TESTCASES);
        test_cases.push((0x79acade00000, 0x419df9000));
        test_cases.push((0x77c537a00000, 0x19bd000));
        test_cases.push((0x7ffef6f36000, 0x4a1a0000));
        test_cases.push((0x7ffef6a00000, 0x4c111000));
        test_cases.push((0x7ffeca600000, 0x2033000));
        /*
        for _ in 0..NUM_TESTCASES {
            let v: usize = rng.gen();
            let p: usize = rng.gen();
            test_cases.push((v, p));
        } */
        for (v, p) in test_cases {
            println!("VA,PA");
            println!("0x{:02x},0x{:02x}", v, p);
            let byte_offset = (p as isize & bank_bits_mask) - (v as isize & bank_bits_mask);
            let byte_offset = byte_offset.rem_euclid(4 * MB as isize) as usize;
            println!("Byte offset 0x{:02x}", byte_offset);
            println!("Row offset: {}", byte_offset >> ROW_SHIFT);
            let dramv =
                DRAMAddr::from_virt_offset(v as *const u8, byte_offset as isize, &mem_config);
            let dramp = DRAMAddr::from_virt(p as *const u8, &mem_config);
            println!("{:?}", dramv);
            println!("{:?}", dramp);
            assert_eq!(dramv.bank, dramp.bank);
        }
        Ok(())
    }

    #[test]
    fn test_virt_zero_gap() -> anyhow::Result<()> {
        const MASK: usize = 0x3FFFFF;
        let (v, p) = (0x79acade00000, 0x419df9000);
        let offset = (p & MASK) as isize - (v & MASK) as isize;
        let offset = offset.rem_euclid(4 * MB as isize);
        println!("{}", offset);
        panic!("fail");
        Ok(())
    }
}
