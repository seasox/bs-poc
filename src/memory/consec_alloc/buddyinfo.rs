use std::{cmp::min, io::Read};

use anyhow::{bail, Context};
use lpfs::proc::buddyinfo::BuddyInfo;
use rand::Rng;

use crate::{
    memory::{
        util::{compact_mem, mmap},
        AllocChecker, ConsecBlocks, ConsecCheck, MemBlock,
    },
    retry,
    util::{MB, PAGE_SIZE},
};

use super::ConsecAllocator;

pub struct ConsecAllocBuddyInfo {
    consec_checker: ConsecCheck,
}

impl ConsecAllocBuddyInfo {
    pub fn new(consec_checker: ConsecCheck) -> Self {
        ConsecAllocBuddyInfo { consec_checker }
    }
}

impl ConsecAllocator for ConsecAllocBuddyInfo {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
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
            let block = unsafe { MemBlock::buddyinfo_alloc(block_size, &self.consec_checker)? };
            info!("TODO implement progress bar");
            blocks.push(block);
        }
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        for block in &blocks {
            unsafe { std::ptr::write_bytes(block.ptr as *mut u8, 0, block.len) };
        }
        Ok(ConsecBlocks::new(blocks))
    }
}

unsafe fn all_locked_blocks() -> anyhow::Result<[u64; 11]> {
    let mut locked: [u64; 11] = [0; 11];
    for i in (0..10).rev() {
        locked[i] = determine_locked_blocks(i)?;
    }
    locked[10] = 0;
    Ok(locked)
}

unsafe fn do_random_allocations() {
    let mut rng = rand::thread_rng();
    for _ in 0..rng.gen_range(1000..10000) {
        let len = rng.gen_range(PAGE_SIZE..4 * MB);
        let v = mmap(std::ptr::null_mut(), len);
        unsafe {
            libc::munmap(v, len);
        }
    }
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

fn get_normal_page_nums() -> anyhow::Result<[u64; 11]> {
    let zones = buddyinfo()?;
    let zone = zones
        .iter()
        .find(|z| z.zone().eq("Normal"))
        .context("Zone 'Normal' not found")?;
    return Ok(zone.free_areas().clone());
}

fn diff_arrs<const S: usize>(l: &[u64; S], r: &[u64; S]) -> [i64; S] {
    let mut diffs: [i64; S] = [Default::default(); S];
    let mut i = 0;
    for (&l, &r) in l.iter().zip(r) {
        diffs[i] = l as i64 - r as i64;
        i += 1;
    }
    diffs
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
            let v = mmap(std::ptr::null_mut(), alloc_size);
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

impl MemBlock {
    unsafe fn buddyinfo_alloc(
        size: usize,
        consec_checker: &dyn AllocChecker,
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
