use std::{io::Read, process::Command, time::Duration};

#[cfg(feature = "spoiler")]
use crate::memory_addresses;

use anyhow::bail;
use proc_getter::buddyinfo::{buddyinfo, BuddyInfo};
use rand::Rng;

use crate::util::{KNOWN_BITS, MB, PAGE_SIZE};

use super::VictimMemory;

pub trait ConsecAlloc: Sized {
    unsafe fn alloc_consec_block(size: usize) -> anyhow::Result<Self>;
    unsafe fn check(&self) -> anyhow::Result<bool>;
}

pub struct BlockMemory {
    pub blocks: Vec<MemBlock>,
}

impl BlockMemory {
    pub fn new(len: usize) -> anyhow::Result<Self> {
        let block_size = 1 << KNOWN_BITS;
        if len % block_size != 0 {
            bail!(
                "Size {} must be a multiple of block size {}",
                len,
                block_size
            );
        }
        let num_blocks = len / block_size;
        info!("Allocating {} blocks of size {}", num_blocks, block_size);
        let blocks = (0..len / block_size)
            .map(|_| unsafe { MemBlock::alloc_consec_block(block_size) })
            .collect::<anyhow::Result<Vec<_>>>()?;
        // makes sure that (1) memory is initialized and (2) page map for buffer is present (for virt_to_phys)
        for block in &blocks {
            unsafe { std::ptr::write_bytes(block.ptr as *mut u8, 0, block.len) };
        }
        Ok(BlockMemory { blocks })
    }
}

impl VictimMemory for BlockMemory {
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

pub struct MemBlock {
    /// block pointer
    pub ptr: *mut u8,
    /// block length in bytes
    pub len: usize,
}

impl ConsecAlloc for MemBlock {
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

    #[cfg(feature = "buddyinfo")]
    unsafe fn alloc_consec_block(size: usize) -> anyhow::Result<MemBlock> {
        use std::ptr::null_mut;

        if size > 4 * MB {
            return Err(anyhow::anyhow!(
                "Buddyinfo only supports consecutive allocations of up to 4MB."
            ));
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
            info!("low order: {}", low_order_sum);
            low_order_sum < 2usize.pow(block_order as u32) * PAGE_SIZE
        }

        unsafe fn find_block10_candidate() -> anyhow::Result<MemBlock> {
            const HUGEBLOCK_SIZE: usize = 2048 * MB;
            const ALLOC_SIZE: usize = 4 * MB;
            const MAX_ALLOCS: usize = 2000;
            log_pagetypeinfo();
            loop {
                let mut pages = [null_mut(); MAX_ALLOCS];
                let mut v1 = None;
                let mut diff: [i64; 11]; // = [0; 11];

                compact_mem()?;
                do_random_allocations();

                trace!("will alloc hugeblock");
                let hb = mmap_block(null_mut(), HUGEBLOCK_SIZE);
                trace!("hugeblock allocated");

                for i in 0..MAX_ALLOCS {
                    log_pagetypeinfo();
                    let blocks_before = get_normal_page_nums().expect("can't read buddyinfo");
                    let v = mmap_block(null_mut(), ALLOC_SIZE);
                    log_pagetypeinfo();
                    let blocks_after = get_normal_page_nums()?;
                    diff = diff_arrs(&blocks_before, &blocks_after);
                    //debug!("  {:?}", blocks_before);
                    //debug!("- {:?}", blocks_after);
                    if diff[10] != 0 {
                        debug!("diff: {:?}", diff);
                    }
                    if is_block_candidate(&diff, 10) {
                        debug!("allocated block from order 10 block");
                        v1 = Some(v);
                        break;
                    } else {
                        pages[i] = v;
                    }
                }

                // cleanup
                libc::munmap(hb, HUGEBLOCK_SIZE);
                for p in pages {
                    if p.is_null() {
                        continue;
                    }
                    libc::munmap(p, ALLOC_SIZE);
                }

                // return
                match v1 {
                    Some(v) => {
                        return Ok(MemBlock {
                            ptr: v as *mut u8,
                            len: ALLOC_SIZE,
                        })
                    }
                    None => {
                        debug!("No block10 candidate found. Retrying...");
                    }
                };
            }
        }

        /*
         * there's two things that might fail here:
         * (1) finding a suitable block10 candidate and
         * (2) verifying that the block is actually consecutive (using the MemBlock::check() function)
         */
        let block = retry(|| {
            let block = find_block10_candidate()?;
            match block.check() {
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

    #[cfg(feature = "consec_check_pfn")]
    unsafe fn check(&self) -> anyhow::Result<bool> {
        /*
         * Check whether the allocation is actually consecutive. The current implementation simply
         * checks for consecutive PFNs using the virt-to-phys pagemap. This needs root permissions.
         * Therefore, this check should be replaced with a timing side channel to verify the address function
         * in the memory block. If the measured timings correspond to the address function, it is very likely that
         * this indeed is a consecutive memory block.
         */

        use crate::memory::{LinuxPageMap, VirtToPhysResolver};
        let mut resolver = LinuxPageMap::new()?;
        if (self.ptr as u64) & 0xFFF != 0 {
            bail!("Address is not page-aligned: 0x{:x}", self.ptr as u64);
        }
        trace!("Get consecutive PFNs for vaddr 0x{:x}", self.ptr as u64);
        let mut phys_prev = resolver.get_phys(self.ptr as u64)?;
        let mut consecs = vec![phys_prev];
        for offset in (PAGE_SIZE..self.len).step_by(PAGE_SIZE) {
            let virt = (self.ptr as *const u8).add(offset);
            let phys = resolver.get_phys(virt as u64)?;
            if phys != phys_prev + PAGE_SIZE as u64 {
                consecs.push(phys_prev + PAGE_SIZE as u64);
                consecs.push(phys);
            }
            phys_prev = phys;
        }
        consecs.push(phys_prev + PAGE_SIZE as u64);
        trace!("PFN check done");
        let first_block_bytes = (consecs[1] - consecs[0]) as usize;
        info!(
            "Allocated a consecutive {} KB block at [{:#02x}, {:#02x}]",
            first_block_bytes / 1024,
            self.ptr as u64,
            self.ptr.add(first_block_bytes) as u64,
        );
        info!("PFNs {:?}", consecs);
        Ok(first_block_bytes >= self.len)
    }

    #[cfg(feature = "no_consec_check")]
    unsafe fn check(&self) -> anyhow::Result<bool> {
        Ok(true)
    }
}

#[cfg(feature = "buddyinfo")]
unsafe fn mmap_block(addr: *mut libc::c_void, len: usize) -> *mut libc::c_void {
    use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

    let v = libc::mmap(
        addr,
        len,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
        -1,
        0,
    );
    assert_ne!(v as i64, -1, "mmap: {}", std::io::Error::last_os_error());
    libc::memset(v, 0x11, len);
    v
}

fn compact_mem() -> anyhow::Result<()> {
    let _output = Command::new("/usr/bin/sudo")
        .arg("-S")
        .arg("sh")
        .arg("-c")
        .arg("echo 1 >> /proc/sys/vm/compact_memory")
        .output()?;
    let _output = Command::new("sh")
        .arg("-c")
        .arg("echo 0 | sudo tee /proc/sys/kernel/randomize_va_space")
        .output()?;
    info!("Waiting 3 seconds for memory compaction...");
    std::thread::sleep(Duration::from_secs(3));
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

#[cfg(feature = "spec_hammer")]
unsafe fn determine_locked_2mb_blocks() -> anyhow::Result<usize> {
    let mut locked = usize::MAX;
    for _repetition in 0..10 {
        let mut allocations = [null_mut(); 50000];
        const MAX_REPETITIONS: usize = 10;
        let mut split_allocations = 0;
        for i in 0..50000 {
            //log_pagetypeinfo();
            let buddy_before = get_normal_page_nums()?;
            let v = mmap_block(2 * MB);
            allocations[i] = v;
            let buddy_after = get_normal_page_nums()?;
            let diff = diff_arrs(&buddy_before, &buddy_after);
            locked = min(locked, buddy_before[9]);
            if diff[9] < 0 {
                // the last allocation increased the block count -> we encountered a split
                log_pagetypeinfo();
                split_allocations += 1;
                debug!("  {:?}", buddy_before);
                debug!("- {:?}", buddy_after);
                debug!("= {:?}", diff);
            }
            if split_allocations == MAX_REPETITIONS {
                debug!("Allocated {} blocks before hitting threshold", i);
                break;
            }
        }
        for v in allocations {
            libc::munmap(v, 2 * MB);
        }
    }
    Ok(locked)
}

impl Drop for MemBlock {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
    }
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

/// A small wrapper around buddyinfo() from proc_getter, which is not convertible to anyhow::Result
fn get_buddyinfo() -> anyhow::Result<Vec<BuddyInfo>> {
    match buddyinfo() {
        Ok(b) => Ok(b),
        Err(e) => bail!("{:?}", e),
    }
}

fn get_normal_page_nums() -> anyhow::Result<[usize; 11]> {
    let zones = get_buddyinfo()?;
    /*
    let mut free_space = 0;
    let zone = zones
        .iter()
        .find(|z| z.zone().eq("Normal"))
        .context("Zone 'Normal' not found")?;
    return Ok(zone.page_nums().clone());*/
    fn add_acc(mut l: [usize; 11], r: &[usize; 11]) -> [usize; 11] {
        for i in 0..11 {
            l[i] += r[i];
        }
        l
    }
    let pages = zones.iter().fold([0; 11], |mut acc, next| {
        acc = add_acc(acc, next.page_nums());
        acc
    });
    Ok(pages)
}

fn diff_arrs<const S: usize>(l: &[usize; S], r: &[usize; S]) -> [i64; S] {
    let mut diffs = [0_i64; S];
    let mut i = 0;
    for (&l, &r) in l.iter().zip(r) {
        diffs[i] = l as i64 - r as i64;
        i += 1;
    }
    diffs
}

fn retry<F, T>(mut f: F) -> T
where
    F: FnMut() -> anyhow::Result<T>,
{
    loop {
        match f() {
            Ok(x) => return x,
            Err(e) => {
                error!("{:?}", e);
            }
        }
    }
}
