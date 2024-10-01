use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::{construct_memory_tuple_timer, BytePointer, DRAMAddr, FormatPfns, PfnResolver};
use std::fs::OpenOptions;
use std::io::Write;
use std::ops::{Deref, Range};
use std::ptr::null_mut;

use anyhow::bail;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;

use super::ConsecAllocator;
use crate::allocator::util::{mmap, munmap};
use crate::retry;
use crate::util::{NamedProgress, MB};
use crate::{
    memory::{ConsecBlocks, MemBlock},
    util::PAGE_SIZE,
};

pub struct Spoiler {
    mem_config: MemConfiguration,
    conflict_threshold: u64,
    progress: Option<MultiProgress>,
}

impl Spoiler {
    pub fn new(
        mem_config: MemConfiguration,
        conflict_threshold: u64,
        progress: Option<MultiProgress>,
    ) -> Self {
        Self {
            mem_config,
            conflict_threshold,
            progress,
        }
    }
}

impl ConsecAllocator for Spoiler {
    fn block_size(&self) -> usize {
        4 * MB
    }

    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        //let hugeblock_len = 1 << 30;
        //let v = mmap_block(null_mut(), hugeblock_len);

        let mut blocks: Vec<MemBlock> = vec![];
        const BLOCK_SIZE: usize = 4 * MB;
        let required_blocks = size.div_ceil(BLOCK_SIZE);
        let timer = construct_memory_tuple_timer()?;
        let p = self.progress.as_ref().map(|p| {
            p.add(
                ProgressBar::new(required_blocks as u64)
                    .with_style(ProgressStyle::named_bar("Allocating blocks")),
            )
        });
        if let Some(p) = &p {
            p.set_position(0);
        }
        while blocks.len() < required_blocks {
            let round_blocks = retry!(|| self.spoiler_round());
            info!("Current blocks: {:?}", blocks);
            info!(
                "Banks: {:?}",
                blocks
                    .iter()
                    .map(|b| DRAMAddr::from_virt(b.pfn().unwrap() as *const u8, &self.mem_config))
                    .collect_vec()
            );
            for block in round_blocks {
                if blocks.len() >= required_blocks {
                    break;
                }
                // check for same bank
                if let Some(last_block) = blocks.last() {
                    let timing = unsafe {
                        timer.time_subsequent_access_from_ram(block.ptr(), last_block.ptr(), 10000)
                    };
                    let same_bank = timing >= self.conflict_threshold;
                    if !same_bank {
                        warn!(
                            "Bank check failed: {} < {} for blocks {:?} and {:?}",
                            timing, self.conflict_threshold, block, last_block
                        );
                        continue;
                    }
                }
                // PFN based check to confirm timings (for debugging, skipped if PageMap ist not available)
                let pfn = block.pfn();
                let last_pfn = blocks.last().map(|b| b.pfn()).transpose();
                if let (Ok(pfn), Ok(Some(last_pfn))) = (&pfn, &last_pfn) {
                    let bank = DRAMAddr::from_virt(*pfn as *const u8, &self.mem_config).bank;
                    if bank != 0 {
                        info!("Not bank 0: {}", bank);
                        //continue;
                    }
                    let last_bank =
                        DRAMAddr::from_virt(*last_pfn as *const u8, &self.mem_config).bank;
                    assert_eq!(bank, last_bank);
                } else {
                    warn!("Skipped PFN check: {:?} {:?}", pfn, last_pfn);
                }
                info!(
                    "Adding block (phys) {:?}:\n{}",
                    DRAMAddr::from_virt(block.pfn()? as *const u8, &self.mem_config),
                    block.consec_pfns()?.format_pfns()
                );
                if let Some(p) = &p {
                    p.inc(1);
                }
                blocks.push(block);
            }
        }
        if let Some(p) = &p {
            p.finish();
        }
        Ok(ConsecBlocks { blocks })
    }
}

struct CArray<T> {
    data: *const T,
    len: usize,
}

impl<T> CArray<T> {
    fn new(data: *const T, len: usize) -> Self {
        assert!(!data.is_null());
        assert_ne!(len, 0);
        Self { data, len }
    }
}

impl<T> Deref for CArray<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }
}

fn _spoiler(requested_size: usize) -> anyhow::Result<ConsecBlocks> {
    let block_size = 8 * MB;
    let rounds = requested_size.div_ceil(block_size);
    for _ in 0..rounds {
        const BUF_SIZE: usize = 512; // buf size in MB
        const PAGE_COUNT: usize = 256 * BUF_SIZE; // 256 pages per MB
        let buf: *mut u8 = mmap(null_mut(), 512 * MB);
        assert!(!buf.is_null());
        // sieve candidates for consecutive memory
        let mut candidates = spoiler_candidates(buf, BUF_SIZE * MB, 0);
        for read_page_offset in 1..PAGE_COUNT {
            if candidates.is_empty() {
                bail!("No candidates found");
            }
            let new_candidates = spoiler_candidates(buf, BUF_SIZE * MB, read_page_offset);
            candidates.retain(|candidate| new_candidates.contains(candidate));
        }
    }
    todo!()
}

impl Spoiler {
    /// Perform a spoiler round to find consecutive memory blocks.
    fn spoiler_round(&self) -> anyhow::Result<Vec<MemBlock>> {
        const PAGE_COUNT: usize = 256 * 512;
        let search_buffer_size = PAGE_COUNT * PAGE_SIZE;
        let search_buffer = mmap(null_mut(), search_buffer_size);
        let spoiler_candidates = spoiler_candidates(search_buffer, search_buffer_size, 0);
        if spoiler_candidates.is_empty() {
            unsafe { munmap(search_buffer, search_buffer_size) };
            bail!("No candidates found");
        }
        info!("Found {} candidates", spoiler_candidates.len());
        debug!("{:?}", spoiler_candidates);

        let addrs = spoiler_candidates
            .iter()
            .flat_map(|range| {
                range
                    .clone()
                    .map(|i| unsafe { search_buffer.byte_add(i * PAGE_SIZE) })
            })
            .collect::<Vec<_>>();

        let to_munmap = (0..512 * MB)
            .step_by(PAGE_SIZE)
            .map(|i| unsafe { search_buffer.byte_add(i) })
            .filter(|ptr| !addrs.contains(ptr))
            .collect_vec();

        for ptr in to_munmap {
            unsafe { munmap(ptr, PAGE_SIZE) };
        }
        let mut blocks = vec![];
        let mut prev_end = 0;
        for candidate in spoiler_candidates {
            if candidate.start < prev_end {
                debug!("Skipping candidate {:?}: overlaps with previous", candidate);
                continue;
            }
            let addr = unsafe { search_buffer.byte_add(candidate.start * PAGE_SIZE) };
            let offset = 0x100000 - (addr.pfn()? as usize & 0xFFFFF);
            let addr = unsafe { addr.byte_add(offset) };
            if addr.pfn().unwrap() & 0xFFFFF != 0 {
                error!(
                    "Not aligned to 1 MB boundary: {:?}, offset {}",
                    addr.pfn().unwrap(),
                    offset
                );
            }
            assert_eq!(candidate.end - candidate.start, 8 * MB / PAGE_SIZE);
            let block = MemBlock::new(addr, self.block_size());
            let consecs = block.consec_pfns()?;
            if consecs[1] - consecs[0] != 4 * MB as u64 {
                warn!("Not a 4 MB block: {}", consecs.format_pfns());
                continue;
            }
            info!("Found 4 MB block: {}", consecs.format_pfns());
            blocks.push(block);
            prev_end = candidate.end;
        }
        // munmap remaining pages
        blocks.sort_by_key(|b| b.ptr() as usize);
        let mut base = search_buffer;
        let search_buf_end = unsafe { search_buffer.byte_add(search_buffer_size - 1) };
        for block in &blocks {
            if base >= search_buf_end {
                break;
            }
            let start = block.ptr() as usize;
            let end = block.addr(block.len() - 1);
            let unused_size = start - base as usize;
            unsafe { libc::munmap(base as *mut libc::c_void, unused_size) };
            base = unsafe { end.byte_add(1) };
        }
        Ok(blocks)
    }
}

const MEASURE_LOG: &str = "log/measurements.csv";
const DIFF_LOG: &str = "log/diffs.csv";

/// Find candidates for consecutive memory blocks for a given read offset.
///
/// This returns a Range for start an end index for each candidate.
fn spoiler_candidates(buf: *mut u8, buf_size: usize, read_page_offset: usize) -> Vec<Range<usize>> {
    assert!(!buf.is_null(), "null buffer");
    assert!(buf_size > 0, "zero-sized buffer");
    assert!(buf_size % MB == 0, "buffer size must be a multiple of MB");

    assert_eq!(
        buf_size,
        512 * MB,
        "Only 512 MB supported, other sizes TODO."
    );
    const THRESH_LOW: u64 = 400;
    const THRESH_HIGH: u64 = 800;

    const PAGES_PER_MB: usize = MB / PAGE_SIZE;

    let page_count = 256 * buf_size / MB; // 256 pages per MB

    // measure the buffer using the spoiler primitive
    let measurements =
        unsafe { crate::spoiler_measure(buf, buf.byte_add(read_page_offset * PAGE_SIZE)) };
    let meas_buf = unsafe { CArray::new(crate::measurements(measurements), page_count) };
    let meas_buf = Vec::from(&meas_buf as &[u64]);
    // write measurements to MEASURE_LOG file
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(MEASURE_LOG)
        .unwrap();
    for (idx, measurement) in meas_buf.iter().enumerate() {
        writeln!(file, "{},{},{}", read_page_offset, idx, measurement).unwrap();
    }
    drop(file);
    let diff_buf = unsafe { CArray::new(crate::diffs(measurements), page_count) };
    let diff_buf = Vec::from(&diff_buf as &[u64]);
    // write diffs to DIFF_LOG file
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(DIFF_LOG)
        .unwrap();
    for (idx, diff) in diff_buf.iter().enumerate() {
        writeln!(file, "{},{},{}", read_page_offset, idx, diff).unwrap();
    }
    drop(file);
    // find peaks in diff_buf. Peaks are read accesses to pages stalled caused by read-after-write pipeline conflicts.
    let peaks = diff_buf.peaks_indices(THRESH_LOW..THRESH_HIGH);
    let peak_distances = peaks
        .iter()
        .tuple_windows()
        .enumerate()
        .map(|(idx, (a, b))| (idx, b - a))
        .collect_vec();
    debug!("peak_distances: {:?}", peak_distances);
    // find `cont_window_size` distances 256 pages apart
    unsafe { libc::free(measurements as *mut libc::c_void) };
    let cont_window_size = 8; // cont window size in MB
    peak_distances
        // slide over peaks in windows of size `cont_window_size`
        .windows(cont_window_size)
        // keep only windows where all peaks are 1 MB apart
        .filter(|window| window.iter().all(|(_, dist)| *dist == PAGES_PER_MB))
        // convert window to start and end index
        .map(|window| peaks[window[0].0]..peaks[window[cont_window_size - 1].0 + 1])
        .collect_vec()
}

trait PeakIndices<T> {
    fn peaks_indices(&self, peak_range: Range<T>) -> Vec<usize>;
}

impl<T> PeakIndices<T> for Vec<T>
where
    T: PartialOrd,
{
    fn peaks_indices(&self, peak_range: Range<T>) -> Vec<usize> {
        let mut peaks = vec![];
        for (idx, x) in self.iter().enumerate() {
            if peak_range.contains(x) {
                peaks.push(idx);
            }
        }
        peaks
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::remove_file, ptr::null_mut};

    use crate::{
        allocator::{
            compact_mem,
            spoiler::{spoiler_candidates, DIFF_LOG, MEASURE_LOG},
            util::{mmap, munmap},
        },
        memory::{FormatPfns, MemBlock},
        util::{MB, PAGE_SIZE},
    };

    #[test]
    #[ignore = "spoiler test needs root permissions. This test is mainly a playground for the spoiler strategy."]
    fn test_spoiler() {
        compact_mem().unwrap();

        let b: *mut u8 = mmap(null_mut(), 2048 * MB); // dummy buffer to collect small page blocks
        const BUF_SIZE: usize = 512 * MB; // buf size in MB
        let buf: *mut u8 = mmap(null_mut(), BUF_SIZE);
        let block = MemBlock::new(buf, BUF_SIZE);
        let pfns = block.consec_pfns().unwrap().format_pfns();
        println!("PFN ranges: {}", pfns);
        assert_ne!(buf, null_mut());
        remove_file(MEASURE_LOG).ok();
        remove_file(DIFF_LOG).ok();
        for offset in 0..256 * 8 {
            let spoiler_candidates = spoiler_candidates(buf, BUF_SIZE, offset);
            println!(
                "Found {} spoiler_candidates: {:?}",
                spoiler_candidates.len(),
                spoiler_candidates
            );
            //let mut offset = None;
            for candidate in spoiler_candidates {
                let (start, end) = (candidate.start, candidate.end);
                assert!(start < end);
                assert_eq!(end - start, 8 * MB / PAGE_SIZE);
                let start = unsafe { buf.byte_add(start * PAGE_SIZE) };
                println!("Start: {:x}", start as usize);
                let block = MemBlock::new(start, 8 * MB);
                let pfns = block.consec_pfns().unwrap().format_pfns();
                println!("PFN ranges:\n{}", pfns);
                /*
                if offset.is_none() {
                    offset = block.pfn_offset(&mem_config, bs_config.threshold, &*timer, None);
                }
                println!("PFN Offset: {:?}", offset);
                if let Some(offset) = offset {
                    let aligned_va = block.addr(offset * ROW_SIZE) as usize;
                    let pfn = block.pfn().unwrap() as usize;
                    assert_eq!(aligned_va & 0xFCFFF, pfn & 0xFCFFF);
                }
                */
                let end = unsafe { buf.byte_add(end * PAGE_SIZE) };
                assert_eq!(end as usize - start as usize, 8 * MB);
            }
        }
        unsafe {
            munmap(buf, BUF_SIZE);
            munmap(b, 2048 * MB);
        }
    }
}
