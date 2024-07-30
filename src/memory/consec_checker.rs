use anyhow::bail;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;

use crate::{
    memory::{DRAMAddr, PfnResolver},
    util::{MemConfiguration, PAGE_SIZE, ROW_SHIFT, ROW_SIZE, TIMER_ROUNDS},
};

use super::{MemBlock, MemoryTupleTimer};

pub trait AllocChecker {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool>;
}

pub struct AllocCheckAnd<A, B> {
    a: A,
    b: B,
}

impl<A: AllocChecker, B: AllocChecker> AllocCheckAnd<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: AllocChecker, B: AllocChecker> AllocChecker for AllocCheckAnd<A, B> {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        Ok(self.a.check(block)? && self.b.check(block)?)
    }
}

pub struct AllocCheckPageAligned {}

impl AllocChecker for AllocCheckPageAligned {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        if (block.ptr as u64) & 0xFFF != 0 {
            bail!("Address is not page-aligned: 0x{:x}", block.ptr as u64);
        }
        Ok(true)
    }
}

pub struct ConsecCheckBankTiming {
    mem_config: MemConfiguration,
    timer: Box<dyn MemoryTupleTimer>,
    conflict_threshold: u64,
    progress_bar: Option<MultiProgress>,
}

impl ConsecCheckBankTiming {
    pub fn new(
        mem_config: MemConfiguration,
        timer: Box<dyn MemoryTupleTimer>,
        conflict_threshold: u64,
    ) -> Self {
        Self::new_with_progress(mem_config, timer, conflict_threshold, None)
    }
    pub fn new_with_progress(
        mem_config: MemConfiguration,
        timer: Box<dyn MemoryTupleTimer>,
        conflict_threshold: u64,
        progress_bar: Option<MultiProgress>,
    ) -> Self {
        Self {
            mem_config,
            timer,
            conflict_threshold,
            progress_bar,
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
    pub fn pfn_offset(
        &self,
        mem_config: &MemConfiguration,
        conflict_threshold: u64,
        timer: &dyn MemoryTupleTimer,
        progress: Option<Progress>,
    ) -> Option<usize> {
        let num_rows = self.len / ROW_SIZE;
        let row_offsets = (1 << mem_config.max_bank_bit) / ROW_SIZE; // the number of rows to iterate before overflowing the bank function
        let row_pairs = (0..num_rows).combinations(2);
        'next_offset: for row_offset in 0..row_offsets {
            let addr_offset = (row_offset as usize * ROW_SIZE) as isize;
            debug!(
                "Checking row offset {} (effective offset: 0x{:x})",
                row_offset, addr_offset
            );
            if let Some(progress) = &progress {
                progress.offset.inc(1);
                progress.pairs.reset();
            }
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
            return Some(row_offset);
        }
        None
    }
}

impl AllocChecker for ConsecCheckBankTiming {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        if block.len % ROW_SIZE != 0 {
            bail!("Block is not row-aligned")
        }
        let row_offsets = 1 << (self.mem_config.max_bank_bit - ROW_SHIFT as u64);
        let num_rows = block.len / ROW_SIZE;

        // as a first quick test, we check whether rows (0, row_offsets) are in the same bank. For a
        // consecutive allocation, this should always hold, since the RankBank function is periodic.
        if block.len >= row_offsets * ROW_SIZE {
            let addr1 = block.byte_add(0 * ROW_SIZE).ptr;
            let addr2 = block.byte_add(row_offsets * ROW_SIZE).ptr;
            debug!("Doing quick pre-check for consecutive allocation");
            let t = unsafe {
                self.timer
                    .time_subsequent_access_from_ram(addr1, addr2, 1000)
            };
            if t < self.conflict_threshold {
                debug!("Block is not consecutive");
                return Ok(false);
            }
        } else {
            debug!("Skip pre-check, block is too small");
        }

        let progress = self
            .progress_bar
            .as_ref()
            .map(|pb| Progress::from_multi(row_offsets as u64, num_rows, pb.clone()));
        let offset = block.pfn_offset(
            &self.mem_config,
            self.conflict_threshold,
            &*self.timer,
            progress,
        );
        if offset.is_some() {
            info!("VA offset: {:?}", offset);
        }
        Ok(offset.is_some())
    }
}

pub struct ConsecCheckPfn {}

impl AllocChecker for ConsecCheckPfn {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        /*
         * Check whether the allocation is actually consecutive. The current implementation simply
         * checks for consecutive PFNs using the virt-to-phys pagemap. This needs root permissions.
         * Therefore, this check should be replaced with a timing side channel to verify the address function
         * in the memory block. If the measured timings correspond to the address function, it is very likely that
         * this indeed is a consecutive memory block.
         */
        trace!("Get consecutive PFNs for vaddr 0x{:x}", block.ptr as u64);
        let mut phys_prev = block.pfn()?;
        let mut consecs = vec![phys_prev];
        for offset in (PAGE_SIZE..block.len).step_by(PAGE_SIZE) {
            let phys = block.byte_add(offset).pfn()?;
            if phys != phys_prev + PAGE_SIZE as u64 {
                consecs.push(phys_prev + PAGE_SIZE as u64);
                consecs.push(phys);
            }
            phys_prev = phys;
        }
        consecs.push(phys_prev + PAGE_SIZE as u64);
        trace!("PFN check done");
        let mut pfns = String::from("PFNs: ");
        for (p1, p2) in consecs.windows(2).map(|w| (w[0], w[1])).step_by(2) {
            pfns += &format!("{:x}..[{} KB]..{:x} ", p1, (p2 - p1 as u64) / 1024, p2);
        }
        let first_block_bytes = (consecs[1] - consecs[0]) as usize;
        let is_consec = first_block_bytes >= block.len;
        if is_consec {
            info!(
                "Allocated a consecutive {} KB block at [{:#02x}, {:#02x}]",
                first_block_bytes / 1024,
                block.ptr as u64,
                block.byte_add(first_block_bytes).ptr as u64,
            );
            info!("{}", pfns);
        }
        Ok(is_consec)
    }
}

pub struct AllocCheckSameBank {
    mem_config: MemConfiguration,
    threshold: u64,
    timer: Box<dyn MemoryTupleTimer>,
    previous_blocks: Vec<MemBlock>,
}

impl AllocCheckSameBank {
    pub fn new(
        mem_config: MemConfiguration,
        threshold: u64,
        timer: Box<dyn MemoryTupleTimer>,
    ) -> Self {
        Self {
            mem_config,
            threshold,
            timer,
            previous_blocks: Vec::new(),
        }
    }
}

impl AllocChecker for AllocCheckSameBank {
    /// bank check
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        let offset = block.pfn_offset(&self.mem_config, self.threshold, &*self.timer, None);
        if offset.is_none() {
            bail!("Block is not consecutive");
        }
        info!("VA offset: {}", offset.unwrap());
        let a1 = block.byte_add(offset.unwrap() as usize * ROW_SIZE);
        for (i, previous_block) in self.previous_blocks.iter().enumerate() {
            let offset =
                previous_block.pfn_offset(&self.mem_config, self.threshold, &*self.timer, None);
            if offset.is_none() {
                bail!("Previous block is not consecutive");
            }
            let a2 = previous_block.byte_add(offset.unwrap() as usize * ROW_SIZE);
            let time = unsafe {
                self.timer
                    .time_subsequent_access_from_ram(a1.ptr, a2.ptr, TIMER_ROUNDS)
            };
            if time < self.threshold {
                info!(
                    "Bank conflict check with block {} failed: timed {} < {}",
                    i, time, self.threshold
                );
                return Ok(false);
            } else {
                info!(
                    "Bank conflict check with block {} succeeded: timed {} > {}",
                    i, time, self.threshold
                );
            }
        }
        self.previous_blocks.push(block.clone());
        info!(
            "Push block {:?}. {} blocks in total",
            block,
            self.previous_blocks.len()
        );
        Ok(true)
    }
}
