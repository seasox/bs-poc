use anyhow::bail;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;

use crate::util::{MemConfiguration, PAGE_SIZE, ROW_SIZE, TIMER_ROUNDS};

use super::{DRAMAddr, MemBlock, MemoryTupleTimer};

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

impl AllocChecker for ConsecCheckBankTiming {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        // TODO: determine row offsets from RankBank function. Here, we repeat
        // bank orders after 512 rows (see bank_order.txt)
        let row_offsets = 512;
        if block.len % ROW_SIZE != 0 {
            bail!("Block is not row-aligned")
        }
        let num_rows = block.len / ROW_SIZE;
        let row_pairs = (0..num_rows).combinations(2);

        // as a first quick test, we check whether rows (0, row_offsets) are in the same bank. For a
        // consecutive allocation, this should always hold, since the RankBank function is periodic.
        let addr1 = unsafe { block.ptr.byte_add(0 * ROW_SIZE) };
        let addr2 = unsafe { block.ptr.byte_add(512 * ROW_SIZE) };
        debug!("Doing quick pre-check for consecutive allocation");
        let t = unsafe {
            self.timer
                .time_subsequent_access_from_ram(addr1, addr2, 1000)
        };
        if t < self.conflict_threshold {
            debug!("Block is not consecutive");
            return Ok(false);
        }

        struct Progress {
            offset: ProgressBar,
            pairs: ProgressBar,
        }
        let progress = if let Some(progress_bar) = &self.progress_bar {
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
            Some(Progress {
                offset: offset_progress,
                pairs: pairs_progress,
            })
        } else {
            None
        };
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
                    (block.ptr as *mut u8)
                        .add(((row_offset as usize + row1) * ROW_SIZE) % block.len)
                };
                let addr2 = unsafe {
                    (block.ptr as *mut u8)
                        .add(((row_offset as usize + row2) * ROW_SIZE) % block.len)
                };
                let dram1 = DRAMAddr::from_virt_offset(addr1, addr_offset, &self.mem_config);
                let dram2 = DRAMAddr::from_virt_offset(addr2, addr_offset, &self.mem_config);
                let bank1 = dram1.bank;
                let bank2 = dram2.bank;
                let same_bank = bank1 == bank2;
                let time = unsafe {
                    self.timer
                        .time_subsequent_access_from_ram(addr1, addr2, 1000)
                };
                if (same_bank && time < self.conflict_threshold)
                    || (!same_bank && time > self.conflict_threshold)
                {
                    debug!(
                        "Expected {} banks for ({:?}, {:?}), but timed {} {} {}",
                        if same_bank { "same" } else { "differing" },
                        row1,
                        row2,
                        time,
                        if same_bank { "<" } else { ">" },
                        self.conflict_threshold
                    );
                    debug!(
                        "rows: ({}, {}); addrs: (0x{:x}, 0x{:x}); DRAM: {:?}, {:?}",
                        row1, row2, addr1 as u64, addr2 as u64, dram1, dram2
                    );
                    continue 'next_offset;
                }
            }
            return Ok(true);
        }
        Ok(false)
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
        use crate::memory::{LinuxPageMap, VirtToPhysResolver};
        let mut resolver = LinuxPageMap::new()?;
        trace!("Get consecutive PFNs for vaddr 0x{:x}", block.ptr as u64);
        let mut phys_prev = resolver.get_phys(block.ptr as u64)?;
        let mut consecs = vec![phys_prev];
        for offset in (PAGE_SIZE..block.len).step_by(PAGE_SIZE) {
            let virt = unsafe { (block.ptr as *const u8).add(offset) };
            let phys = resolver.get_phys(virt as u64)?;
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
                unsafe { block.ptr.add(first_block_bytes) as u64 },
            );
            info!("{}", pfns);
        }
        Ok(is_consec)
    }
}

pub struct AllocCheckSameBank {
    threshold: u64,
    timer: Box<dyn MemoryTupleTimer>,
    previous_blocks: Vec<MemBlock>,
}

impl AllocCheckSameBank {
    pub fn new(threshold: u64, timer: Box<dyn MemoryTupleTimer>) -> Self {
        Self {
            threshold,
            timer,
            previous_blocks: Vec::new(),
        }
    }
}

impl AllocChecker for AllocCheckSameBank {
    /// bank check
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        let a1 = block.ptr;
        for (i, previous_block) in self.previous_blocks.iter().enumerate() {
            let a2 = previous_block.ptr;
            let time = unsafe {
                self.timer
                    .time_subsequent_access_from_ram(a1, a2, TIMER_ROUNDS)
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
