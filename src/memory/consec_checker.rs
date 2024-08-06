use anyhow::bail;
use indicatif::MultiProgress;

use crate::{
    memory::{DRAMAddr, FormatPfns, PfnResolver},
    util::{MemConfiguration, PAGE_SIZE, ROW_SIZE, TIMER_ROUNDS},
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

impl AllocChecker for ConsecCheckBankTiming {
    fn check(&mut self, block: &MemBlock) -> anyhow::Result<bool> {
        if block.len % ROW_SIZE != 0 {
            bail!("Block is not row-aligned")
        }
        let row_offsets = self.mem_config.bank_function_period() as usize / 2;

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

        let offset = block.pfn_offset(
            &self.mem_config,
            self.conflict_threshold,
            &*self.timer,
            self.progress_bar.as_ref(),
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
        let consecs = block.consec_pfns()?;
        let pfns = consecs.format_pfns();
        info!("PFNs: {}", pfns);
        let first_block_bytes = (consecs[1] - consecs[0]) as usize;
        let is_consec = first_block_bytes >= block.len;
        if is_consec {
            info!(
                "Allocated a consecutive {} KB block at [{:#02x}, {:#02x})",
                first_block_bytes / 1024,
                block.ptr as u64,
                block.byte_add(first_block_bytes - PAGE_SIZE).ptr as usize + PAGE_SIZE, // subtrace one page from byte_add call to circumvent overflow
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
            bail!("PFN Offset check failed.");
        }
        info!("VA offset: {}", offset.unwrap());
        let a1 = block.byte_add((256 - offset.unwrap()) as usize * ROW_SIZE); // todo row offsets from mem_config
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
