use anyhow::bail;
use indicatif::MultiProgress;

use super::{construct_memory_tuple_timer, MemBlock, PfnOffsetResolver};
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::GetConsecPfns;
use crate::{
    memory::{BytePointer, DRAMAddr, FormatPfns, PfnResolver},
    util::{PAGE_SIZE, ROW_SIZE},
};

pub trait AllocChecker {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool>;
}

/**
 * A helper enum to create a checker from CLI arguments. This allows us to circumvent heap allocation
 */
#[derive(Clone)]
pub enum ConsecCheck {
    Pfn(ConsecCheckPfn),
    BankTiming(ConsecCheckBankTiming),
    None(ConsecCheckNone),
}

impl AllocChecker for ConsecCheck {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        match self {
            ConsecCheck::Pfn(c) => c.check(block),
            ConsecCheck::BankTiming(c) => c.check(block),
            ConsecCheck::None(c) => c.check(block),
        }
    }
}

#[derive(Clone)]
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
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        Ok(self.a.check(block)? && self.b.check(block)?)
    }
}

#[derive(Clone)]
pub struct AllocCheckPageAligned {}

impl AllocChecker for AllocCheckPageAligned {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        if (block.ptr as u64) & 0xFFF != 0 {
            bail!("Address is not page-aligned: 0x{:x}", block.ptr as u64);
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct ConsecCheckBankTiming {
    mem_config: MemConfiguration,
    conflict_threshold: u64,
    progress_bar: Option<MultiProgress>,
}

impl ConsecCheckBankTiming {
    pub fn new(mem_config: MemConfiguration, conflict_threshold: u64) -> Self {
        Self::new_with_progress(mem_config, conflict_threshold, None)
    }
    pub fn new_with_progress(
        mem_config: MemConfiguration,
        conflict_threshold: u64,
        progress_bar: Option<MultiProgress>,
    ) -> Self {
        Self {
            mem_config,
            conflict_threshold,
            progress_bar,
        }
    }
}

impl AllocChecker for ConsecCheckBankTiming {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        if block.len % ROW_SIZE != 0 {
            bail!("Block is not row-aligned")
        }

        let offset = block.pfn_offset(
            &self.mem_config,
            self.conflict_threshold,
            &*construct_memory_tuple_timer()?,
            self.progress_bar.as_ref(),
        );
        if offset.is_some() {
            info!("VA offset: {:?}", offset);
        }
        Ok(offset.is_some())
    }
}

#[derive(Copy, Clone)]
pub struct ConsecCheckPfn {}

impl AllocChecker for ConsecCheckPfn {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
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
        let first_block_bytes = (consecs[0].end - consecs[0].start) as usize;
        let is_consec = first_block_bytes >= block.len;
        if is_consec {
            info!(
                "Allocated a consecutive {} KB block at [{:#02x}, {:#02x})",
                first_block_bytes / 1024,
                block.ptr as u64,
                block.addr(first_block_bytes - PAGE_SIZE) as usize + PAGE_SIZE, // subtrace one page from byte_add call to circumvent overflow
            );
            info!("{}", pfns);
        }
        Ok(is_consec)
    }
}

/// An AllocChecker which tests for consistent memory banks.
///
/// As it turns out, we don't *really* need consecutive PFNs. What we do need is dram addressing with a bank order consistent with consecutive PFNs.
/// This is what this check does.
pub struct ConsecCheckPfnBank {
    mem_config: MemConfiguration,
}

impl ConsecCheckPfnBank {
    pub fn new(mem_config: MemConfiguration) -> Self {
        Self { mem_config }
    }
}

impl AllocChecker for ConsecCheckPfnBank {
    fn check(&self, block: &MemBlock) -> anyhow::Result<bool> {
        let pfns = block.consec_pfns()?.format_pfns();
        info!("PFNs: {}", pfns);
        let first_pfn = block.pfn()? as *mut u8;
        for row in (0..block.len).step_by(ROW_SIZE) {
            let pfn = block.addr(row).pfn()? as *mut u8;
            // compare the actual PFN bank with the expected bank if the observed block were consecutive
            let dram = DRAMAddr::from_virt(pfn, &self.mem_config);
            let expected_dram =
                DRAMAddr::from_virt(unsafe { first_pfn.byte_add(row) }, &self.mem_config);
            if dram.bank != expected_dram.bank {
                info!("Bank check failed: {:?} != {:?}", dram, expected_dram);
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone)]
pub struct ConsecCheckNone {}

impl AllocChecker for ConsecCheckNone {
    fn check(&self, _block: &MemBlock) -> anyhow::Result<bool> {
        Ok(true)
    }
}
