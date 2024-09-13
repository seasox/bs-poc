use super::keyed_cache::KeyedCache;
use std::cmp::min;

use super::DRAMAddr;
use super::{pfn_offset::CachedPfnOffset, BytePointer, MemoryTupleTimer};
use crate::memory::mem_configuration::MemConfiguration;
use crate::util::NamedProgress;
use crate::util::ROW_SIZE;
use indicatif::MultiProgress;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use itertools::Itertools;

pub trait PfnOffsetResolver {
    fn pfn_offset(
        &self,
        mem_config: &MemConfiguration,
        conflict_threshold: u64,
        timer: &dyn MemoryTupleTimer,
        progress: Option<&MultiProgress>,
    ) -> Option<usize>;
}

impl<T> PfnOffsetResolver for T
where
    T: BytePointer + CachedPfnOffset,
{
    /// Find the PFN-VA offset in rows.
    ///
    /// This is brute force, simply trying all row offsets from 0..row_offsets (determined using mem_config)
    /// There probably is a more sophisticated way to implement this, e.g., by examing the bank orders and
    /// filtering for possible "bank periods" after each iteration, but this here should be fast enough for now.
    /// WARNING: This function initializes pfn_offset with the provided mem_config. Calling #pfn_offset(...) with
    ///          different arguments afterwards WILL NOT reset the OnceCell, potentially causing unintended behavior.
    fn pfn_offset(
        &self,
        mem_config: &MemConfiguration,
        conflict_threshold: u64,
        timer: &dyn MemoryTupleTimer,
        progress: Option<&MultiProgress>,
    ) -> Option<usize> {
        // reuse cached value if possible
        if let Some(offset) = self.get_cached((mem_config.clone(), conflict_threshold)) {
            return Some(offset);
        }
        // find PFN offset
        let num_rows = self.len() / ROW_SIZE;
        let max_rows = mem_config.bank_function_period() as usize / 2; // TODO: check if it is valid for all bank functions to divide by two here (I think it is)
        let num_rows = min(num_rows, max_rows);
        let offset = progress.map(|progress| {
            progress.add(
                ProgressBar::new(num_rows as u64).with_style(ProgressStyle::named_bar("Offset")),
            )
        });
        let pairs = progress.map(|progress| {
            progress.add(
                ProgressBar::new((num_rows * (num_rows - 1) / 2) as u64)
                    .with_style(ProgressStyle::named_bar("Pairs")),
            )
        });

        // do a quick pre-check. Toggling the uppermost bit in the bank function should result in a fast timing.
        if self.len() >= num_rows * ROW_SIZE {
            let addr1 = self.ptr();
            let addr2 = self.addr(num_rows * ROW_SIZE);
            let time = unsafe { timer.time_subsequent_access_from_ram(addr1, addr2, 1000) };
            if time > conflict_threshold {
                info!("Pre-check failed. Block is not consecutive");
                return self.put(None, (mem_config.clone(), conflict_threshold));
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
            if let (Some(offset), Some(pairs)) = (&offset, &pairs) {
                offset.inc(1);
                pairs.reset();
            }
            // iterate over row pairs
            for row_pair in (0..num_rows).combinations(2) {
                if let Some(pairs) = &pairs {
                    pairs.inc(1);
                }
                let offset1 = row_pair[0] * ROW_SIZE;
                let offset2 = row_pair[1] * ROW_SIZE;
                let addr1 = self.addr(offset1);
                let addr2 = self.addr(offset2);
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
            return self.put(Some(row_offset), (mem_config.clone(), conflict_threshold));
        }
        self.put(None, (mem_config.clone(), conflict_threshold))
    }
}
