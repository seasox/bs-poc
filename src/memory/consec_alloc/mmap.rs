use std::{
    cmp::min,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{sleep, spawn},
    time::Duration,
};

use anyhow::Context;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use rand::prelude::SliceRandom;

use crate::{
    memory::{AllocChecker, ConsecBlocks, ConsecCheck, MemBlock},
    util::{NamedProgress, MB, ROW_SIZE},
};

use super::ConsecAllocator;

pub struct ConsecAllocMmap {
    consec_checker: ConsecCheck,
    progress: Option<MultiProgress>,
}

impl ConsecAllocMmap {
    pub fn new(consec_checker: ConsecCheck, progress: Option<MultiProgress>) -> Self {
        ConsecAllocMmap {
            consec_checker,
            progress,
        }
    }
}

impl ConsecAllocator for ConsecAllocMmap {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        assert_eq!(size % self.block_size(), 0);
        unsafe impl Send for MemBlock {}
        let num_blocks = size / self.block_size();

        let blocks: Vec<MemBlock> = Vec::with_capacity(num_blocks);
        let blocks = Arc::new(Mutex::new(blocks));
        let mem_lock = Arc::new(Mutex::new(()));
        let stop = Arc::new(AtomicBool::new(false));

        let loader_blocks = blocks.clone();
        let loader_mem_lock = mem_lock.clone();
        let loader_stop = Arc::clone(&stop);
        let loader_thread = spawn(|| {
            info!(target: "loader", "starting loader thread");
            let blocks = loader_blocks;
            let mem_lock = loader_mem_lock;
            let stop = loader_stop;
            while stop.load(Ordering::Relaxed) == false {
                let blocks = blocks.lock().unwrap().clone();
                for block in blocks {
                    for offset in (0..block.len).step_by(ROW_SIZE) {
                        let addr = block.byte_add(offset).ptr;
                        let count = min(ROW_SIZE, block.len - offset);
                        trace!(target: "loader", "Waiting for memory lock");
                        let mem_lock = mem_lock.lock().unwrap();
                        unsafe { std::ptr::write_bytes(addr as *mut u8, 0, count) };
                        drop(mem_lock);
                    }
                }
                sleep(Duration::from_millis(100));
            }
            info!(target: "loader", "goodbye");
        });
        let block_size = self.block_size();
        let checker = self.consec_checker.clone();

        let progress = match &mut self.progress {
            Some(progress) => {
                let pg = ProgressBar::new(num_blocks as u64)
                    .with_style(ProgressStyle::named_bar("Blocks"));
                let pg = progress.add(pg);
                pg.enable_steady_tick(Duration::from_secs(1));
                Some(pg)
            }
            None => None,
        };

        let allocator_mem_lock = Arc::clone(&mem_lock);
        let allocator_blocks = Arc::clone(&blocks);
        let allocator_progress = progress.clone();
        let allocator_thread = spawn(move || {
            let blocks = allocator_blocks;
            let mem_lock = allocator_mem_lock;
            let progress = allocator_progress;
            const CANDIDATE_COUNT: usize = 1000; // 1000 * 4 MB = 4 GB
            const DUMMY_ALLOC_SIZE: usize = 4 * 1024 * MB;
            let buf = MemBlock::mmap(DUMMY_ALLOC_SIZE).unwrap();
            let mut blocks_len = 0;
            while blocks_len < num_blocks {
                let mut candidates = (0..CANDIDATE_COUNT)
                    .map(|_| MemBlock::mmap(block_size).context("mmap").unwrap())
                    .collect_vec();
                candidates.shuffle(&mut rand::thread_rng());
                let mut found_consec = false;
                for candidate in candidates {
                    if blocks_len >= num_blocks {
                        candidate.dealloc();
                        continue;
                    }
                    trace!(target: "allocator", "Waiting for memory lock");
                    let lock = mem_lock.lock().unwrap();
                    let is_consec = checker.check(&candidate).unwrap();
                    drop(lock);
                    if is_consec {
                        blocks.lock().unwrap().push(candidate);
                        blocks_len += 1;
                        found_consec = true;
                        info!("Found consecutive block");
                        if let Some(progress) = &progress {
                            progress.inc(1);
                        }
                    } else {
                        candidate.dealloc();
                    }
                }
                if blocks_len < num_blocks && !found_consec {
                    warn!(
                    "Failed to find consecutive block in {} candidates. Retrying with new candidates...",
                    CANDIDATE_COUNT
                );
                }
            }
            buf.dealloc();
            assert_eq!(blocks_len, num_blocks);
        });

        allocator_thread.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        loader_thread.join().unwrap();

        let blocks = blocks.lock().unwrap().clone();

        let consecs = ConsecBlocks::new(blocks);
        progress.map(|p| p.finish());
        Ok(consecs) /*.pfn_align(
                        &self.mem_config,
                        self.conflict_threshold,
                        &*construct_memory_tuple_timer()?,
                    )*/
    }
}
