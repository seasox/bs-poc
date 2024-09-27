use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{spawn, JoinHandle},
    time::Duration,
};

use anyhow::Context;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use itertools::Itertools;
use rand::prelude::SliceRandom;

use super::ConsecAllocator;
use crate::{
    allocator::util::spawn_page_locking_thread,
    memory::{AllocChecker, ConsecBlocks, ConsecCheck, MemBlock},
    util::{NamedProgress, MB},
};

pub struct Mmap {
    consec_checker: ConsecCheck,
    progress: Option<MultiProgress>,
}

impl Mmap {
    pub fn new(consec_checker: ConsecCheck, progress: Option<MultiProgress>) -> Self {
        Mmap {
            consec_checker,
            progress,
        }
    }
}

/// Spawn a thread that allocates memory blocks and checks for consecutive blocks using the provided `checker`.
fn spawn_allocator_thread(
    blocks: Arc<Mutex<Vec<MemBlock>>>,
    mem_lock: Arc<Mutex<()>>,
    num_blocks: usize,
    block_size: usize,
    checker: ConsecCheck,
    progress: Option<ProgressBar>,
) -> JoinHandle<()> {
    spawn(move || {
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
    })
}

impl ConsecAllocator for Mmap {
    fn block_size(&self) -> usize {
        4 * MB
    }

    fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        assert_eq!(size % self.block_size(), 0);
        unsafe impl Send for MemBlock {}
        let block_size = self.block_size();
        let num_blocks = size / block_size;

        let blocks: Vec<MemBlock> = Vec::with_capacity(num_blocks);
        let blocks = Arc::new(Mutex::new(blocks));
        let mem_lock = Arc::new(Mutex::new(()));
        let stop = Arc::new(AtomicBool::new(false));

        let page_locker = spawn_page_locking_thread(blocks.clone(), mem_lock.clone(), stop.clone());

        let progress = self.progress.as_ref().map(|progress| {
            let pg =
                ProgressBar::new(num_blocks as u64).with_style(ProgressStyle::named_bar("Blocks"));
            let pg = progress.add(pg);
            pg.enable_steady_tick(Duration::from_secs(1));
            pg
        });

        let allocator_thread = spawn_allocator_thread(
            blocks.clone(),
            mem_lock.clone(),
            num_blocks,
            block_size,
            self.consec_checker.clone(),
            progress.clone(),
        );

        allocator_thread.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        page_locker.join().unwrap();

        let blocks = blocks.lock().unwrap().clone();

        let _blocks = blocks
            .into_iter()
            .flat_map(|block| block.pfn_align().expect("Failed to align block"))
            .collect_vec();

        todo!("Migrate config file to struct member");
        /*
        let pfns: Vec<_> = blocks
            .iter()
            .map(|block| block.pfn().expect("Failed to get PFN"))
            .map(|pfn| {
                DRAMAddr::from_virt(
                    pfn as *mut u8,
                    &MemConfiguration::from_blacksmith(
                        &BlacksmithConfig::from_jsonfile("config/bs-config.json").unwrap(),
                    ),
                )
                .bank
            })
            .collect();

        info!("{:?}", pfns);

        let consecs = ConsecBlocks::new(blocks);
        if let Some(progress) = progress {
            progress.finish();
        }
        Ok(consecs)*/
    }
}
