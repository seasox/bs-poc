use crate::{
    memory::{ConsecBlocks, HugepageAllocator, MemBlock, VictimMemory},
    util::{make_vec, MB},
};
use rand::prelude::SliceRandom;

use super::ConsecAllocator;

pub struct ConsecAllocHugepageRnd {
    hugepages: Vec<ConsecBlocks>,
}

impl ConsecAllocHugepageRnd {
    pub fn new(num_hugepages: u8) -> Self {
        let hugepages = make_vec(num_hugepages as usize, |_| unsafe {
            HugepageAllocator::new()
                .alloc_consec_blocks(1024 * MB)
                .expect("hugepage alloc")
        });
        ConsecAllocHugepageRnd { hugepages }
    }
}

impl ConsecAllocator for ConsecAllocHugepageRnd {
    fn block_size(&self) -> usize {
        4 * MB
    }

    unsafe fn alloc_consec_blocks(&mut self, size: usize) -> anyhow::Result<ConsecBlocks> {
        let hp_size = 1024 * MB;
        let chunk_size = self.block_size();
        let num_chunks = hp_size / chunk_size;
        let total_chunks = self.hugepages.len() * num_chunks;
        let num_blocks = size / chunk_size;

        let mut chunk_indices: Vec<usize> = (0..total_chunks).collect();
        let mut rng = rand::thread_rng();
        chunk_indices.shuffle(&mut rng);
        let selected_indices = &chunk_indices[..num_blocks];
        //let free_indices = &chunk_indices[num_blocks..];

        let blocks = selected_indices
            .iter()
            .map(|index| {
                info!("Hugepage {}", index / num_chunks);
                self.hugepages[index / num_chunks].addr((index % num_chunks) * chunk_size)
            })
            .map(|ptr| MemBlock::new(ptr, chunk_size))
            .collect::<Vec<_>>();
        let consecs = ConsecBlocks::new(blocks);
        Ok(consecs)
    }
}
