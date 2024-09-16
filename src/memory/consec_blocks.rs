use std::io::Write;
use std::{collections::VecDeque, fs::OpenOptions};

use crate::memory::{BytePointer, FormatPfns};

use super::{MemBlock, VictimMemory};

#[derive(Debug)]
pub struct ConsecBlocks {
    pub blocks: Vec<MemBlock>,
}

impl ConsecBlocks {
    pub fn new(blocks: Vec<MemBlock>) -> Self {
        ConsecBlocks { blocks }
    }
    pub fn dealloc(self) {
        for block in self.blocks {
            block.dealloc();
        }
    }
}

impl VictimMemory for ConsecBlocks {}

impl BytePointer for ConsecBlocks {
    fn addr(&self, offset: usize) -> *mut u8 {
        assert!(offset < self.len(), "Offset {} >= {}", offset, self.len());
        let mut offset = offset;
        for block in &self.blocks {
            if offset < block.len {
                return block.addr(offset);
            }
            offset -= block.len;
        }
        unreachable!("block not found for offset 0x{:x}", offset);
    }

    fn ptr(&self) -> *mut u8 {
        self.blocks.first().unwrap().ptr()
    }

    fn len(&self) -> usize {
        return self.blocks.iter().map(|block| block.len).sum();
    }
}

impl ConsecBlocks {
    pub fn log_pfns(&self) {
        let mut pfns = vec![];
        for block in &self.blocks {
            let block_pfns = match block.consec_pfns() {
                Ok(pfns) => pfns,
                Err(e) => {
                    error!("Failed to get PFNs: {:?}", e);
                    return;
                }
            };
            let mut block_pfns = VecDeque::from(block_pfns);
            let is_cons = pfns.last().map_or(false, |last| *last == block_pfns[0]);
            if is_cons {
                pfns.pop();
                block_pfns.pop_front();
            }
            pfns.extend(block_pfns);
        }
        let pfns = pfns.format_pfns();
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open("pfns.txt")
            .expect("Failed to open pfns.txt");
        write!(f, "\nConsecutive PFNs:\n{}\n", pfns).expect("Failed to write to pfns.txt");
        info!("PFNs:\n{}", pfns);
    }
}
