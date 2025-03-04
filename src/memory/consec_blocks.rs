use std::{collections::VecDeque, ops::Range};

use crate::memory::BytePointer;

use super::{GetConsecPfns, MemBlock, VictimMemory};

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
        self.blocks.iter().map(|block| block.len).sum()
    }
}

impl GetConsecPfns for ConsecBlocks {
    fn consec_pfns(&self) -> anyhow::Result<Vec<Range<u64>>> {
        let mut pfns = vec![];
        for block in &self.blocks {
            let mut block_pfns = VecDeque::from(block.consec_pfns()?);
            let is_cons = pfns
                .last()
                .is_some_and(|last: &Range<u64>| last.start == block_pfns[0].end);
            if is_cons {
                let prev = pfns.pop();
                let next = block_pfns.pop_front();
                pfns.push(prev.unwrap().start..next.unwrap().end);
            }
            pfns.extend(block_pfns);
        }
        Ok(pfns)
    }
}
