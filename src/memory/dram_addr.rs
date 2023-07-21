use std::fmt::{self, Display, Formatter};

use crate::{jitter::MutAggPointer, util::MemConfiguration};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct DRAMAddr {
    bank: usize,
    row: usize,
    col: usize,
}

impl Display for DRAMAddr {
    fn fmt(&self, fmt: &mut Formatter) -> fmt::Result {
        write!(fmt, "({}, {}, {})", self.bank, self.row, self.col)
    }
}

impl DRAMAddr {
    pub fn from_virt(addr: MutAggPointer, mem_config: &MemConfiguration) -> DRAMAddr {
        let p = addr as usize;
        let mut res = 0;

        for &i in mem_config.dram_mtx.iter() {
            res <<= 1;
            res |= (p & i).count_ones() as usize & 1;
        }
        let bank = (res >> mem_config.bk_shift) & mem_config.bk_mask as usize;
        let row = (res >> mem_config.row_shift) & mem_config.row_mask as usize;
        let col = (res >> mem_config.col_shift) & mem_config.col_mask as usize;

        DRAMAddr { bank, row, col }
    }
}

impl DRAMAddr {
    fn linearize(&self, mem_config: MemConfiguration) -> usize {
        (self.bank << mem_config.bk_shift)
            | (self.row << mem_config.row_shift)
            | (self.col << mem_config.col_shift)
    }

    pub fn to_virt(&self, base_msb: MutAggPointer, mem_config: MemConfiguration) -> MutAggPointer {
        let mut res = 0;
        let l = self.linearize(mem_config);
        for &i in mem_config.addr_mtx.iter() {
            res <<= 1;
            res |= (l & i).count_ones() as usize % 2;
        }
        let base_msb_usize = (base_msb as usize) & !((1 << 30) - 1);
        let v_addr = (base_msb_usize | res) as MutAggPointer;
        v_addr
    }
}

impl Default for DRAMAddr {
    fn default() -> Self {
        Self {
            bank: 0,
            row: 0,
            col: 0,
        }
    }
}

impl DRAMAddr {
    pub fn add(&self, bank: usize, row: usize, col: usize) -> DRAMAddr {
        DRAMAddr {
            bank: self.bank + bank,
            row: self.row + row,
            col: self.col + col,
        }
    }
}
