use std::fmt::{self, Display, Formatter};

use crate::util::MemConfiguration;
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
    fn linearize(&self, mem_config: MemConfiguration) -> usize {
        (self.bank << mem_config.bk_shift)
            | (self.row << mem_config.row_shift)
            | (self.col << mem_config.col_shift)
    }

    pub fn to_virt(
        &self,
        base_msb: *const std::ffi::c_void,
        mem_config: MemConfiguration,
    ) -> *const libc::c_void {
        let mut res = 0;
        let l = self.linearize(mem_config);
        for &i in mem_config.addr_mtx.iter() {
            res <<= 1;
            res |= (l & i).count_ones() as usize % 2;
        }
        let base_msb_usize = (base_msb as usize) & !((1 << 30) - 1);
        let v_addr = (base_msb_usize | res) as *const std::ffi::c_void;
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
