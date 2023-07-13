use crate::util::MemConfiguration;
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct DRAMAddr {
    bank: usize,
    row: usize,
    col: usize,
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

    fn to_string_virt(
        &self,
        base_msb: *const libc::c_void,
        mem_config: MemConfiguration,
    ) -> String {
        format!(
            "DRAMAddr(b: {}, r: {}, c: {}) = {:p}",
            self.bank,
            self.row,
            self.col,
            self.to_virt(base_msb, mem_config)
        )
    }

    fn to_string(&self) -> String {
        format!("({}, {}, {})", self.bank, self.row, self.col)
    }

    fn add(
        &self,
        bank_increment: usize,
        row_increment: usize,
        column_increment: usize,
    ) -> DRAMAddr {
        DRAMAddr {
            bank: self.bank + bank_increment,
            row: self.row + row_increment,
            col: self.col + column_increment,
        }
    }

    fn add_inplace(
        &mut self,
        bank_increment: usize,
        row_increment: usize,
        column_increment: usize,
    ) {
        self.bank += bank_increment;
        self.row += row_increment;
        self.col += column_increment;
    }
}

impl DRAMAddr {
    pub fn new(bank: usize, row: usize, col: usize) -> Self {
        Self {
            bank: bank,
            row: row,
            col: col,
        }
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
