use crate::hammerer::blacksmith::blacksmith_config::{BitDef, BlacksmithConfig};
use crate::util::ROW_SHIFT;
use nalgebra::SMatrix;
use serde::Deserialize;

pub const MTX_SIZE: usize = 30;

#[derive(Deserialize, Debug, Copy, Clone, Default, PartialEq, Eq)]
pub struct MemConfiguration {
    pub(crate) bk_shift: usize,
    pub(crate) bk_mask: usize,
    pub(crate) row_shift: usize,
    pub(crate) row_mask: usize,
    pub(crate) col_shift: usize,
    pub(crate) col_mask: usize,
    pub(crate) dram_mtx: [usize; MTX_SIZE],
    pub(crate) addr_mtx: [usize; MTX_SIZE],
    max_bank_bit: u64,
}

impl MemConfiguration {
    pub fn from_blacksmith(config: &BlacksmithConfig) -> Self {
        MemConfiguration::from_bitdefs(
            config.bank_bits.clone(),
            config.row_bits.clone(),
            config.col_bits.clone(),
        )
    }
    pub fn from_bitdefs(
        bank_bits: Vec<BitDef>,
        row_bits: Vec<BitDef>,
        col_bits: Vec<BitDef>,
    ) -> Self {
        let mut out = MemConfiguration::default();
        let mut i = 0;

        assert_eq!(MTX_SIZE, bank_bits.len() + col_bits.len() + row_bits.len());

        out.bk_shift = MTX_SIZE - bank_bits.len();
        out.bk_mask = (1 << bank_bits.len()) - 1;
        out.col_shift = MTX_SIZE - bank_bits.len() - col_bits.len();
        out.col_mask = (1 << col_bits.len()) - 1;
        out.row_shift = MTX_SIZE - bank_bits.len() - col_bits.len() - row_bits.len();
        out.row_mask = (1 << row_bits.len()) - 1;
        out.max_bank_bit = bank_bits
            .iter()
            .map(|b| match b {
                BitDef::Single(bit) => *bit,
                BitDef::Multi(bits) => *bits.iter().max().unwrap(),
            })
            .max()
            .unwrap();

        // construct dram matrix
        let mut dram_mtx: [usize; MTX_SIZE] = [0; MTX_SIZE];
        let mut update_dram_mtx = |def: &BitDef| {
            dram_mtx[i] = def.to_bitstr();
            i += 1;
        };
        // bank
        bank_bits.iter().for_each(&mut update_dram_mtx);
        // col
        col_bits.iter().for_each(&mut update_dram_mtx);
        // row
        row_bits.iter().for_each(&mut update_dram_mtx);
        out.dram_mtx = dram_mtx;

        // construct addr matrix
        let mut addr_mtx: [usize; MTX_SIZE] = [0; MTX_SIZE];
        // create dram matrix in nalgebra
        let mut matrix = SMatrix::<u8, 30, 30>::zeros();
        for row in 0..MTX_SIZE {
            for col in 0..MTX_SIZE {
                matrix[(row, col)] = (dram_mtx[row] >> (MTX_SIZE - col - 1) & 1) as u8;
            }
        }
        // invert dram matrix, assign addr matrix
        let matrix_inv = matrix
            .cast::<f64>()
            .try_inverse()
            .expect("The matrix defined in the config file is not invertible.")
            .try_cast::<i8>()
            .expect("inverse cast to i8 failed")
            .map(|e| e.abs());

        for row in 0..MTX_SIZE {
            for col in 0..MTX_SIZE {
                if matrix_inv[(row, col)] != 0 && matrix_inv[(row, col)] != 1 {
                    panic!(
                        "expected element to be 0 or 1, got {}",
                        matrix_inv[(row, col)]
                    );
                }
                addr_mtx[row] |= (matrix_inv[(row, col)] as usize) << (MTX_SIZE - col - 1);
            }
        }
        out.addr_mtx = addr_mtx;
        out
    }
}

impl MemConfiguration {
    /// The periodicity of the bank function in rows, i.e., how many rows have to
    /// be iterated until the bank function repeats.
    pub fn bank_function_period(&self) -> u64 {
        1 << (self.max_bank_bit + 1 - ROW_SHIFT as u64)
    }
}

impl MemConfiguration {
    pub fn get_bank_count(&self) -> usize {
        (1 << self.bk_mask.count_ones()) as usize
    }
    pub fn get_row_count(&self) -> usize {
        1_usize << (self.row_mask.count_ones() as usize)
    }
}
