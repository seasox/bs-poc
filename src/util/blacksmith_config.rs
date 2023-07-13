//
// Created by rowhammer on 27.02.23.
//

use anyhow::Context;
use nalgebra::SMatrix;
use serde::de::{self, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::vec::Vec;

#[derive(Deserialize)]
#[serde(untagged)]
pub enum BitDef {
    Single(u64),
    Multi(Vec<u64>),
}

pub const MTX_SIZE: usize = 30;

#[derive(Deserialize)]
pub struct BlacksmithConfig {
    name: String,
    channels: u64,
    dimms: u64,
    ranks: u64,
    total_banks: u64,
    max_rows: u64,
    threshold: u64,
    hammer_rounds: usize,
    drama_rounds: usize,
    acts_per_trefi: u64,
    row_bits: Vec<BitDef>,
    col_bits: Vec<BitDef>,
    bank_bits: Vec<BitDef>,
}

impl BlacksmithConfig {
    pub fn from_jsonfile(filepath: &str) -> Result<BlacksmithConfig, Box<dyn std::error::Error>> {
        let mut file = File::open(Path::new(filepath))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        let config: BlacksmithConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    pub fn to_memconfig(&self) -> MemConfiguration {
        let mut out = MemConfiguration::default();
        let mut i = 0;

        assert_eq!(
            MTX_SIZE,
            self.bank_bits.len() + self.col_bits.len() + self.row_bits.len()
        );

        out.bk_shift = MTX_SIZE - self.bank_bits.len();
        out.bk_mask = (1 << self.bank_bits.len()) - 1;
        out.col_shift = MTX_SIZE - self.bank_bits.len() - self.col_bits.len();
        out.col_mask = (1 << self.col_bits.len()) - 1;
        out.row_shift = MTX_SIZE - self.bank_bits.len() - self.col_bits.len() - self.row_bits.len();
        out.row_mask = (1 << self.row_bits.len()) - 1;

        // construct dram matrix
        let mut dram_mtx: [usize; MTX_SIZE] = [0; MTX_SIZE];
        let mut update_dram_mtx = |def: &BitDef| {
            dram_mtx[i] = bitdef_to_bitstr(def);
            i += 1;
        };
        // bank
        self.bank_bits.iter().for_each(&mut update_dram_mtx);
        // col
        self.col_bits.iter().for_each(&mut update_dram_mtx);
        // row
        self.row_bits.iter().for_each(&mut update_dram_mtx);
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
        let matrix_decomp = matrix
            .cast::<f64>()
            .try_inverse()
            .expect("The matrix defined in the config file is not invertible.")
            .try_cast::<u8>()
            .expect("inverse cast to u8 failed");
        for row in 0..MTX_SIZE {
            for col in 0..MTX_SIZE {
                addr_mtx[row] |= (matrix_decomp[(row, col)] as usize) << (MTX_SIZE - col - 1);
            }
        }
        out.addr_mtx = addr_mtx;
        out
    }
}

pub fn bitdef_to_bitstr(def: &BitDef) -> usize {
    let mut res = 0;
    match def {
        BitDef::Single(bit) => {
            res |= 1 << bit;
        }
        BitDef::Multi(bits) => {
            bits.iter().for_each(|bit| {
                res |= 1 << bit;
            });
        }
    }
    res
}

#[derive(Deserialize, Debug, Copy, Clone, Default)]
pub struct MemConfiguration {
    pub(crate) bk_shift: usize,
    pub(crate) bk_mask: usize,
    pub(crate) row_shift: usize,
    pub(crate) row_mask: usize,
    pub(crate) col_shift: usize,
    pub(crate) col_mask: usize,
    pub(crate) dram_mtx: [usize; MTX_SIZE],
    pub(crate) addr_mtx: [usize; MTX_SIZE],
}
/*
impl MemConfiguration {
    fn get_bank_count(&self) -> usize {
        (1 << self.bk_mask.count_ones()) as usize
    }
    pub fn get_row_count(&self) -> usize {
        1_usize << (self.row_mask.count_ones() as usize)
    }
}
*/
