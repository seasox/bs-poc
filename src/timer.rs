use std::{
    arch::x86_64::{__rdtscp, _mm_clflush, _mm_lfence, _mm_mfence},
    ptr,
};

use crate::jitter::AggressorPtr;

pub trait MemoryTupleTimer {
    fn measure(&self, a1: AggressorPtr, a2: AggressorPtr, rounds: u64) -> u64;
}

pub struct DefaultMemoryTupleTimer {}

impl MemoryTupleTimer for DefaultMemoryTupleTimer {
    fn measure(&self, a1: AggressorPtr, a2: AggressorPtr, rounds: u64) -> u64 {
        let mut sum = 0;
        for _round in 0..rounds {
            unsafe {
                let mut aux = 0;
                _mm_mfence();
                let start = __rdtscp(&mut aux);
                _mm_lfence();
                ptr::read_volatile(a1);
                ptr::read_volatile(a2);
                _mm_lfence();
                let end = __rdtscp(&mut aux);
                sum += end - start;
                _mm_clflush(a1);
                _mm_clflush(a2);
            }
        }
        sum / rounds as u64
    }
}
