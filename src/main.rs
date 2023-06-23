mod jitter;
mod memory;

use jitter::{FencingStrategy, FlushingStrategy, Jitter, Program};
use memory::Memory;

fn main() {
    let mut memory = Memory::new();
    memory.alloc(2048);
    let addr = memory.addr.unwrap() as u64;
    let aggressors: Vec<u64> = (addr..addr + 2048).collect();
    let program = Program::jit(
        170,
        FlushingStrategy::LatestPossible,
        FencingStrategy::EarliestPossible,
        &aggressors,
        true,
        32,
        120,
    );
    let result = program.unwrap().call();
    println!("{:?}", result);
    memory.dealloc();
}
