mod jitter;
mod memory;

use jitter::{Jitter, Program};
use memory::Memory;

fn main() {
    let mut memory = Memory::new();
    memory.alloc(2048);
    let addr = memory.addr.unwrap() as usize;
    let aggressors: Vec<usize> = (addr..addr + 2048).collect();
    let program = Program::jit(32, &aggressors);
    let result = program.call();
    println!("{:?}", result);
    memory.dealloc();
}
