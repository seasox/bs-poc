use std::io::stdin;
use std::io::stdout;
use std::thread;
use std::time::Duration;

use bs_poc::memory::MemBlock;
use bs_poc::memory::PfnResolver;
use bs_poc::util::PipeIPC;
use bs_poc::util::ATTACKER_READY;
use bs_poc::util::IPC;
use bs_poc::util::PAGE_SIZE;
use bs_poc::util::VICTIM_ALLOC_DONE;
use bs_poc::util::VICTIM_ALLOC_READY;

fn main() -> anyhow::Result<()> {
    let mut channel = PipeIPC::new(stdin(), stdout());

    eprintln!("Waiting for signal {} from attacker", ATTACKER_READY);
    channel.wait_for(ATTACKER_READY)?;

    thread::sleep(Duration::from_secs(1));

    eprintln!("Will do very secret allocation");
    channel.send(VICTIM_ALLOC_READY)?;

    let b = MemBlock::mmap(PAGE_SIZE)?;
    let pfn = b.pfn()?;
    eprintln!("PFN: 0x{:02x}", pfn);
    channel.send(VICTIM_ALLOC_DONE)?;

    eprintln!("Doing very important cryptography stuff");

    thread::sleep(Duration::from_secs(3));

    eprintln!("Cryptography stuff done");
    Ok(())
}
