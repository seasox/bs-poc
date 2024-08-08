use std::io::stdin;
use std::io::stdout;
use std::thread;
use std::time::Duration;

use bs_poc::memory::MemBlock;
use bs_poc::memory::PfnResolver;
use bs_poc::util::AttackState;
use bs_poc::util::PipeIPC;
use bs_poc::util::IPC;
use bs_poc::util::PAGE_SIZE;

fn main() -> anyhow::Result<()> {
    let mut channel = PipeIPC::new(stdin(), stdout());

    eprintln!("Victim initialization");

    eprintln!(
        "Waiting for signal {:?} from attacker",
        AttackState::AttackerReady
    );
    channel.wait_for(AttackState::AttackerReady)?;

    eprintln!("Victim preparing for allocation");

    eprintln!("Send signal {:?}", AttackState::VictimAllocReady);
    channel.send(AttackState::VictimAllocReady)?;

    let b = MemBlock::mmap(PAGE_SIZE)?;
    let pfn = b.pfn()?;
    eprintln!("PFN: 0x{:02x}", pfn);

    loop {
        channel.wait_for(AttackState::AttackerHammerDone)?;

        eprintln!("Cryptography stuff done");
        let p = b.ptr;
        let val = unsafe { std::ptr::read_volatile(p) };
        if val != 0 {
            eprintln!("Hammering successful");
            channel.send(AttackState::VictimHammerSuccess)?;
            return Ok(());
        } else {
            eprintln!("Hammering failed");
            channel.send(AttackState::VictimAllocReady)?;
        }
    }
}
