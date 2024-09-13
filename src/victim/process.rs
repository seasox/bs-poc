use crate::memory::{MemBlock, PfnResolver};
use crate::util::{AttackState, PipeIPC, IPC, PAGE_SIZE};
use crate::victim::HammerVictim;
use anyhow::Context;
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, ChildStdout, Command};
use std::thread;

pub struct VictimProcess<P> {
    pipe: P,
}

impl<P> VictimProcess<P> {
    pub fn new(pipe: P) -> Self {
        Self { pipe }
    }
}

impl<P: IPC<AttackState>> HammerVictim for VictimProcess<P> {
    fn init(&mut self) {
        info!("Victim process initialized");
    }

    fn check(&mut self) -> bool {
        info!("Victim process check");
        self.pipe
            .send(AttackState::AttackerHammerDone)
            .expect("send");
        info!("Reading pipe");
        let state = self.pipe.receive().expect("receive");
        info!("Received state: {:?}", state);
        state == AttackState::VictimHammerSuccess
    }

    fn log_report(&self) {
        info!("Victim process report");
    }
}

/// spawn a thread to log the victim's stderr
pub fn log_victim_stderr(victim: &mut Option<Child>) -> anyhow::Result<()> {
    if let Some(victim) = victim {
        let stderr = victim.stderr.take().context("victim stderr")?;
        thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                info!(target: "victim", "{}", line.unwrap());
            }
        });
    }
    Ok(())
}

pub fn spawn_victim(victim: &[String]) -> anyhow::Result<Option<Child>, std::io::Error> {
    let mut victim_args = victim.to_vec();
    let victim = victim_args.pop();
    victim
        .map(|victim| {
            Command::new(victim)
                .args(victim_args)
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
        })
        .transpose()
}

pub fn inject_page<P: IPC<AttackState>>(channel: &mut P) -> anyhow::Result<()> {
    channel.send(AttackState::AttackerReady)?;

    let b = MemBlock::mmap(PAGE_SIZE)?;
    let pfn = b.pfn()?;
    info!("Victim block PFN: 0x{:02x}", pfn);

    info!("Waiting for signal {:?}", AttackState::VictimAllocReady);
    channel.wait_for(AttackState::VictimAllocReady)?;
    info!("Received signal {:?}", AttackState::VictimAllocReady);

    b.dealloc();
    warn!("TODO release victim page (determined by mapping)");
    Ok(())
}

pub fn piped_channel(child: &mut Child) -> anyhow::Result<PipeIPC<ChildStdout, ChildStdin>> {
    let child_in = child.stdin.take().context("piped_channel stdin")?;
    let child_out = child.stdout.take().context("piped_channel stdout")?;
    Ok(PipeIPC::new(child_out, child_in))
}
