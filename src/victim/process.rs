use crate::util::{AttackState, PipeIPC, IPC};
use crate::victim::HammerVictim;
use anyhow::{bail, Context};
use std::io::{BufRead, BufReader};
use std::process::{Child, ChildStdin, ChildStdout, Command};
use std::thread;

pub struct VictimProcess {
    victim: Child,
    pipe: PipeIPC<ChildStdout, ChildStdin>,
}

impl VictimProcess {
    pub fn new(target: &[String]) -> anyhow::Result<Self> {
        let program = target.first().context("No target specified")?.clone();
        let args = target;
        let mut victim = spawn_victim(program, args)?;
        log_victim_stderr(&mut victim)?;
        let mut pipe: PipeIPC<ChildStdout, ChildStdin> = piped_channel(&mut victim)?;
        inject_page(&mut pipe)?;
        Ok(Self { victim, pipe })
    }
}

impl HammerVictim<String> for VictimProcess {
    fn init(&mut self) {
        info!("Victim process initialized");
    }

    fn check(&mut self) -> anyhow::Result<String> {
        info!("Victim process check");
        self.pipe
            .send(AttackState::AttackerHammerDone)
            .expect("send");
        info!("Reading pipe");
        let state: AttackState = self.pipe.receive()?;
        info!("Received state: {:?}", state);
        if state == AttackState::VictimHammerSuccess {
            Ok("Success".to_string())
        } else {
            bail!("hammer failed")
        }
    }

    fn stop(self) {
        info!("Waiting for victim to finish");
        match self.victim.wait_with_output() {
            Ok(output) => {
                info!("Captured output: {:?}", output);
            }
            Err(e) => {
                error!("Failed to wait for victim: {:?}", e);
            }
        }
    }
}

/// spawn a thread to log the victim's stderr
fn log_victim_stderr(victim: &mut Child) -> anyhow::Result<()> {
    let stderr = victim.stderr.take().context("victim stderr")?;
    thread::spawn(move || {
        let reader = BufReader::new(stderr);
        for line in reader.lines() {
            info!(target: "victim", "{}", line.unwrap());
        }
    });
    Ok(())
}

fn spawn_victim(victim: String, args: &[String]) -> anyhow::Result<Child> {
    Command::new(victim.clone())
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context(format!(
            "Failed to spawn victim {} with args {:?}",
            victim, args
        ))
}

fn inject_page<P: IPC<AttackState, AttackState>>(_channel: &mut P) -> anyhow::Result<()> {
    todo!("Inject page into victim process");
    /*
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
    */
}

pub(crate) fn piped_channel(child: &mut Child) -> anyhow::Result<PipeIPC<ChildStdout, ChildStdin>> {
    let child_in = child.stdin.take().context("piped_channel stdin")?;
    let child_out = child.stdout.take().context("piped_channel stdout")?;
    Ok(PipeIPC::new(child_out, child_in))
}
