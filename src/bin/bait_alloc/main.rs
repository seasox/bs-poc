use std::{
    env,
    process::{Command, Stdio},
    ptr::null_mut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
};

use anyhow::Context;
use bs_poc::memory::{LinuxPageMap, VirtToPhysResolver};
use clap::Parser;
use libc::{MAP_ANONYMOUS, MAP_PRIVATE, M_ARENA_MAX, M_MMAP_THRESHOLD, PROT_READ, PROT_WRITE};

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "mode", default_value = "bait")]
    mode: BaitMode,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum BaitMode {
    Bait,
    Prey,
}

const PAGE_COUNT: usize = 1000;
const RELEASE_COUNT: usize = 500;
const PREY_PAGE_COUNT: usize = 500;
const PAGE_LEN: usize = 4096;

fn prog() -> Option<String> {
    env::args().next().as_ref().cloned()
}

fn signal(sig: &str, pid: u32) -> anyhow::Result<()> {
    let mut kill = Command::new("kill")
        .args(["-s", sig, &pid.to_string()])
        .spawn()?;
    kill.wait()?;
    Ok(())
}
// next: spezifischen speicherbereich unterschieben
unsafe fn mode_bait(mut resolver: LinuxPageMap) -> anyhow::Result<()> {
    let mut virt = [std::ptr::null_mut(); PAGE_COUNT];
    let mut phys = [0_u64; PAGE_COUNT];

    let prog = prog().expect("prog");
    let child = Command::new(prog)
        .stdout(Stdio::piped())
        .args(["--mode", "prey"])
        .spawn()?;

    // allocate PAGE_COUNT 4K pages
    for i in 0..PAGE_COUNT {
        let v = libc::mmap(
            null_mut(),
            PAGE_LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        libc::memset(v, 0_i32, PAGE_LEN);
        let p = resolver
            .get_phys(v as u64)
            .context("virt_to_phys failed. Are we root?")?;
        virt[i] = v;
        phys[i] = p;
    }

    // release RELEASE_COUNT 4K pages
    // write phys addrs to be deallocated to file
    let bait_phys = &phys[PAGE_COUNT - RELEASE_COUNT..PAGE_COUNT];

    // deallocate bait pages
    for i in (PAGE_COUNT - RELEASE_COUNT)..PAGE_COUNT {
        libc::munmap(virt[i], PAGE_LEN);
    }

    // signal child process
    signal("INT", child.id())?;

    let output = child.wait_with_output().expect("child wait");

    // compare allocated pages
    let bait: Vec<String> = bait_phys
        .iter()
        .map(|p| format!("{}", p).to_string())
        .collect();
    let prey: Vec<String> = String::from_utf8(output.stdout)?
        .lines()
        .map(|s| s.to_string())
        .collect();

    let mut hit = 0;

    for line in &prey {
        if bait.contains(line) {
            hit += 1;
        }
    }

    println!(
        "{}/{}: {:.03}",
        hit,
        prey.len(),
        hit as f32 / prey.len() as f32
    );

    Ok(())
}

// entweder malloc arena vergiften oder viel speicher alloziieren und wenig freigeben
unsafe fn mode_prey(mut resolver: LinuxPageMap) -> anyhow::Result<()> {
    libc::mallopt(M_ARENA_MAX, 1);
    libc::mallopt(M_MMAP_THRESHOLD, 1);

    // setup signal handler
    let waiting = Arc::new(AtomicBool::new(true));
    let waiting_sigh = waiting.clone();
    ctrlc::set_handler(move || {
        waiting_sigh.store(false, Ordering::SeqCst);
    })
    .expect("ctrlc setup failed");

    libc::mallopt(M_ARENA_MAX, 1);
    libc::mallopt(M_MMAP_THRESHOLD, 0);

    // wait for signal
    while waiting.load(Ordering::SeqCst) {
        thread::sleep(std::time::Duration::from_millis(1));
    }

    // allocate 500 4K pages
    let mut virt = [std::ptr::null_mut(); PREY_PAGE_COUNT];
    let mut phys = [0_u64; PREY_PAGE_COUNT];

    // allocate pages
    for i in 0..PREY_PAGE_COUNT {
        let v = libc::mmap(
            null_mut(),
            PAGE_LEN,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS,
            -1,
            0,
        );
        //let v = libc::malloc(PAGE_LEN);
        libc::memset(v, 0_i32, PAGE_LEN);
        let p = resolver
            .get_phys(v as u64)
            .context("virt_to_phys failed. Are we root?")?;
        phys[i] = p;
        virt[i] = v;
    }

    // log phys addrs to stdout
    for i in 0..PREY_PAGE_COUNT {
        println!("{}", phys[i]);
    }

    for i in 0..PREY_PAGE_COUNT {
        libc::munmap(virt[i], PAGE_LEN);
    }

    Ok(())
}

unsafe fn _main() -> anyhow::Result<()> {
    let args = CliArgs::parse();

    let resolver = LinuxPageMap::new()?;

    match args.mode {
        BaitMode::Bait => mode_bait(resolver),
        BaitMode::Prey => mode_prey(resolver),
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
