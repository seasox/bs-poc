use crate::memory::{BitFlip, PfnResolver, PhysAddr, VictimMemory};
use crate::util::{CL_SIZE, PAGE_MASK, PAGE_SIZE};

use super::{HammerVictim, HammerVictimError, VictimResult};
use libc::{
    mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE,
};
use std::arch::x86_64::_mm_clflush;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ptr;

pub struct HammerVictimDevMemCheck {
    targets: Vec<(BitFlip, PhysAddr)>,
    flush_lines: Vec<usize>,
}

impl HammerVictimDevMemCheck {
    pub fn new(
        targets: Vec<BitFlip>,
        memory: &dyn VictimMemory,
        flush_before_check: bool,
    ) -> anyhow::Result<Self> {
        let flush_lines = if flush_before_check {
            let mut flush_lines = vec![];
            let flip_pages = targets
                .iter()
                .map(|f| f.addr & !(PAGE_MASK))
                .collect::<Vec<_>>();
            for offset in (0..memory.len()).step_by(CL_SIZE) {
                let line = memory.addr(offset) as usize;
                let page = line & !(PAGE_MASK);
                if !flip_pages.contains(&page) {
                    flush_lines.push(line);
                }
            }
            flush_lines
        } else {
            vec![]
        };
        Ok(HammerVictimDevMemCheck {
            targets: targets
                .into_iter()
                .map(|target| (target.addr as *const u8).pfn().map(|pfn| (target, pfn)))
                .collect::<anyhow::Result<Vec<_>>>()?,
            flush_lines,
        })
    }
}

fn write_dev_mem(addr: PhysAddr, value: u8) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).open("/dev/mem")?;
    file.seek(SeekFrom::Start(addr.as_usize() as u64))?;
    file.write_all(&[value])?;
    Ok(())
}

fn read_dev_mem(addr: PhysAddr) -> Result<u8, std::io::Error> {
    let mut file = File::open("/dev/mem")?;
    file.seek(SeekFrom::Start(addr.as_usize() as u64))?;
    let mut buffer = [0u8; 1];
    file.read_exact(&mut buffer)?;
    Ok(buffer[0])
}

impl HammerVictim for HammerVictimDevMemCheck {
    fn start(&mut self) -> Result<(), HammerVictimError> {
        let num_pages = 50;
        let length = PAGE_SIZE * num_pages;

        unsafe {
            let addr = mmap(
                ptr::null_mut(),
                length,
                PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_POPULATE | MAP_ANONYMOUS,
                -1,
                0,
            );

            if addr == MAP_FAILED {
                return Err(HammerVictimError::IoError(std::io::Error::last_os_error()));
            }

            if munmap(addr, length) != 0 {
                return Err(HammerVictimError::IoError(std::io::Error::last_os_error()));
            }

            for (target, _) in &self.targets {
                munmap(
                    (target.addr & !(PAGE_SIZE - 1)) as *mut libc::c_void,
                    PAGE_SIZE,
                );
            }
        }
        Ok(())
    }

    fn init(&mut self) {
        for (target, phys_addr) in &self.targets {
            write_dev_mem(*phys_addr, target.data).expect("Write failed");
            let byte = read_dev_mem(*phys_addr).unwrap();
            assert_eq!(byte, target.data, "Target byte is not as expected");
        }
    }

    fn check(&mut self) -> Result<VictimResult, HammerVictimError> {
        // flush all pages
        for page in self.flush_lines.iter() {
            unsafe { _mm_clflush(*page as *const u8) };
        }
        let flips = self
            .targets
            .iter()
            .filter_map(|(target, phys_addr)| {
                let byte = read_dev_mem(*phys_addr)
                    .map_err(HammerVictimError::IoError)
                    .expect("/dev/mem read failed");

                if byte != target.data {
                    // if actual value is not equal to the expected value
                    Some(BitFlip::new(
                        (*phys_addr).into(),
                        byte ^ target.data,
                        target.data,
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        if flips.is_empty() {
            Err(HammerVictimError::NoFlips)
        } else {
            Ok(VictimResult::BitFlips(flips))
        }
    }

    fn stop(&mut self) {}
}
