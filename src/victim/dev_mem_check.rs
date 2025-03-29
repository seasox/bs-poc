use crate::memory::{BitFlip, PfnResolver, PhysAddr};
use crate::util::{PAGE_MASK, PAGE_SIZE};

use super::{HammerVictim, HammerVictimError, VictimResult};
use libc::{
    mmap, munmap, MAP_ANONYMOUS, MAP_FAILED, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE,
};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ptr;

#[derive(Serialize)]
pub struct HammerVictimDevMemCheck {
    #[serde(skip_serializing)]
    targets: Vec<(BitFlip, PhysAddr)>,
}

impl HammerVictimDevMemCheck {
    pub fn new(targets: Vec<BitFlip>) -> anyhow::Result<Self> {
        Ok(HammerVictimDevMemCheck {
            targets: targets
                .into_iter()
                .map(|target| (target.addr as *const u8).pfn().map(|pfn| (target, pfn)))
                .collect::<anyhow::Result<Vec<_>>>()?,
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
        let num_pages = 20;
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

            for (target, _) in &self.targets {
                debug!("munmap target: {:?}", target);
                munmap((target.addr & !(PAGE_MASK)) as *mut libc::c_void, PAGE_SIZE);
            }
            if munmap(addr, length) != 0 {
                return Err(HammerVictimError::IoError(std::io::Error::last_os_error()));
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
