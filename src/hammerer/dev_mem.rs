use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

use crate::{
    memory::{FlipDirection, PhysAddr},
    victim::{HammerVictim, HammerVictimError},
};

use super::{HammerResult, Hammering};
pub struct DevMemHammerer {
    phys_addr: PhysAddr,
    bit: usize,
    direction: FlipDirection,
}

impl DevMemHammerer {
    pub fn new(phys_addr: PhysAddr, bit: usize, direction: FlipDirection) -> Self {
        assert!(bit < 8);
        Self {
            phys_addr,
            bit,
            direction,
        }
    }
}

impl Hammering for DevMemHammerer {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult, HammerVictimError> {
        victim.init();
        let mut dev_mem = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
        dev_mem.seek(SeekFrom::Start(self.phys_addr.as_usize() as u64))?;
        let mut value = [0u8; 1];
        dev_mem.read_exact(&mut value)?;
        let new_value = match self.direction {
            FlipDirection::ZeroToOne => [value[0] | (1 << self.bit)],
            FlipDirection::OneToZero | FlipDirection::Any | FlipDirection::Multiple(_) => {
                [value[0] & !(1 << self.bit)]
            }
            FlipDirection::None => unimplemented!("FlipDirection::None"),
        };
        debug!(
            "Flip address 0x{:02X} from {} to {}",
            self.phys_addr, value[0], new_value[0],
        );
        dev_mem.seek(SeekFrom::Start(self.phys_addr.as_usize() as u64))?;
        dev_mem.write_all(&new_value)?;
        dev_mem.flush()?;
        let victim_result = victim.check()?;
        Ok(HammerResult {
            attempt: 0,
            victim_result,
        })
    }
}
