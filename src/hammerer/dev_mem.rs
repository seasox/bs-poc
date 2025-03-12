use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

use crate::victim::{HammerVictim, HammerVictimError};

use super::{HammerResult, Hammering};

pub struct DevMemHammerer {
    phys_addr: u64,
    bit: usize,
}

impl DevMemHammerer {
    pub fn new(phys_addr: u64, bit: usize) -> Self {
        assert!(bit < 8);
        Self { phys_addr, bit }
    }
}

impl Hammering for DevMemHammerer {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult, HammerVictimError> {
        victim.init();
        let mut dev_mem = OpenOptions::new().read(true).write(true).open("/dev/mem")?;
        dev_mem.seek(SeekFrom::Start(self.phys_addr))?;
        let mut value = [0u8; 1];
        dev_mem.read_exact(&mut value)?;
        debug!(
            "Flip address 0x{:02X} from {} to {}",
            self.phys_addr,
            value[0],
            value[0] ^ (1 << self.bit)
        );
        value[0] ^= 1 << self.bit;
        dev_mem.seek(SeekFrom::Start(self.phys_addr))?;
        dev_mem.write_all(&value)?;
        dev_mem.flush()?;
        let victim_result = victim.check()?;
        Ok(HammerResult {
            attempt: 0,
            victim_result,
        })
    }
}
