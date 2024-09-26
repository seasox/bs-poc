use crate::hammerer::HammerResult;
use crate::hammerer::Hammering;
use crate::victim::HammerVictim;
use anyhow::bail;
use std::arch::x86_64::_mm_clflush;

pub struct Hammerer {
    flip_addr: *mut u8,
}

impl Hammerer {
    pub fn new(flip_addr: *mut u8) -> Self {
        Hammerer { flip_addr }
    }
}

impl Hammering for Hammerer {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> anyhow::Result<HammerResult> {
        victim.init();
        unsafe {
            debug!(
                "Flip address 0x{:02X} from {} to {}",
                self.flip_addr as usize, *self.flip_addr, !*self.flip_addr
            );
            *self.flip_addr = !*self.flip_addr;
            _mm_clflush(self.flip_addr);
        }
        let result = victim.check();
        if result {
            return Ok(HammerResult { run: 0, attempt: 0 });
        }
        bail!("Hammering not successful")
    }
}
