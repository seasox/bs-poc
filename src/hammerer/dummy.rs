use crate::hammerer::HammerResult;
use crate::hammerer::Hammering;
use crate::victim::HammerVictim;
use crate::victim::HammerVictimError;
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
    fn hammer<T>(
        &self,
        victim: &mut dyn HammerVictim<T>,
    ) -> Result<HammerResult<T>, HammerVictimError> {
        victim.init();
        unsafe {
            debug!(
                "Flip address 0x{:02X} from {} to {}",
                self.flip_addr as usize, *self.flip_addr, !*self.flip_addr
            );
            *self.flip_addr = !*self.flip_addr;
            _mm_clflush(self.flip_addr);
        }
        let victim_result = victim.check()?;
        Ok(HammerResult {
            attempt: 0,
            victim_result,
        })
    }
}
