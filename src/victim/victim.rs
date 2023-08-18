use anyhow::bail;

use crate::{
    forge::HammerVictim, memory::Memory, RSACRT_ctx_t, RSACRT_init, RSACRT_sign, RSACRT_verify,
};

#[derive(Debug)]
pub struct HammerVictimRsa {
    ctx: *mut RSACRT_ctx_t,
}

impl<'a> HammerVictimRsa {
    pub fn new(memory: &'a Memory) -> anyhow::Result<Self> {
        let (ctx, ret) = unsafe {
            let ctx = memory.addr.add(1337) as *mut RSACRT_ctx_t;
            (ctx, RSACRT_init(ctx))
        };
        if ret != 0 {
            bail!("RSACRT_init");
        }
        Ok(HammerVictimRsa { ctx })
    }
}

impl HammerVictim for HammerVictimRsa {
    fn check(&mut self) -> bool {
        let msg = "hello world";
        let mut sig = std::mem::MaybeUninit::uninit();
        let mut siglen = std::mem::MaybeUninit::uninit();
        let ret = unsafe {
            RSACRT_sign(
                self.ctx,
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                siglen.as_mut_ptr(),
            )
        };
        if ret != 0 {
            return true;
        }
        let ret = unsafe {
            RSACRT_verify(
                self.ctx,
                msg.as_ptr(),
                msg.len(),
                sig.assume_init() as *const u8,
                siglen.assume_init() as usize,
            )
        };
        ret != 1
    }
}
