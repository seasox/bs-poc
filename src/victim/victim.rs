use std::ptr::null_mut;

use anyhow::bail;

use crate::{
    forge::HammerVictim, memory::Memory, RSACRT_alloc, RSACRT_check_openssl_version, RSACRT_ctx_t,
    RSACRT_free_ctx, RSACRT_init, RSACRT_sign, RSACRT_verify,
};

#[derive(Debug)]
pub struct HammerVictimRsa {
    ctx: *mut RSACRT_ctx_t,
}

impl<'a> HammerVictimRsa {
    pub fn new(memory: &'a Memory, offset: usize) -> anyhow::Result<Self> {
        let check = unsafe { RSACRT_check_openssl_version() };
        if check != 1 {
            bail!("check version");
        }
        let (ctx, ret) = unsafe {
            let d = memory.addr.add(offset) as *mut libc::c_ulong;
            let mut ctx: *mut RSACRT_ctx_t = null_mut();
            RSACRT_alloc(&mut ctx);

            (ctx, RSACRT_init(d, ctx))
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
        if ret != 1 {
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

impl Drop for HammerVictimRsa {
    fn drop(&mut self) {
        unsafe { RSACRT_free_ctx(self.ctx) };
    }
}
