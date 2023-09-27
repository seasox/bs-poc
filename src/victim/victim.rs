use std::ptr::null_mut;

use anyhow::bail;

use crate::{
    forge::HammerVictim, memory::Memory, RSACRT_alloc, RSACRT_check_dmp1,
    RSACRT_check_openssl_version, RSACRT_ctx_t, RSACRT_free_ctx, RSACRT_get_dmp1, RSACRT_init,
    BIGNUM,
};

#[derive(Debug)]
pub struct HammerVictimRsa {
    ctx: *mut RSACRT_ctx_t,
    d: *mut libc::c_ulong,
    exp_dmp1: Option<*const BIGNUM>,
}

impl HammerVictimRsa {
    pub fn new(memory: &Memory, offset: usize) -> anyhow::Result<Self> {
        let check = unsafe { RSACRT_check_openssl_version() };
        if check != 1 {
            bail!("check version");
        }
        let ctx = unsafe {
            let mut ctx: *mut RSACRT_ctx_t = null_mut();
            RSACRT_alloc(&mut ctx);
            ctx
        };
        Ok(HammerVictimRsa {
            ctx,
            d: unsafe { memory.addr.add(offset) as *mut libc::c_ulong },
            exp_dmp1: None,
        })
    }
}

impl HammerVictim for HammerVictimRsa {
    fn init(&mut self) {
        let ret = unsafe {
            let ctx_size = std::mem::size_of::<RSACRT_ctx_t>();
            info!(
                "Put RSA context at address 0x{:02X}..0x{:02X}",
                self.d as usize,
                self.d.add(ctx_size) as usize
            );
            RSACRT_init(self.d, self.ctx)
        };
        if ret != 0 {
            panic!("RSACRT_init");
        }
        unsafe {
            let mut dmp1 = null_mut() as *mut BIGNUM;
            RSACRT_get_dmp1(self.ctx, &mut dmp1 as *mut *mut BIGNUM);
            self.exp_dmp1 = Some(dmp1);
        };
    }

    fn check(&mut self) -> bool {
        //check dmp1 correct
        let ret = unsafe { RSACRT_check_dmp1(self.ctx, self.exp_dmp1.unwrap()) };
        return ret != 0;
        /*
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
                siglen.assume_init(),
            )
        };
        ret != 1
        */
    }
}

impl Drop for HammerVictimRsa {
    fn drop(&mut self) {
        unsafe { RSACRT_free_ctx(self.ctx) };
    }
}
