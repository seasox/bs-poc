use std::ptr::null_mut;

use anyhow::{bail, Context};

use crate::{
    forge::BitFlip, memory::VictimMemory, util::MemConfiguration, RSACRT_alloc, RSACRT_check_dmp1,
    RSACRT_check_openssl_version, RSACRT_ctx_t, RSACRT_free_ctx, RSACRT_get_dmp1, RSACRT_init,
    BIGNUM,
};

pub trait HammerVictim {
    fn init(&mut self) {}
    /// returns true if flip was successful
    fn check(&mut self) -> bool;
    fn log_report(&self) {}
}

#[derive(Debug)]
pub struct HammerVictimRsa {
    ctx: *mut RSACRT_ctx_t,
    d: *mut libc::c_ulong,
    exp_dmp1: Option<*const BIGNUM>,
}

impl HammerVictimRsa {
    pub fn new(memory: &dyn VictimMemory, offset: usize) -> anyhow::Result<Self> {
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
            d: memory.addr(offset) as *mut libc::c_ulong,
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

pub struct HammerVictimMemCheck<'a> {
    mem_config: MemConfiguration,
    memory: &'a dyn VictimMemory,
    seed: Option<[u8; 32]>,
    flips: Vec<BitFlip>,
}

impl<'a> HammerVictimMemCheck<'a> {
    pub fn new(mem_config: MemConfiguration, memory: &'a dyn VictimMemory) -> Self {
        HammerVictimMemCheck {
            mem_config,
            memory,
            seed: None,
            flips: vec![],
        }
    }
}

impl<'a> HammerVictim for HammerVictimMemCheck<'a> {
    fn init(&mut self) {
        let seed = rand::random();
        self.memory.initialize(seed);
        self.seed = Some(seed);
    }

    fn check(&mut self) -> bool {
        self.flips = self.memory.check(
            self.mem_config,
            self.seed.with_context(|| "no seed").unwrap(),
        );
        !self.flips.is_empty()
    }

    fn log_report(&self) {
        let virt_addrs: Vec<String> = self
            .flips
            .iter()
            .map(|bf| {
                format!(
                    "{:?}",
                    bf.dram_addr,
                    //bf.dram_addr.to_virt(base_msb, self.mem_config) as usize
                )
            })
            .collect();
        info!("Addresses with flips: {:?}", virt_addrs);
    }
}
