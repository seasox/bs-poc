#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

pub mod forge;
pub mod jitter;
pub mod memory;
pub mod util;
pub mod victim;

#[macro_use]
extern crate log;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(test)]
mod tests {

    use crate::*;

    #[test]
    fn rsa_crt_sign_verify() {
        unsafe {
            let ctx = libc::malloc(16 * std::mem::size_of::<BN_ULONG>()) as *mut BN_ULONG;
            let ctx = libc::malloc(std::mem::size_of::<RSACRT_ctx_t>()) as *mut RSACRT_ctx_t;
            let ret = RSACRT_init(ctx);
            assert_eq!(ret, 0);
            assert_ne!((*ctx).sk, std::ptr::null_mut());
            let msg = "hello world".to_string();
            let mut sig = std::mem::MaybeUninit::uninit();
            let mut siglen = std::mem::MaybeUninit::uninit();
            let ret = RSACRT_sign(
                ctx,
                msg.as_ptr(),
                msg.len(),
                sig.as_mut_ptr(),
                siglen.as_mut_ptr(),
            );
            assert_eq!(ret, 0);
            assert_ne!(siglen.assume_init(), 0);
            let sig = Vec::from_raw_parts(
                sig.assume_init(),
                siglen.assume_init(),
                siglen.assume_init(),
            );
            assert!(!sig.is_empty());
            let ret = RSACRT_verify(
                ctx,
                msg.as_ptr(),
                msg.len(),
                sig.as_ptr(),
                siglen.assume_init(),
            );
            assert_eq!(ret, 1);
        }
    }
}
