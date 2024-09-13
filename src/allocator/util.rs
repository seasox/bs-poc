use std::process::Command;

use anyhow::bail;

pub fn compact_mem() -> anyhow::Result<()> {
    let output = Command::new("sh")
        .arg("-c")
        .arg("echo 1 | tee /proc/sys/vm/compact_memory")
        .output()?;
    if !output.status.success() {
        bail!("Failed to compact memory. Are we root?");
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg("echo 0 | tee /proc/sys/kernel/randomize_va_space")
        .output()?;
    if !output.status.success() {
        bail!("Failed to disable ASLR. Are we root?");
    }
    Ok(())
}

pub fn mmap<P>(addr: *mut libc::c_void, len: usize) -> *mut P {
    use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_SHARED, PROT_READ, PROT_WRITE};

    let v = unsafe {
        libc::mmap(
            addr,
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
            -1,
            0,
        )
    };
    assert_ne!(
        v,
        libc::MAP_FAILED,
        "mmap: {}",
        std::io::Error::last_os_error()
    );
    unsafe { libc::memset(v, 0x11, len) };
    v as *mut P
}

pub fn munmap<P>(addr: *mut P, len: usize) {
    let r = unsafe { libc::munmap(addr as *mut libc::c_void, len) };
    assert_eq!(r, 0, "munmap: {}", std::io::Error::last_os_error());
}
