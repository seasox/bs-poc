use anyhow::bail;
use libc::{
    close, shm_open, MAP_POPULATE, MAP_SHARED, O_CREAT, O_RDWR, PROT_READ, PROT_WRITE, S_IRUSR,
    S_IWUSR,
};
use std::{
    cmp::min,
    ffi::CString,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{sleep, spawn, JoinHandle},
    time::Duration,
};

use crate::{
    memory::{BytePointer, MemBlock},
    util::ROW_SIZE,
};

pub(crate) fn compact_mem() -> anyhow::Result<()> {
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

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub(crate) fn mmap_shm<P>(addr: *mut libc::c_void, len: usize, name: String) -> *mut P {
    unsafe {
        let name = CString::new(name).expect("CString");
        let shm = shm_open(name.as_ptr(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if shm == -1 {
            panic!("shm_open: {}", std::io::Error::last_os_error());
        }
        if libc::ftruncate(shm, len as libc::off_t) == -1 {
            panic!("ftruncate: {}", std::io::Error::last_os_error());
        }

        let v = libc::mmap(
            addr,
            len,
            PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE,
            shm,
            0,
        );
        assert_ne!(
            v,
            libc::MAP_FAILED,
            "mmap: {}",
            std::io::Error::last_os_error()
        );
        close(shm);
        if !addr.is_null() && addr != v {
            panic!(
                "mmap returned unexpected address: {:x} != {:x}",
                addr as usize, v as usize
            );
        }
        libc::memset(v, 0xAA, len);
        v as *mut P
    }
}
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn mmap<P>(addr: *mut libc::c_void, len: usize) -> *mut P {
    use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_PRIVATE, PROT_READ, PROT_WRITE};

    let v = unsafe {
        libc::mmap(
            addr,
            len,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE,
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

/// Unmap memory
///
/// # Safety
/// * `addr` must be a valid pointer to a memory region previously allocated by `mmap`
/// * `len` must be less than or equal the length as the memory region previously allocated by `mmap`
pub unsafe fn munmap<P>(addr: *mut P, len: usize) {
    let r = libc::munmap(addr as *mut libc::c_void, len);
    assert_eq!(
        r,
        0,
        "munmap({:x}, {}): {}",
        addr as usize,
        len,
        std::io::Error::last_os_error()
    );
}

/// Spawn a thread that periodically writes 0s to the allocated memory blocks.
/// This is used to lock the memory in RAM, preventing it from being swapped out.
pub(super) fn spawn_page_locking_thread(
    blocks: Arc<Mutex<Vec<MemBlock>>>,
    mem_lock: Arc<Mutex<()>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    spawn(move || {
        info!(target: "loader", "Loader thread started");
        while !stop.load(Ordering::Relaxed) {
            let blocks = blocks.lock().unwrap().clone();
            for block in blocks {
                for offset in (0..block.len).step_by(ROW_SIZE) {
                    let addr = block.addr(offset);
                    let count = min(ROW_SIZE, block.len - offset);
                    trace!(target: "loader", "Waiting for memory lock");
                    let mem_lock = mem_lock.lock().unwrap();
                    unsafe { std::ptr::write_bytes(addr, 0, count) };
                    drop(mem_lock);
                }
            }
            sleep(Duration::from_millis(100));
        }
        info!(target: "loader", "Stopping loader thread");
    })
}
