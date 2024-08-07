use std::{
    ffi::CString,
    io::{Read, Write},
};

use anyhow::bail;
use libc::{c_int, shm_open, O_APPEND, O_CREAT, O_RDWR, O_TRUNC, S_IRUSR, S_IWUSR};

pub trait IPC<T: Eq> {
    fn close(self) -> anyhow::Result<()>;
    fn send(&mut self, msg: T) -> anyhow::Result<()>;
    fn receive(&mut self) -> anyhow::Result<T>;
    fn wait_for(&mut self, msg: T) -> anyhow::Result<T> {
        let mut r = self.receive()?;
        while r != msg {
            r = self.receive()?;
        }
        assert!(r == msg);
        Ok(r)
    }
}

pub struct PipeIPC<R: Read, W: Write> {
    input: R,
    output: W,
}

pub const ATTACKER_READY: u8 = 1;
pub const VICTIM_ALLOC_READY: u8 = 2;
pub const VICTIM_ALLOC_DONE: u8 = 3;

impl<R: Read, W: Write> PipeIPC<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output }
    }
}

impl<R: Read, W: Write> IPC<u8> for PipeIPC<R, W> {
    fn send(&mut self, msg: u8) -> anyhow::Result<()> {
        let success = self.output.write(&[msg]);
        if success.is_err() {
            bail!("write failed: {:?}", success.err().unwrap());
        }
        Ok(())
    }
    fn receive(&mut self) -> anyhow::Result<u8> {
        let mut buf = [0u8; 1];
        let success = self.input.read(&mut buf);
        if success.is_err() {
            bail!("read failed: {:?}", success.err().unwrap());
        }
        Ok(buf[0])
    }
    fn close(self) -> anyhow::Result<()> {
        Ok(())
    }
}

pub struct SharedMemIPC {
    name: CString,
    fd: i32,
}

impl SharedMemIPC {
    pub const ATTACKER_READY: i8 = 1;
    pub const VICTIM_ALLOC_READY: i8 = 2;
    pub const VICTIM_ALLOC_DONE: i8 = 3;

    pub fn create(name: String) -> anyhow::Result<Self> {
        Self::open_with_flags(name, O_CREAT | O_RDWR | O_TRUNC | O_APPEND)
    }

    pub fn open(name: String) -> anyhow::Result<Self> {
        Self::open_with_flags(name, O_RDWR | O_APPEND)
    }

    fn open_with_flags(name: String, flags: c_int) -> anyhow::Result<Self> {
        let name = CString::new(name)?;
        let fd = unsafe { shm_open(name.as_ptr(), flags, S_IRUSR | S_IWUSR) };
        if fd <= 0 {
            bail!("shm_open failed: {:?}", std::io::Error::last_os_error());
        }
        Ok(Self { name, fd })
    }
}

impl IPC<i8> for SharedMemIPC {
    fn send(&mut self, msg: i8) -> anyhow::Result<()> {
        const MSG_SIZE: usize = std::mem::size_of::<i8>();
        let success = unsafe {
            libc::write(
                self.fd,
                &msg as *const i8 as *const libc::c_void,
                std::mem::size_of::<i8>(),
            )
        };
        if success != MSG_SIZE as isize {
            bail!("write failed: {:?}", std::io::Error::last_os_error());
        }
        Ok(())
    }
    fn receive(&mut self) -> anyhow::Result<i8> {
        const MSG_SIZE: usize = std::mem::size_of::<i8>();
        let mut msg = 0;
        let msg_ptr = &mut msg as *mut i8;
        let mut nread = 0;
        while nread < MSG_SIZE {
            unsafe {
                let p = msg_ptr.byte_add(nread);
                let n = libc::read(self.fd, p as *mut libc::c_void, 1);
                if n < 0 {
                    bail!("read failed: {:?}", std::io::Error::last_os_error());
                }
                nread += n as usize;
            }
        }
        Ok(msg)
    }
    fn close(self) -> anyhow::Result<()> {
        let success = unsafe { libc::shm_unlink(self.name.as_ptr()) };
        if success != 0 {
            bail!("shm_unlink failed: {:?}", std::io::Error::last_os_error());
        }
        let success = unsafe { libc::close(self.fd) };
        if success != 0 {
            bail!("close failed: {:?}", std::io::Error::last_os_error());
        }
        Ok(())
    }
}
