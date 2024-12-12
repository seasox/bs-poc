use std::io::{BufRead, BufReader, Read, Write};

use anyhow::bail;

use super::Anyhow;

pub trait IPC<T: Eq + std::fmt::Debug, U: Eq + std::fmt::Debug> {
    fn send(&mut self, msg: T) -> anyhow::Result<()>;
    fn receive(&mut self) -> anyhow::Result<U>;
    fn wait_for(&mut self, msg: U) -> anyhow::Result<U> {
        debug!("Waiting for message {:?}", msg);
        let r = self.receive()?;
        if r != msg {
            bail!("Expected message {:?}, got {:?}", msg, r);
        }
        debug!("Received message {:?}", r);
        Ok(r)
    }
}

pub struct PipeIPC<R: Read, W: Write> {
    input: R,
    output: W,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AttackState {
    AttackerReady = 1,
    VictimAllocReady = 2,
    VictimWaitHammer = 3,
    AttackerHammerDone = 4,
    VictimHammerSuccess = 5,
    VictimHammerFailed = 6,
}

impl TryFrom<u8> for AttackState {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(AttackState::AttackerReady),
            2 => Ok(AttackState::VictimAllocReady),
            3 => Ok(AttackState::VictimWaitHammer),
            4 => Ok(AttackState::AttackerHammerDone),
            5 => Ok(AttackState::VictimHammerSuccess),
            6 => Ok(AttackState::VictimHammerFailed),
            _ => Err(value),
        }
    }
}

impl<R: Read, W: Write> PipeIPC<R, W> {
    pub fn new(input: R, output: W) -> Self {
        Self { input, output }
    }
}

impl<R: Read, W: Write> IPC<u8, String> for PipeIPC<R, W> {
    fn send(&mut self, msg: u8) -> anyhow::Result<()> {
        debug!("Sending message {:?}", msg);
        let success = self.output.write(&[msg]);
        match success {
            Ok(nbytes) => {
                if nbytes != 1 {
                    bail!("write failed: wrote {} bytes", nbytes);
                }
                self.output.flush()?;
                Ok(())
            }
            Err(e) => bail!("write failed: {:?}", e),
        }
    }
    fn receive(&mut self) -> anyhow::Result<String> {
        let mut reader = BufReader::new(&mut self.input);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        if bytes_read == 0 {
            bail!("EOF reached");
        }
        // Remove the trailing newline character if it exists.
        if !line.ends_with('\n') {
            bail!("line does not end with newline");
        }
        line.pop();
        Ok(line)
    }
}

impl<R: Read, W: Write> IPC<AttackState, AttackState> for PipeIPC<R, W> {
    fn send(&mut self, msg: AttackState) -> anyhow::Result<()> {
        let success = self.output.write(&[msg as u8]);
        match success {
            Ok(nbytes) => {
                if nbytes != 1 {
                    bail!("write failed: wrote {} bytes", nbytes);
                }
                self.output.flush()?;
                Ok(())
            }
            Err(e) => bail!("write failed: {:?}", e),
        }
    }
    fn receive(&mut self) -> anyhow::Result<AttackState> {
        let mut buf = [0u8; 1];
        let success = self.input.read(&mut buf);
        if success.is_err() {
            bail!("read failed: {:?}", success.err().unwrap());
        }
        AttackState::try_from(buf[0]).anyhow()
    }
}

/*
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
*/
