use std::io::{BufRead, BufReader, Read, Write};

pub trait IPC<T: Eq + std::fmt::Debug, U: Eq + std::fmt::Debug> {
    fn send(&mut self, msg: T) -> Result<(), std::io::Error>;
    fn receive(&mut self) -> Result<U, std::io::Error>;
    fn wait_for(&mut self, msg: U) -> Result<U, std::io::Error> {
        debug!("Waiting for message {:?}", msg);
        let r = self.receive()?;
        if r != msg {
            error!("Expected message {:?}, got {:?}", msg, r);
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Expected message {:?}, got {:?}", msg, r),
            ));
        }
        debug!("Received message {:?}", r);
        Ok(r)
    }
}

pub struct PipeIPC<R: Read, W: Write> {
    input: R,
    output: W,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
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
    fn send(&mut self, msg: u8) -> Result<(), std::io::Error> {
        debug!("Sending message {:?}", msg);
        let nbytes = self.output.write(&[msg])?;
        if nbytes != 1 {
            error!("Failed to write message {:?}. Wrote {} bytes", msg, nbytes);
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!("Failed to write message {:?}. Wrote {} bytes", msg, nbytes),
            ));
        }
        debug!("Sent message {:?}", msg);
        self.output.flush()?;
        Ok(())
    }
    fn receive(&mut self) -> Result<String, std::io::Error> {
        debug!("Receiving message");
        let mut reader = BufReader::new(&mut self.input);
        let mut line = String::new();
        let bytes_read = reader.read_line(&mut line)?;
        debug!("Received message '{:?}'", line);
        if bytes_read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Zero bytes read",
            ));
        }
        // Remove the trailing newline character if it exists.
        if !line.ends_with('\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "No newline character found",
            ));
        }
        line.pop();
        Ok(line)
    }
}

impl<R: Read, W: Write> IPC<AttackState, AttackState> for PipeIPC<R, W> {
    fn send(&mut self, msg: AttackState) -> Result<(), std::io::Error> {
        debug!("Sending message {:?}", msg);
        let nbytes = self.output.write(&[msg as u8])?;
        if nbytes != 1 {
            error!("Failed to write message {:?}. Wrote {} bytes", msg, nbytes);
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                format!("Failed to write message {:?}. Wrote {} bytes", msg, nbytes),
            ));
        }
        debug!("Sent message {:?}", msg);
        self.output.flush()?;
        Ok(())
    }
    fn receive(&mut self) -> Result<AttackState, std::io::Error> {
        debug!("Receiving message");
        let mut buf = [0u8; 1];
        let nbytes = self.input.read(&mut buf)?;
        if nbytes != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read message",
            ));
        }
        debug!("Received message {:?}", buf);
        AttackState::try_from(buf[0])
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
    }
}
