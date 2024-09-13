pub mod mem_check;
pub mod process;

pub use self::mem_check::HammerVictimMemCheck as MemCheck;
pub use self::process::VictimProcess as Process;

pub trait HammerVictim {
    fn init(&mut self) {}
    /// returns true if flip was successful
    fn check(&mut self) -> bool;
    fn log_report(&self) {}
}
