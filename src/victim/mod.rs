pub mod mem_check;

pub use self::mem_check::*;

pub trait HammerVictim {
    fn init(&mut self) {}
    /// returns true if flip was successful
    fn check(&mut self) -> bool;
    fn log_report(&self) {}
}
