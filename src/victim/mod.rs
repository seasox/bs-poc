//! This module contains the victim implementations for the hammer attack.
//!
//! A victim is the target of the Rowhammer attack. It can be a memory region or a process. To probe memory regions, the `MemCheck` victim is used. To probe a victim process, the `Process` victim is used.
pub mod mem_check;
pub mod process;

pub use self::mem_check::HammerVictimMemCheck as MemCheck;
pub use self::process::VictimProcess as Process;

/// The HammerVictim trait. A victim must implement this trait to be used as a target for the hammer attack.
///
/// The trait provides methods to initialize the victim, check if the hammering was successful, and log the report.
///
pub trait HammerVictim<T> {
    /// Initialize the victim. This method is called before the hammering starts.
    fn init(&mut self) {}
    /// Check if the hammering was successful. Returns Some with an optional string describing the result if the hammering was successful, None otherwise.
    fn check(&mut self) -> Option<T>;
    /// Log the report of the hammering (optional).
    fn log_report(&self) {}
    /// Stop the victim. This method is called after the hammering is done. This consumes the victim.
    fn stop(self);
}
