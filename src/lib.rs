//! # Swage
//!
//! Swage is a modular framework for end-to-end Rowhammer attacks. It includes
//! several modules that handle different aspects of the attack, such as memory
//! allocation, hammering, and victim management.
//!
//! ## Quickstart guide
//!
//! To build the crate on a Linux x86-64 system with `libclang-dev` and Rust installed,
//! run the following commands:
//!
//! ```sh
//! # Install Rust using rustup
//! curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
//!
//! # Install libclang-dev on Debian-based systems
//! sudo apt-get update
//! sudo apt-get install -y libclang-dev
//!
//! # Build and run the crate
//! cargo build --release
//! cargo run --release --bin=hammer
//!```
//!
//! This compiles the crate and runs the hammering attack with default options.
//! The default options assumes that you use blacksmith as hammerer, put a
//! blacksmith configuration file in `config/bs-config.json` and the
//! blacksmith fuzz summary in `config/fuzz-summary.json`.
//! After a successful compilation, the hammer binary is located at
//! `target/release/hammer`. Use `target/release/hammer --help` to see
//! available options.
//!
//! ## Modules
//!
//! - `allocator`: Handles memory allocation for the attack.
//! - `hammerer`: Contains the logic for performing the Rowhammer attack.
//! - `memory`: Provides utilities for allocating, managing, and manipulating memory.
//! - `util`: Contains various utility functions used throughout the crate.
//! - `victim`: Manages the victim processes and memory regions targeted by the attack.
//!
//! ## External Crates
//!
//! - `log`: Used for logging throughout the crate.
//!
//! ## Bindings
//!
//! The crate includes bindings generated at build time, which are included from
//! the `OUT_DIR` environment variable.
pub mod allocator;
pub mod hammerer;
pub mod memory;
pub mod util;
pub mod victim;

#[macro_use]
extern crate log;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
