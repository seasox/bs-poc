# bs_poc

## Blacksmith Proof of Concept

This crate is a proof of concept for an end-to-end blacksmith attack. It includes
several modules that handle different aspects of the attack, such as memory
allocation, hammering, and victim management.

### Quickstart guide

To build the crate on a Linux x86-64 system with `libclang-dev` and Rust installed,
run the following commands:

```sh
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install libclang-dev on Debian-based systems
sudo apt-get update
sudo apt-get install -y libclang-dev

# Build and run the crate
cargo build --release
cargo run --release --bin=hammer
```

This compiles the crate and runs the hammering attack with default options.
The default options assumes that you put the blacksmith configuration file in `config/bs-config.json` and the
blacksmith fuzz summary in `config/fuzz-summary.json`.
You can find the hammer binary at `target/release/hammer`.
Use `target/release/hammer --help` to see available options.

### Modules

- `allocator`: Handles memory allocation for the attack.
- `hammerer`: Contains the logic for performing the Rowhammer attack.
- `memory`: Provides utilities for allocating, managing, and manipulating memory.
- `util`: Contains various utility functions used throughout the crate.
- `victim`: Manages the victim processes and memory regions targeted by the attack.

### External Crates

- `log`: Used for logging throughout the crate.
- `clap`: Used for command-line argument parsing.
- `serde`: Used for serialization and deserialization of configuration files.
- `serde_json`: Provides JSON support for `serde`.
- `libc`: Provides FFI bindings to native C libraries.
- `rand`: Used for random number generation.
- `nix`: Provides idiomatic Rust bindings to Unix system APIs.

### Bindings

The crate includes bindings generated at build time, which are included from
the `OUT_DIR` environment variable.

License: MIT
