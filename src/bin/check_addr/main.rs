use anyhow::Result;
use bs_poc::memory::construct_memory_tuple_timer;
use bs_poc::memory::{DRAMAddr, Memory};
use clap::Parser;
use iced_x86::OpCodeOperandKind::mem;
use libc::c_void;
use std::ptr;

use bs_poc::util::{BlacksmithConfig, MemConfiguration};

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn main() -> Result<()> {
    const MEM_SIZE: usize = 1 << 30; // 1 GB

    let args = CliArgs::parse();

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    let mut memory = Memory::new();
    memory.alloc(MEM_SIZE)?;
    let base_msb = memory
        .addr
        .expect("no base address. Was allocation successful?") as *const c_void;
    println!("base_msb: {:?}", base_msb);

    let start_addr = DRAMAddr::default();
    let start_addr_virt = start_addr.to_virt(base_msb, mem_config);

    let timer = construct_memory_tuple_timer()?;

    const THRESH: u64 = 330;

    for row in 1..mem_config.get_row_count() {
        let addr = start_addr.add(0, row, 0);
        let addr_virt = addr.to_virt(base_msb, mem_config);
        let time = unsafe {
            timer.time_subsequent_access_from_ram(
                start_addr_virt as *const u8,
                addr_virt as *const u8,
                1000,
            )
        };
        if time < THRESH {
            panic!("too fast!");
        }
        println!("{:?}, {:?}, {}", start_addr, addr, time);
    }

    for bank in 0..mem_config.get_bank_count() {
        let addr = start_addr.add(bank, 0, 0);
        let addr_virt = addr.to_virt(base_msb, mem_config);
        let time = unsafe {
            timer.time_subsequent_access_from_ram(
                start_addr_virt as *const u8,
                addr_virt as *const u8,
                1000,
            )
        };
        if time > THRESH {
            panic!("too slow!");
        }
        println!("{:?}, {:?}, {}", start_addr, addr, time);
    }

    Ok(())
}
