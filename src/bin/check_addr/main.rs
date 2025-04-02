use anyhow::Result;
use bs_poc::hammerer::blacksmith::blacksmith_config::BlacksmithConfig;
use bs_poc::memory::mem_configuration::MemConfiguration;
use bs_poc::memory::{construct_memory_tuple_timer, BytePointer, MemBlock};
use bs_poc::memory::{DRAMAddr, HugepageSize};
use clap::Parser;

/// Search for a pattern in a file and display the lines that contain it.
#[derive(Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn main() -> Result<()> {
    let args = CliArgs::parse();

    let config = BlacksmithConfig::from_jsonfile(&args.config)?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);

    let memory: MemBlock = MemBlock::hugepage(HugepageSize::OneGb)?;
    let base_msb = memory.ptr();
    println!("base_msb: {:?}", base_msb);

    let start_addr = DRAMAddr::from_virt(base_msb, &mem_config);
    let start_addr_virt = start_addr.to_virt(base_msb, mem_config);

    let timer = construct_memory_tuple_timer()?;

    const THRESH: u64 = 330;

    struct Outliers {
        fast: Vec<DRAMAddr>,
        slow: Vec<DRAMAddr>,
    }
    let mut outliers = Outliers {
        fast: vec![],
        slow: vec![],
    };

    for row in 1..mem_config.get_row_count() {
        let addr = start_addr.add(0, row, 0);
        let addr_virt = addr.to_virt(base_msb, mem_config);
        let time =
            unsafe { timer.time_subsequent_access_from_ram(start_addr_virt, addr_virt, 1000) };
        print!("{:?}, {:?}, {}", start_addr, addr, time);
        if time < THRESH {
            print!(" [FAST]");
            outliers.fast.push(addr.clone());
        }
        println!();
    }

    for bank in 0..mem_config.get_bank_count() {
        let addr = start_addr.add(bank, 0, 0);
        let addr_virt = addr.to_virt(base_msb, mem_config);
        let time =
            unsafe { timer.time_subsequent_access_from_ram(start_addr_virt, addr_virt, 1000) };
        print!("{:?}, {:?}, {}", start_addr, addr, time);
        if time > THRESH {
            print!(" [SLOW]");
            outliers.slow.push(addr.clone());
        }
        println!();
    }

    println!("Too fast: {:?}", outliers.fast);
    println!("Too slow: {:?}", outliers.slow);
    Ok(())
}
