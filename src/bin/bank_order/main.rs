use anyhow::Context;
use bs_poc::hammerer::blacksmith::blacksmith_config::BlacksmithConfig;
use bs_poc::memory::mem_configuration::MemConfiguration;
use bs_poc::{memory::DRAMAddr, util::KB};
use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
struct CliArgs {
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let addr = 0x2000000000 as *mut u8;
    let row_offsets = mem_config.bank_function_period() as usize;
    info!("Row offsets: {}", row_offsets);
    for row_offset in 0..row_offsets {
        let ptr = unsafe { addr.byte_add(row_offset * 8 * KB) };
        let dram = DRAMAddr::from_virt(ptr, &mem_config);
        if row_offset != 0 && row_offset % 256 == 0 {
            println!();
        } else if row_offset != 0 {
            print!(",");
        }
        print!("{:02}", dram.bank);
    }
    Ok(())
}
