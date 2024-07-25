use anyhow::Context;
use bs_poc::{
    memory::DRAMAddr,
    util::{BlacksmithConfig, MemConfiguration, KB},
};
use clap::Parser;

#[derive(Parser, Debug)]
struct CliArgs {
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let addr = 0x2000000000 as *mut u8;
    // 1024 rows = 8 MiB
    for row_offset in 0..1024 {
        let ptr = unsafe { addr.add(row_offset * 8 * KB) };
        let dram = DRAMAddr::from_virt(ptr, &mem_config);
        if dram.bank == 0 && row_offset != 0 {
            println!();
        } else if row_offset != 0 {
            print!(",");
        }
        print!("{:02}", dram.bank);
    }
    Ok(())
}
