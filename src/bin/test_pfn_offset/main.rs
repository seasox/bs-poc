use anyhow::Context;
use bs_poc::{
    memory::{
        construct_memory_tuple_timer, ConsecAllocMmap, ConsecAllocator, ConsecCheckPfn, PfnResolver,
    },
    util::{BlacksmithConfig, MemConfiguration, MB, ROW_SHIFT},
};
use clap::Parser;

#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    println!("{:?}", mem_config);
    let mut alloc = ConsecAllocMmap::new(Box::new(ConsecCheckPfn {}));
    loop {
        let block = unsafe { alloc.alloc_consec_blocks(4 * MB, &|| {}) }?;
        assert_eq!(block.blocks.len(), 1);
        let block = block.blocks[0];
        let pfn = block.pfn()?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        let row_offsets = (1 << (mem_config.max_bank_bit - ROW_SHIFT as u64)) as u64;
        let expected_pfn_offset =
            (((pfn & (0x3FFFFF)) - (block.ptr as u64 & (0x3FFFFF))) >> ROW_SHIFT) % row_offsets;
        match pfn_offset {
            Some(pfn_offset) => {
                println!(
                    "0x{:02x},0x{:02x},{},{}",
                    block.ptr as usize, pfn, pfn_offset, expected_pfn_offset,
                );
            }
            None => {
                println!(
                    "0x{:02x},0x{:02x},?,{}",
                    block.ptr as usize, pfn, expected_pfn_offset
                );
            }
        }
        block.dealloc();
    }
}
