use anyhow::Context;
use bs_poc::{
    memory::{
        construct_memory_tuple_timer, AllocCheckSameBank, AllocChecker, ConsecAllocMmap,
        ConsecAllocator, ConsecCheckPfn, DRAMAddr, PfnResolver,
    },
    util::{BlacksmithConfig, MemConfiguration, MB, ROW_SHIFT, ROW_SIZE},
};
use clap::Parser;
use lpfs::proc::buddyinfo::buddyinfo;

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
    let mut blocks = Vec::new();
    let mut offsets = Vec::new();
    loop {
        let buddy = buddyinfo().map_err(|e| anyhow::anyhow!("{:?}", e))?;
        if buddy[2].free_areas()[10] == 0 {
            panic!("No 4 MB blocks in normal zone. Goodbye.")
        }
        let mut consecs = unsafe { alloc.alloc_consec_blocks(4 * MB, &|| {}) }?;
        assert_eq!(consecs.blocks.len(), 1);
        let block = consecs.blocks.pop().unwrap();
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
                blocks.push(block);
                offsets.push(pfn_offset);
                if blocks.len() == 2 {
                    let block1 = blocks.pop().unwrap();
                    let block2 = blocks.pop().unwrap();
                    let offset1 = 256 - offsets.pop().unwrap();
                    let offset2 = 256 - offsets.pop().unwrap();
                    let block1 = block1.byte_add(offset1 * ROW_SIZE);
                    let block2 = block2.byte_add(offset2 * ROW_SIZE);
                    //let block2 = block1.byte_add(2 * MB);
                    println!("Block1 aligned PFN: 0x{:02x}", block1.pfn()?);
                    let vaddr = DRAMAddr::from_virt(block1.ptr, &mem_config);
                    let paddr = DRAMAddr::from_virt(block1.pfn()? as *const u8, &mem_config);
                    println!("VA: {:?}", vaddr);
                    println!("PA: {:?}", paddr);
                    println!("Block2 aligned PFN: 0x{:02x}", block2.pfn()?);
                    let vaddr = DRAMAddr::from_virt(block2.ptr, &mem_config);
                    let paddr = DRAMAddr::from_virt(block2.pfn()? as *const u8, &mem_config);
                    println!("VA: {:?}", vaddr);
                    println!("PA: {:?}", paddr);
                    let timer = construct_memory_tuple_timer()?;
                    let time = unsafe {
                        timer.time_subsequent_access_from_ram(block1.ptr, block2.ptr, 10000)
                    };
                    println!("Time: {}", time);
                    let mut bank_check = AllocCheckSameBank::new(
                        mem_config,
                        config.threshold,
                        construct_memory_tuple_timer()?,
                    );
                    _ = bank_check.check(&block1)?;
                    let success = bank_check.check(&block2)?;
                    println!("Bank Check: {}", success);
                }
            }
            None => {
                println!(
                    "0x{:02x},0x{:02x},?,{}",
                    block.ptr as usize, pfn, expected_pfn_offset
                );
                block.dealloc();
            }
        }
    }
}
