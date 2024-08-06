use anyhow::Context;
use bs_poc::{
    memory::{
        compact_mem, construct_memory_tuple_timer, AllocChecker, ConsecAllocMmap, ConsecAllocator,
        ConsecCheckBankTiming, ConsecCheckPfnBank, DRAMAddr, PfnResolver,
    },
    util::{BlacksmithConfig, MemConfiguration, MB, ROW_SHIFT, ROW_SIZE},
};
use clap::Parser;
use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;
use log::info;
use lpfs::proc::buddyinfo::buddyinfo;

#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config/bs-config.json")]
    config: String,
}

fn main() -> anyhow::Result<()> {
    // wrap logger for indicatif
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let multi = MultiProgress::new();
    LogWrapper::new(multi.clone(), logger).try_init()?;
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    info!("{:?}", mem_config);
    loop {
        compact_mem()?;
        let buddy = buddyinfo().map_err(|e| anyhow::anyhow!("{:?}", e))?;
        if buddy[2].free_areas()[10] == 0 {
            panic!("No 4 MB blocks in normal zone. Goodbye.")
        }
        let checker = ConsecCheckBankTiming::new_with_progress(
            mem_config.clone(),
            construct_memory_tuple_timer()?,
            config.threshold,
            Some(multi.clone()),
        );
        let mut alloc = ConsecAllocMmap::new(Box::new(checker));
        let mut consecs = unsafe { alloc.alloc_consec_blocks(4 * MB, || {}) }?;
        //let block = MemBlock::hugepage(bs_poc::memory::HugepageSize::ONE_GB)?;
        //let block = MemBlock::mmap(4 * MB)?;
        //let mut consecs = ConsecBlocks::new(vec![block]);
        assert_eq!(consecs.blocks.len(), 1);
        let block = consecs.blocks.pop().unwrap();
        let pfn = block.pfn()?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        let row_offsets = mem_config.bank_function_period() as isize / 2;
        let expected_pfn_offset =
            ((pfn as isize & (0x3FFFFF)) - (block.ptr as isize & (0x3FFFFF))) >> ROW_SHIFT;
        let expected_pfn_offset = expected_pfn_offset.rem_euclid(row_offsets);
        println!(
            "0x{:02x},0x{:02x},{},{}",
            block.ptr as usize,
            pfn,
            pfn_offset.map_or("?".to_string(), |x| format!("{}", x)),
            expected_pfn_offset,
        );
        if let Some(pfn_offset) = pfn_offset {
            let mut pfn_checker = ConsecCheckPfnBank::new(mem_config.clone());
            assert!(pfn_checker.check(&block)?, "PFN check failed");
            assert_eq!(pfn_offset, expected_pfn_offset as usize);
            let byte_offset = pfn_offset * ROW_SIZE;
            let byte_offset = byte_offset.rem_euclid(block.len);
            let dramv = DRAMAddr::from_virt_offset(block.ptr, byte_offset as isize, &mem_config);
            let dramp = DRAMAddr::from_virt(block.pfn()? as *const u8, &mem_config);
            info!(
                "VA: 0x{:16x}, {:?} (offset {})",
                block.ptr as usize, dramv, byte_offset
            );
            info!("PA: 0x{:16x}, {:?}", block.pfn()?, dramp);
            assert_eq!(dramv.bank | 0b1, dramp.bank | 0b1);
        }
        block.dealloc();
    }
}
