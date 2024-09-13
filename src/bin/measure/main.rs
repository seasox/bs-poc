use std::ptr::null_mut;

use anyhow::{bail, Context};
use bs_poc::{
    memory::{
        construct_memory_tuple_timer, AllocChecker, BytePointer, ConsecCheckPfn, DRAMAddr,
        MemBlock, PfnResolver,
    },
    util::{BlacksmithConfig, MemConfiguration, MB, ROW_SIZE},
};
use clap::Parser;
use log::info;

#[derive(Parser, Debug)]
struct CliArgs {
    #[clap(long = "row1")]
    row1: usize,
    #[clap(long = "row2")]
    row2: usize,
    #[clap(long = "config", default_value = "config.json")]
    config: String,
    #[clap(long = "use_hugepage", action)]
    use_hugepage: bool,
}

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    let timer = construct_memory_tuple_timer()?;
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let mem = if args.use_hugepage {
        alloc_1g_hugepage()?
    } else {
        alloc_4m_consec()?
    };
    let addr1 = mem.addr(args.row1 * ROW_SIZE);
    let addr2 = mem.addr(args.row2 * ROW_SIZE);
    let dram1 = DRAMAddr::from_virt((addr1 as u64 & (0x3FFFFF)) as *mut u8, &mem_config);
    let dram2 = DRAMAddr::from_virt((addr2 as u64 & (0x3FFFFF)) as *mut u8, &mem_config);
    println!("row1,row2,vaddr1,vaddr2,paddr1,paddr2,dram1,dram2");
    println!(
        "{},{},0x{:x},0x{:x},{:x},{:x},{:?},{:?}",
        args.row1,
        args.row2,
        addr1 as usize,
        addr2 as usize,
        addr1.pfn()?,
        addr2.pfn()?,
        dram1,
        dram2
    );
    loop {
        let time = unsafe { timer.time_subsequent_access_from_ram(addr1, addr2, 100000) };
        println!("{}", time);
    }
}

fn mmap(size: usize) -> anyhow::Result<*mut libc::c_void> {
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANONYMOUS | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        bail!("mmap failed");
    }
    unsafe {
        libc::memset(ptr, 0x42, 4 * MB);
    }
    Ok(ptr)
}

fn alloc_4m_consec() -> anyhow::Result<MemBlock> {
    info!("Allocating a consecutive 4 MiB block. This might take some time...");
    let pfn_checker = ConsecCheckPfn {};
    let mut allocations: [*mut libc::c_void; 10000] = [null_mut(); 10000];
    for i in 0..10000 {
        let ptr = mmap(4 * MB)?;
        let mem = MemBlock::new(ptr as *mut u8, 4 * MB);
        let is_consec = pfn_checker.check(&mem)?;
        if is_consec {
            return Ok(mem);
        } else {
            allocations[i] = ptr;
        }
    }
    bail!("Failed to allocate 4M consecutive pages");
}

fn alloc_1g_hugepage() -> anyhow::Result<MemBlock> {
    let addr = 0x2000000000 as *mut libc::c_void;
    let ptr = unsafe {
        libc::mmap(
            addr,
            1024 * MB,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED
                | libc::MAP_ANONYMOUS
                | libc::MAP_HUGETLB
                | libc::MAP_HUGE_1GB
                | libc::MAP_POPULATE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        bail!("mmap failed");
    }
    if ptr != addr {
        bail!("mmap failed to allocate at the requested address");
    }
    Ok(MemBlock::new(ptr as *mut u8, 1024 * MB))
}
