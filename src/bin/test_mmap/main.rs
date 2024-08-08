use anyhow::{bail, Context};
use bs_poc::{
    memory::{AllocChecker, ConsecCheckBankTiming, ConsecCheckPfn, MemBlock},
    util::{BlacksmithConfig, MemConfiguration, MB},
};
use clap::Parser;
use log::info;

#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn _mmap_1g_hugepage() -> anyhow::Result<*mut libc::c_void> {
    const ADDR: *mut libc::c_void = 0x2000000000 as *mut libc::c_void;
    let ptr = unsafe {
        libc::mmap(
            ADDR,
            1024 * MB,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED
                | libc::MAP_ANONYMOUS
                | libc::MAP_HUGETLB
                | libc::MAP_HUGE_1GB
                | libc::MAP_POPULATE
                | libc::MAP_FIXED_NOREPLACE,
            -1,
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        bail!("mmap failed");
    }
    if ptr != ADDR {
        bail!(
            "mmap failed to allocate at the requested address (requested {:02x}, got {:02x})",
            ADDR as usize,
            ptr as usize
        );
    }
    Ok(ptr)
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
    Ok(ptr)
}

unsafe fn _main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let checker = ConsecCheckBankTiming::new(mem_config, config.threshold);
    let pfn_checker = ConsecCheckPfn {};
    info!("Let's go 🚀");
    loop {
        const SIZE: usize = 4 * MB;
        let mut allocations = Vec::with_capacity(3000);
        for i in 0..3000 {
            let block = MemBlock::new(mmap(SIZE)? as *mut u8, SIZE);
            allocations.push(block.clone());
            let pfn_check = pfn_checker.check(&block)?;
            if pfn_check {
                let is_consec = checker.check(&block)?;
                if is_consec {
                    info!("Found consecutive block after {} allocations", i);
                } else {
                    panic!("Bank timing bug");
                }
                break;
            }
        }
        for allocation in allocations {
            allocation.dealloc();
        }
    }
}

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
