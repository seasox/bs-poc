use std::ptr::null_mut;

use anyhow::{bail, Context};
use bs_poc::{
    memory::{
        construct_memory_tuple_timer, AllocChecker, ConsecCheckBankTiming, ConsecCheckPfn, MemBlock,
    },
    util::{BlacksmithConfig, MemConfiguration, KB, MB},
};
use clap::Parser;
use log::{error, info};

#[derive(Debug, Parser)]
struct CliArgs {
    /// The JSON file containing the memory config
    #[clap(long = "config", default_value = "config.json")]
    config: String,
}

fn mmap_1g_hugepage() -> anyhow::Result<*mut libc::c_void> {
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

fn format_arr(arr: &[u64; 11]) -> String {
    let mut s = String::new();
    for i in 0..11 {
        s.push_str(&format!("{:5}", arr[i]));
    }
    s
}

fn pti_locked_blocks() -> anyhow::Result<[u64; 11]> {
    let pti = match lpfs::proc::pagetypeinfo::pagetypeinfo() {
        Ok(pti) => pti,
        Err(e) => bail!("{:?}", e),
    };
    let pages = pti.free_pages().clone();
    let mut free_pages = [0_u64; 11];
    for (_, zone, migrate_type, blocks) in pages {
        if zone == "Normal" && (migrate_type == "Movable" || migrate_type == "Reclaimable") {
            continue;
        }
        for i in 0..11 {
            free_pages[i] += blocks[i];
        }
    }
    Ok(free_pages)
}

unsafe fn _main() -> anyhow::Result<()> {
    env_logger::init();
    let args = CliArgs::parse();
    let timer = construct_memory_tuple_timer()?;
    let config = BlacksmithConfig::from_jsonfile(&args.config).with_context(|| "from_jsonfile")?;
    let mem_config =
        MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
    let mut checker = ConsecCheckBankTiming::new(mem_config, &*timer, config.threshold);
    let mut pfn_checker = ConsecCheckPfn {};
    info!("Let's go 🚀");
    loop {
        const SIZE: usize = 4 * MB;
        //let dummy = mmap(1024 * MB)?;
        let mut allocations = Vec::with_capacity(3000);
        for i in 0..3000 {
            //let buddy_before = get_normal_page_nums().expect("no buddy info");
            //allocations[i] = mmap(SIZE)?;
            //let mut block = MemBlock::new(mmap_1g_hugepage()? as *mut u8, 1024 * MB);
            let block = MemBlock::new(mmap(SIZE)? as *mut u8, SIZE);
            allocations.push(block.clone());
            //let buddy_after = get_normal_page_nums().expect("no buddy info");
            /*let diff = diff_arrs(&buddy_before, &buddy_after);
            let sum = diff.iter().enumerate().fold(0, |acc, (i, x)| {
                acc + x * 2_i64.pow(i as u32) * 4 * KB as i64
            });*/
            // Problem mit diesem Ansatz: offset zwischen virtueller und physikalischer Adresse ist konsistent.
            // Muss im address lookup was rumpatchen um das Phänomen zu simulieren.

            let pfn_check = pfn_checker.check(&block)?;
            if pfn_check {
                let is_consec = checker.check(&block)?;
                if is_consec {
                    info!("Found consecutive block after {} allocations", i);
                } else {
                    error!("Bank timing bug");
                }
                break;
            }
            //file.write_all(format!("{},{}\n", sum, pfn_consec).as_bytes())?;
        }
        for allocation in allocations {
            allocation.dealloc();
        }
        //libc::munmap(dummy, 1024 * MB);
    }
}

/*unsafe fn _main() -> anyhow::Result<()> {
    env_logger::init();
    loop {
        let pti = pti_locked_blocks()?;
        info!("Locked blocks (PTI):   {}", format_arr(&pti));
        let locked = all_locked_blocks()?;
        info!("Locked blocks (buddy): {}", format_arr(&locked));
    }
}*/

fn main() -> anyhow::Result<()> {
    unsafe { _main() }
}
