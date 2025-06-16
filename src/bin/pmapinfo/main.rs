use std::env;

use swage::memory::PageMapInfo;
use pagemap::PageMapError;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let pid: u32 = if args.len() == 1 {
        std::process::id()
    } else {
        args[1].parse().expect("Invalid PID")
    };
    let pmapinfo = PageMapInfo::load(pid as u64)?;
    for map in pmapinfo.maps() {
        println!("{:?}", map);
        let pagemap = pmapinfo.pagemap(map);
        match pagemap {
            Some(pagemap) => {
                for (va, pmap) in pagemap {
                    let pfn = pmap.pfn();
                    match pfn {
                        Ok(pfn) => {
                            println!("{:#x}    {:#x}", va, pfn);
                        }
                        Err(e) => match e {
                            PageMapError::PageNotPresent => println!("{:#x}", va),
                            _ => println!("{:#x}    {}", va, e),
                        },
                    }
                }
            }
            None => println!("No pagemap for this region"),
        }
    }
    Ok(())
}
