use std::env;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();

    let pid: u32 = if args.len() == 1 {
        std::process::id()
    } else {
        args[1].parse().expect("Invalid PID")
    };

    let mut pagemap = pagemap::PageMap::new(pid as u64)?;

    let maps = pagemap.maps()?;
    for map in maps {
        println!("{:?}", map);
        if map.path() == Some("[vsyscall]") {
            // vsyscall is not resolvable on modern linux systems
            continue;
        }
        let pmap = pagemap.pagemap_region(&map.memory_region())?;
        println!("{:?}", pmap);
    }

    Ok(())
}
