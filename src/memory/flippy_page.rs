use std::fs::OpenOptions;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use anyhow::bail;
use pagemap::MapsEntry;

use crate::util::find_pattern;

use crate::util::PAGE_SHIFT;
use crate::util::PAGE_SIZE;

use crate::memory::PageMapInfo;

#[derive(Debug)]
pub struct FlippyPage {
    #[allow(dead_code)]
    pub maps_entry: MapsEntry,
    #[allow(dead_code)]
    pub region_offset: usize, // page offset in the region
}

pub fn find_flippy_page(target_page: u64, pid: u32) -> anyhow::Result<Option<FlippyPage>> {
    let pmap = PageMapInfo::load(pid as u64)?.0;
    let mut flippy_region = None;
    for (map, pagemap) in pmap {
        for (idx, (va, pmap)) in pagemap.iter().enumerate() {
            let pfn = pmap.pfn();
            match pfn {
                Ok(pfn) => {
                    if target_page >> PAGE_SHIFT == pfn {
                        flippy_region = Some(FlippyPage {
                            maps_entry: map.0.clone(),
                            region_offset: idx,
                        });
                        info!("Region: {:?}", map.0);
                        debug!("Region size: {}", map.0.memory_region().size());
                        info!("[{}]  {:#x}    {:#x} [REUSED TARGET PAGE]", idx, va, pfn);
                        if let Some("[stack]") = map.0.path() {
                            let mut stack_contents = String::new();
                            let contents = read_memory_from_proc(pid, *va, PAGE_SIZE as u64);
                            match contents {
                                Ok(contents) => {
                                    match find_pattern(&contents, 0b10101010, PAGE_SIZE) {
                                        Some(offset) => {
                                            info!("Found pattern at offset {}", offset);
                                        }
                                        None => {
                                            info!("Pattern not found");
                                        }
                                    }
                                    for (i, byte) in contents.iter().enumerate() {
                                        stack_contents += &format!("{:02x}", byte);
                                        if i % 8 == 7 {
                                            stack_contents += " ";
                                        }
                                        if i % 64 == 63 {
                                            stack_contents += "\n";
                                        }
                                    }
                                    info!("Content:\n{}", stack_contents);
                                }
                                Err(e) => {
                                    info!("Failed to read stack contents: {}", e);
                                }
                            }
                        }
                    } else {
                        //info!("[{}]  {:#x}    {:#x}", idx, va, pfn);
                    }
                }
                Err(e) => match e {
                    pagemap::PageMapError::PageNotPresent => {
                        //info!("[{}]  {:#x}    ???", idx, va);
                    }
                    _ => bail!(e),
                },
            }
        }
    }
    Ok(flippy_region)
}

fn read_memory_from_proc(pid: u32, va: u64, size: u64) -> std::io::Result<Vec<u8>> {
    // Construct the path to the process's memory file
    let path = format!("/proc/{}/mem", pid);
    let mut file = OpenOptions::new().read(true).open(path)?;

    // Seek to the virtual memory address
    file.seek(SeekFrom::Start(va))?;

    // Read the specified number of bytes into a buffer
    let mut buffer = vec![0; size as usize];
    file.read_exact(&mut buffer)?;

    Ok(buffer)
}
