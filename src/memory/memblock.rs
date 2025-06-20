use std::{cell::RefCell, ffi::CString, ops::Range, ptr::null_mut};

use crate::{
    memory::{LinuxPageMap, VirtToPhysResolver},
    util::{MB, PAGE_SIZE, ROW_SIZE},
};
use anyhow::{bail, ensure};
use libc::{MAP_ANONYMOUS, MAP_POPULATE, MAP_SHARED, O_CREAT, O_RDWR};
use pagemap::MemoryRegion;

use super::{pfn_offset::CachedPfnOffset, BytePointer, PfnOffset, PhysAddr};

#[derive(Clone, Debug)]
pub struct Memory {
    /// block pointer
    pub ptr: *mut u8,
    /// block length in bytes
    pub len: usize,
    pfn_offset: PfnOffset,
}

unsafe impl Send for Memory {}

pub enum HugepageSize {
    //    TWO_MB,  // not supported yet. TODO: Check PFN offset for 2 MB hugepages in docs.
    OneGb,
}

impl Memory {
    pub fn new(ptr: *mut u8, len: usize) -> Self {
        Memory {
            ptr,
            len,
            pfn_offset: PfnOffset::Dynamic(Box::new(RefCell::new(None))),
        }
    }
    pub fn mmap(size: usize) -> anyhow::Result<Self> {
        let p = unsafe {
            libc::mmap(
                null_mut(),
                size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS | MAP_POPULATE,
                -1,
                0,
            )
        };
        if p == libc::MAP_FAILED {
            bail!("mmap failed: {}", std::io::Error::last_os_error());
        }
        unsafe { libc::memset(p, 0x00, size) };
        Ok(Memory::new(p as *mut u8, size))
    }

    pub fn hugepage(size: HugepageSize) -> anyhow::Result<Self> {
        const ADDR: usize = 0x2000000000;
        let hp_size = match size {
            HugepageSize::OneGb => 1024 * MB,
        };
        let fd = unsafe {
            libc::open(
                CString::new("/dev/hugepages/hammer_huge")
                    .expect("CString")
                    .as_ptr(),
                O_RDWR | O_CREAT,
                666,
            )
        };
        ensure!(fd != -1, "open failed");
        let p = unsafe {
            libc::mmap(
                ADDR as *mut libc::c_void,
                hp_size,
                libc::PROT_READ | libc::PROT_WRITE,
                MAP_SHARED | MAP_POPULATE,
                fd,
                0,
            )
        };
        unsafe { libc::close(fd) };
        ensure!(
            p != libc::MAP_FAILED,
            "mmap failed: {}",
            std::io::Error::last_os_error()
        );
        Ok(Memory {
            ptr: p as *mut u8,
            len: hp_size,
            pfn_offset: PfnOffset::Fixed(0),
        })
    }
    pub fn dealloc(self) {
        unsafe { libc::munmap(self.ptr as *mut libc::c_void, self.len) };
    }
}

impl BytePointer for Memory {
    fn addr(&self, offset: usize) -> *mut u8 {
        assert!(
            offset < self.len,
            "Memory::byte_add failed. Offset {} >= {}",
            offset,
            self.len
        );
        unsafe { self.ptr.byte_add(offset) }
    }
    fn ptr(&self) -> *mut u8 {
        self.ptr
    }
    fn len(&self) -> usize {
        self.len
    }
}

impl CachedPfnOffset for Memory {
    fn cached_offset(&self) -> &PfnOffset {
        &self.pfn_offset
    }
}

pub trait GetConsecPfns {
    fn consec_pfns(&self) -> anyhow::Result<ConsecPfns>;

    fn log_pfns(&self, level: log::Level) {
        let pfns = match self.consec_pfns() {
            Ok(pfns) => pfns,
            Err(e) => {
                warn!("Failed to get PFNs: {:?}", e);
                return;
            }
        };
        let pfns = pfns.format_pfns();
        log!(level, "PFNs:\n{}", pfns);
    }
}

impl GetConsecPfns for Memory {
    fn consec_pfns(&self) -> anyhow::Result<ConsecPfns> {
        (self.ptr, self.len).consec_pfns()
    }
}

impl<T> GetConsecPfns for (*mut T, usize) {
    fn consec_pfns(&self) -> anyhow::Result<ConsecPfns> {
        trace!("Get consecutive PFNs for vaddr 0x{:x}", self.0 as u64);
        let mut consecs = vec![];
        // optimization: get PFN range
        let mut resolver = LinuxPageMap::new()?;
        let pfns = resolver.get_phys_range(MemoryRegion::from((self.0 as u64, unsafe {
            self.0.byte_add(self.1) as u64
        })))?;
        if pfns.is_empty() {
            bail!("Empty PFN range");
        }
        let mut phys_prev = pfns[0];
        let mut range_start = phys_prev;
        for phys in pfns.into_iter().skip(1) {
            if phys != phys_prev + PAGE_SIZE {
                consecs.push(range_start..phys_prev + PAGE_SIZE);
                range_start = phys;
            }
            phys_prev = phys;
        }
        consecs.push(range_start..phys_prev + PAGE_SIZE);
        trace!("PFN check done");
        Ok(consecs)
    }
}

pub trait FormatPfns {
    fn format_pfns(&self) -> String;
}

type ConsecPfns = Vec<Range<PhysAddr>>;

impl FormatPfns for ConsecPfns {
    fn format_pfns(&self) -> String {
        let mut pfns = String::from("");
        for range in self {
            pfns += &format!(
                "{:p}..[{:04} KB]..{:p}\n",
                range.start,
                (range.end - range.start).as_usize() / 1024,
                range.end
            );
        }
        pfns
    }
}

// TODO: we can move this alongside consec_alloc/mmap.rs, but we'll need some more refactoring before (self.pfn_offset is private).
impl Memory {
    pub fn pfn_align(mut self) -> anyhow::Result<Vec<Memory>> {
        let mut blocks = vec![];
        let offset = match self.pfn_offset {
            PfnOffset::Fixed(offset) => offset,
            PfnOffset::Dynamic(ref offset) => {
                let offset = offset.borrow();
                match offset.into() {
                    Some(offset) => offset
                        .expect("PFN offset not determined yet. Call MemBlock::pfn_offset() before MemBlock::pfn_align()")
                        .0
                        .expect("Block is not consecutive"),
                    None => bail!("PFN offset not determined yet. Call MemBlock::pfn_offset() before MemBlock::pfn_align()"),
                }
            }
        };
        if offset == 0 {
            return Ok(vec![self]);
        }
        assert_eq!(self.len, 4 * MB);
        let offset = self.len - offset * ROW_SIZE;
        assert!(offset < 4 * MB, "Offset {} >= 4MB", offset);
        let ptr = self.addr(offset);
        let len = self.len - offset;
        let block = Memory::new(ptr, len); // TODO: add new trait for offsetting into MemBlock (byte_add returns *mut u8 now, but we need MemBlock here)
        blocks.push(block);
        self.len = offset;
        blocks.push(self);

        Ok(blocks)
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::PfnResolver;
    use rand::{thread_rng, Rng};

    use crate::hammerer::blacksmith::blacksmith_config::BlacksmithConfig;
    use crate::memory::mem_configuration::MemConfiguration;
    use crate::{
        memory::{
            construct_memory_tuple_timer, memblock::PfnOffset, DRAMAddr, HugepageSize, Memory,
            MemoryTupleTimer, PfnOffsetResolver,
        },
        util::{MB, ROW_SHIFT, ROW_SIZE},
    };

    const CONFIG_FILE: &str = "config/bs-config.json";

    #[test]
    fn test_pfn_offset_mock_timer() -> anyhow::Result<()> {
        struct TestTimer<'a> {
            callback: &'a dyn Fn((*const u8, *const u8)) -> u64,
        }

        impl MemoryTupleTimer for TestTimer<'_> {
            unsafe fn time_subsequent_access_from_ram(
                &self,
                a: *const u8,
                b: *const u8,
                _rounds: usize,
            ) -> u64 {
                (self.callback)((a, b))
            }
        }

        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        const ADDR: *mut u8 = 0x200000000 as *mut u8;

        // it is not possible to determine the highest bank bit by only using one single memblock.
        let row_offsets = mem_config.bank_function_period() as usize / 2;
        for row_offset in 0..row_offsets {
            let base_addr = ADDR as usize + row_offset * ROW_SIZE;
            let timer = TestTimer {
                callback: &|(a, b)| {
                    let a = a as usize - ADDR as usize;
                    let a = base_addr + a;
                    let b = b as usize - ADDR as usize;
                    let b = base_addr + b;
                    let a = DRAMAddr::from_virt(a as *mut u8, &mem_config);
                    let b = DRAMAddr::from_virt(b as *mut u8, &mem_config);
                    if a.bank == b.bank {
                        config.threshold + 100
                    } else {
                        config.threshold - 100
                    }
                },
            };

            let block = Memory::new(ADDR, 4 * MB);
            let offset = block.pfn_offset(&mem_config, config.threshold, &timer, None);

            assert!(offset.is_some());
            assert_eq!(offset.unwrap(), row_offset);
        }

        Ok(())
    }

    #[test]
    fn test_pfn_offset_mmap() -> anyhow::Result<()> {
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let block = Memory::mmap(4 * MB)?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        assert!(pfn_offset.is_none());
        block.dealloc();
        Ok(())
    }

    #[test]
    #[ignore]
    fn test_pfn_offset_hugepage() -> anyhow::Result<()> {
        env_logger::init();
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let block = Memory::hugepage(HugepageSize::OneGb)?;
        let timer = construct_memory_tuple_timer()?;
        let pfn_offset = block.pfn_offset(&mem_config, config.threshold, &*timer, None);
        println!("VA: 0x{:02x}", block.ptr as usize);
        println!("PFN: 0x{:p}", block.pfn()?);
        assert_eq!(pfn_offset, Some(0));
        block.dealloc();
        Ok(())
    }

    #[test]
    fn test_virt_offset() -> anyhow::Result<()> {
        let config = BlacksmithConfig::from_jsonfile(CONFIG_FILE)?;
        let mem_config =
            MemConfiguration::from_bitdefs(config.bank_bits, config.row_bits, config.col_bits);
        let bank_bits_mask = (mem_config.bank_function_period() as usize * ROW_SIZE - 1) as isize;
        //let row_offsets = (1 << (mem_config.max_bank_bit + 1 - ROW_SHIFT as u64)) as u64;
        //let mut rng = thread_rng();
        const NUM_TESTCASES: usize = 1_000_000;
        let mut test_cases: Vec<(usize, usize)> = Vec::with_capacity(NUM_TESTCASES);
        test_cases.push((0x79acade00000, 0x419df9000));
        test_cases.push((0x77c537a00000, 0x19bd000));
        test_cases.push((0x7ffef6f36000, 0x4a1a0000));
        test_cases.push((0x7ffef6a00000, 0x4c111000));
        test_cases.push((0x7ffeca600000, 0x2033000));
        /*
        for _ in 0..NUM_TESTCASES {
            let v: usize = rng.gen();
            let p: usize = rng.gen();
            test_cases.push((v, p));
        } */
        for (v, p) in test_cases {
            println!("VA,PA");
            println!("0x{:02x},0x{:02x}", v, p);
            let byte_offset = (p as isize & bank_bits_mask) - (v as isize & bank_bits_mask);
            let byte_offset = byte_offset.rem_euclid(4 * MB as isize) as usize;
            println!("Byte offset 0x{:02x}", byte_offset);
            println!("Row offset: {}", byte_offset >> ROW_SHIFT);
            let dramv = unsafe {
                DRAMAddr::from_virt_offset(v as *const u8, byte_offset as isize, &mem_config)
            };
            let dramp = DRAMAddr::from_virt(p as *const u8, &mem_config);
            println!("{:?}", dramv);
            println!("{:?}", dramp);
            assert_eq!(dramv.bank, dramp.bank);
        }
        Ok(())
    }

    #[test]
    fn test_virt_zero_gap() -> anyhow::Result<()> {
        let config = BlacksmithConfig::from_jsonfile("config/bs-config.json")?;
        let mem_config = MemConfiguration::from_blacksmith(&config);
        const MASK: isize = 0x3FFFFF;
        let mut rand = thread_rng();
        for _ in 0..1000000 {
            let v = rand.gen::<isize>() << 12;
            let p = rand.gen::<isize>() << 12;
            println!("VA,PA: 0x{:x}, 0x{:x}", v, p);
            let vbase = v & MASK;
            let pbase = p & MASK;
            let offset = pbase as isize - vbase as isize;
            let offset = offset.rem_euclid(4 * MB as isize);
            //let offset = offset.rem_euclid(2 * MB as isize);
            let block = Memory {
                ptr: v as *mut u8,
                len: 4 * MB,
                pfn_offset: PfnOffset::Fixed(offset as usize / ROW_SIZE),
            };
            let aligned = &block.pfn_align()?[0];
            let expected = if offset == 0 {
                v
            } else {
                v + 4 * MB as isize - offset
            };
            assert_eq!(aligned.ptr as usize, expected as usize);

            let zero_gap = offset + vbase as isize;
            let pdram_zero =
                DRAMAddr::from_virt((p + 4 * MB as isize - zero_gap) as *mut u8, &mem_config);
            assert_eq!(pdram_zero.bank, 0);
        }
        Ok(())
    }

    /*
    #[test]
    fn test_row_delta() -> anyhow::Result<()> {
        const BASE: *mut u8 = 0x2000000000 as *mut u8;
        let config = BlacksmithConfig::from_jsonfile("config/bs-config.json")?;
        let mem_config = MemConfiguration::from_blacksmith(&config);
        let a1 = DRAMAddr::from_virt(BASE, &mem_config);
        let a2 = a1.clone();
        for _ in 0..100 {
            let a2 = a2.add(0, 2, 0);
            let a1 = a1.to_virt(BASE, mem_config) as isize;
            let a2 = a2.to_virt(BASE, mem_config) as isize;
            println!("{}", a2 - a1);
        }
        assert!(false);
        Ok(())
    }
    */
}
