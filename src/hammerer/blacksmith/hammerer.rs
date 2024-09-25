use crate::hammerer::blacksmith::jitter::{AggressorPtr, CodeJitter, Jitter, Program};
use crate::hammerer::Hammering;
use crate::memory::mem_configuration::MemConfiguration;
use crate::memory::{BytePointer, ConsecBlocks, DRAMAddr, LinuxPageMap, VirtToPhysResolver};
use crate::util::{group, BASE_MSB};
use crate::victim::HammerVictim;
use anyhow::{bail, Context, Result};
use itertools::Itertools;
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::arch::x86_64::{__rdtscp, _mm_mfence};
use std::fmt::Debug;
use std::time::SystemTime;
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
        blocks: &ConsecBlocks,
    ) -> Vec<Vec<AggressorPtr>> {
        self.bit_flips
            .iter()
            .map(|flips| {
                flips
                    .iter()
                    .map(|flip| {
                        let addr =
                            flip.dram_addr.to_virt(BASE_MSB as *const u8, mem_config) as usize;
                        let offset = addr - BASE_MSB as usize;
                        let addr = blocks.addr(offset);
                        addr as *const u8
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
        for (i, group) in &sets {
            debug!("{}: {:?}", i, group);
            for aggr in group {
                base_lookup.insert(*aggr, *i);
            }
        }
        debug!("{:?}", base_lookup);

        assert_eq!(sets.len() * block_size, memory.len());

        let mut aggrs_relocated = vec![];
        let mut pagemap = LinuxPageMap::new()?;
        for agg in aggressors {
            let base_idx = base_lookup[agg];
            let base = memory.addr(base_idx * block_size) as u64;
            let base = base & !((1 << block_shift) - 1);
            let addr = &addrs[agg];
            #[allow(clippy::zero_ptr)]
            let virt = addr.to_virt(0 as *const u8, mem_config);
            let virt = virt as u64 & ((1 << block_shift) - 1);
            let virt = (base | virt) as *const u8;
            let p = pagemap.get_phys(virt as u64);
            match p {
                Ok(p) => {
                    let phys = DRAMAddr::from_virt(p as *const u8, &mem_config);
                    info!(
                        "Relocate {:?} to {:?}, phys {:?} (0x{:x}), base: 0x{:x}, base_idx {}",
                        addr,
                        DRAMAddr::from_virt(virt, &mem_config),
                        phys,
                        p,
                        base,
                        base_idx
                    );
                }
                Err(e) => warn!("Failed to get physical address: {}", e),
            }
            aggrs_relocated.push(virt);
        }
        Ok(aggrs_relocated)
    }

    fn get_random_nonaccessed_rows(
        &self,
        bases: &[AggressorPtr],
        mem_config: MemConfiguration,
    ) -> Vec<AggressorPtr> {
        let mut addresses = vec![];
        let mut rng = rand::thread_rng();
        for _ in 0..1024 {
            let row = rng.gen_range(self.max_row..self.max_row + self.min_row)
                % mem_config.get_row_count();
            let base = bases[rng.gen_range(0..bases.len())];
            addresses.push(DRAMAddr::new(self.bank_no, row, 0).to_virt(base, mem_config));
        }
        addresses
    }

    pub fn count_bitflips(&self) -> usize {
        self.bit_flips.iter().map(|b| b.len()).sum()
    }
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

#[derive(Debug)]
pub struct HammerResult {
    pub run: u64,
    pub attempt: u8,
}

pub struct Hammerer<'a, Mem: BytePointer> {
    blocks: Vec<&'a Mem>,
    mem_config: MemConfiguration,
    mapping: PatternAddressMapper,
    program: Program,
}

impl<'a, Mem: BytePointer> Hammerer<'a, Mem> {
    pub fn new(
        mem_config: MemConfiguration,
        pattern: HammeringPattern,
        mapping: PatternAddressMapper,
        hammering_addrs: &[AggressorPtr],
        blocks: Vec<&'a Mem>,
    ) -> Result<Self> {
        info!("Using pattern {}", pattern.id);
        info!("Using mapping {}", mapping.id);

        let hammer_log_cb = |action: &str, addr: *const u8| {
            let block_idx = blocks.iter().find_position(|base| {
                (addr as u64) >= base.ptr() as u64
                    && (addr as u64) <= (base.addr(base.len() - 1) as u64)
            });
            let found = block_idx.is_some();
            if !found {
                error!("OUT OF BOUNDS ACCESS: {:?}", addr);
            }
            let paddr = LinuxPageMap::new()
                .expect("pagemap open")
                .get_phys(addr as u64);
            match paddr {
                Ok(paddr) => {
                    let dram = DRAMAddr::from_virt(paddr as *const u8, &mem_config);
                    info!(
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

        let num_accessed_addrs = hammering_addrs
            .iter()
            .map(|x| (*x as usize) & !0xFFF)
            .unique()
            .count();

        info!("Pattern contains {} accessed addresses", num_accessed_addrs);

        let program =
            mapping
                .code_jitter
                .jit(acts_per_tref as u64, hammering_addrs, &hammer_log_cb)?;
        if cfg!(feature = "jitter_dump") {
            program
                .write("hammer_jit.o")
                .with_context(|| "failed to write function to disk")?;
        }

        Ok(Hammerer {
            blocks,
            program,
            mem_config,
            mapping,
        })
    }

    fn do_random_accesses(
        &self,
        rows: &[AggressorPtr],
        wait_until_start_hammering_us: u128,
    ) -> Result<()> {
        let start = SystemTime::now();
        while SystemTime::now()
            .duration_since(start)
            .with_context(|| "time went backwards")?
            .as_micros()
            < wait_until_start_hammering_us
        {
            for row in rows {
                let _ = unsafe { std::ptr::read_volatile(row) };
            }
        }
        Ok(())
    }
}

impl<'a, Mem: BytePointer> Hammering for Hammerer<'a, Mem> {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u64) -> Result<HammerResult> {
        let mut rng = rand::thread_rng();
        const REF_INTERVAL_LEN_US: f32 = 7.8; // check if can be derived from pattern?

        const NUM_RETRIES: u8 = 100;

        for run in 0..max_runs {
            victim.init();
            info!("Hammering run {}", run);
            for attempt in 0..NUM_RETRIES {
                let wait_until_start_hammering_refs = rng.gen_range(10..128); // range 10..128 is hard-coded in FuzzingParameterSet
                let wait_until_start_hammering_us =
                    wait_until_start_hammering_refs as f32 * REF_INTERVAL_LEN_US;
                let random_rows = self.mapping.get_random_nonaccessed_rows(
                    &self
                        .blocks
                        .iter()
                        .map(|b| b.ptr() as *const u8)
                        .collect::<Vec<_>>(),
                    self.mem_config,
                );
                debug!(
                    "do random memory accesses for {} us before running jitted code",
                    wait_until_start_hammering_us as u128
                );
                self.do_random_accesses(&random_rows, wait_until_start_hammering_us as u128)?;
                debug!("call into jitted program");
                unsafe {
                    let mut aux = 0;
                    _mm_mfence();
                    let time = __rdtscp(&mut aux);
                    _mm_mfence();
                    let result = self.program.call();
                    _mm_mfence();
                    let time = __rdtscp(&mut aux) - time;
                    _mm_mfence();
                    info!("Run {};{}: JIT call took {} cycles", run, attempt, time);
                    debug!(
                        "jit call done: 0x{:02X} (attempt {}:{})",
                        result, run, attempt
                    );
                }
                let result = victim.check();
                if result {
                    return Ok(HammerResult { run, attempt });
                }
            }
        }
        bail!("No success")
    }
}
