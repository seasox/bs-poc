use anyhow::{bail, Context, Result};
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::arch::x86_64::_mm_clflush;
use std::fmt::Debug;
use std::time::SystemTime;
use std::{collections::HashMap, fs::File, io::BufReader};

use crate::jitter::{AggressorPtr, CodeJitter, Jitter, Program};
use crate::memory::{DRAMAddr, MemBlock};
use crate::util::{group, MemConfiguration};
use crate::victim::HammerVictim;

pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u8) -> Result<HammerResult>;
}

#[derive(Deserialize, Debug, Hash, PartialEq, Eq, Clone, Copy)]
pub struct Aggressor(u64);

#[derive(Deserialize, Debug, Clone)]
struct AggressorAccessPattern {
    frequency: usize,
    amplitude: i32,
    start_offset: usize,
    aggressors: Vec<Aggressor>,
}

#[derive(Deserialize, Debug, Clone)]
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
        aggressors: &Vec<Aggressor>,
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
    ) -> Vec<Vec<(&Aggressor, &DRAMAddr)>> {
        // find mapping classes
        let addrs: &HashMap<Aggressor, DRAMAddr> = &self.aggressor_to_addr;

        let addrs_vec = addrs.iter().collect::<Vec<_>>();

        // group aggressors by prefix
        let groups: Vec<Vec<(&Aggressor, &DRAMAddr)>> = group(addrs_vec, |(_, addr)| {
            let virt = addr.to_virt(0 as *const u8, mem_config) as usize;
            let virt = virt >> block_shift;
            virt
        });
        groups
    }

    pub fn get_hammering_addresses_relocate(
        &self,
        aggressors: &Vec<Aggressor>,
        mem_config: MemConfiguration,
        block_shift: usize,
        blocks: &[MemBlock],
    ) -> anyhow::Result<Vec<AggressorPtr>> {
        let addrs = &self.aggressor_to_addr;
        let sets = self.aggressor_sets(mem_config, block_shift);

        let mut base_lookup: HashMap<Aggressor, usize> = HashMap::new();
        for (i, group) in sets.iter().enumerate() {
            debug!("{}: {:?}", i, group.iter().collect::<Vec<_>>());
            for (&aggr, _) in group {
                base_lookup.insert(aggr, i);
            }
        }
        debug!("{:?}", base_lookup);

        let aggrs = aggressors
            .iter()
            .map(|agg| {
                let addr = &addrs[agg];
                let base = blocks[base_lookup[agg]].ptr as u64;
                let virt = addr.to_virt(0 as *const u8, mem_config);
                let virt = virt as u64 & ((1 << block_shift) - 1);
                let virt = (base | virt) as *const u8;

                debug!("Relocate {:?} to {:?} (base: {:?})", addr, virt, base);
                virt
            })
            .collect();

        Ok(aggrs)
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
}

#[derive(Deserialize, Debug)]
pub struct FuzzSummary {
    pub hammering_patterns: Vec<HammeringPattern>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct HammeringPattern {
    pub id: String,
    base_period: i32,
    max_period: usize,
    total_activations: u32,
    num_refresh_intervals: u32,
    is_location_dependent: bool,
    pub access_ids: Vec<Aggressor>,
    agg_access_patterns: Vec<AggressorAccessPattern>,
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
        Ok(patterns
            .hammering_patterns
            .into_iter()
            .find(|p| pattern_id.eq(&p.id))
            .with_context(|| {
                format!(
                    "did not find pattern with id {} in {}",
                    pattern_id.clone(),
                    json_filename
                )
            })?)
    }
}

impl HammeringPattern {
    pub fn determine_most_effective_mapping(&self) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter()
            .max_by_key(|m| m.bit_flips.len())
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
    pub run: u8,
    pub attempt: u8,
}

pub struct DummyHammerer {
    base_msb: *mut u8,
    flip_offset: usize,
}

impl DummyHammerer {
    pub fn new(base_msb: *mut u8, flip_offset: usize) -> Self {
        DummyHammerer {
            base_msb,
            flip_offset,
        }
    }
}

impl Hammering for DummyHammerer {
    fn hammer(&self, victim: &mut dyn HammerVictim, _max_runs: u8) -> Result<HammerResult> {
        victim.init();
        unsafe {
            let flipped_byte = self.base_msb.add(self.flip_offset);
            debug!(
                "Flip 0x{:02X} from {} to {} at offset {}",
                flipped_byte as usize, *flipped_byte, !*flipped_byte, self.flip_offset
            );
            *flipped_byte = !*flipped_byte;
            _mm_clflush(flipped_byte);
        }
        let result = victim.check();
        if result {
            return Ok(HammerResult { run: 0, attempt: 0 });
        }
        bail!("Hammering not successful")
    }
}

pub struct Hammerer<'a> {
    blocks: &'a [MemBlock],
    mem_config: MemConfiguration,
    mapping: PatternAddressMapper,
    program: Program,
}

impl<'a> Hammerer<'a> {
    pub fn new(
        mem_config: MemConfiguration,
        pattern: HammeringPattern,
        mapping: PatternAddressMapper,
        hammering_addrs: &[AggressorPtr],
        blocks: &'a [MemBlock],
    ) -> Result<Self> {
        info!("Using pattern {}", pattern.id);
        info!("Using mapping {}", mapping.id);

        let hammer_log_cb = |action: &str, addr| {
            let found = blocks
                .iter()
                .find(|base| unsafe {
                    addr as u64 >= base.ptr as u64
                        && (addr as u64) < (base.ptr.add(base.len) as u64)
                })
                .is_some();
            if !found {
                error!("OUT OF BOUNDS ACCESS: {:?}", addr);
            }
            debug!(
                "{} 0x{:016X} ({})",
                action,
                addr as usize,
                DRAMAddr::from_virt(addr, &mem_config)
            );
        };

        let acts_per_tref = pattern.total_activations / pattern.num_refresh_intervals;

        let program =
            mapping
                .code_jitter
                .jit(acts_per_tref as u64, &hammering_addrs, &hammer_log_cb)?;
        program
            .write("hammer_jit.o")
            .with_context(|| "failed to write function to disk")?;

        return Ok(Hammerer {
            blocks,
            program,
            mem_config,
            mapping,
        });
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

impl<'a> Hammering for Hammerer<'a> {
    fn hammer(&self, victim: &mut dyn HammerVictim, max_runs: u8) -> Result<HammerResult> {
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
                        .map(|b| b.ptr as *const u8)
                        .collect::<Vec<_>>(),
                    self.mem_config,
                );
                debug!(
                    "do random memory accesses for {} us before running jitted code",
                    wait_until_start_hammering_us as u128
                );
                self.do_random_accesses(&random_rows, wait_until_start_hammering_us as u128)?;
                debug!("call into jitted program");
                let result = unsafe { self.program.call() };
                debug!(
                    "jit call done: 0x{:02X} (attempt {}:{})",
                    result, run, attempt
                );
                let result = victim.check();
                if result {
                    return Ok(HammerResult { run, attempt });
                }
            }
        }
        bail!("No success")
    }
}
