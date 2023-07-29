use anyhow::{Context, Result};
use rand::Rng;
use serde::Deserialize;
use serde_with::serde_as;
use std::time::SystemTime;
use std::{collections::HashMap, fs::File, io::BufReader};

use crate::jitter::{AggressorPtr, CodeJitter, Jitter, Program};
use crate::memory::DRAMAddr;
use crate::util::MemConfiguration;

pub struct Hammerer {
    base_msb: *const u8,
    mem_config: MemConfiguration,
    mapping: PatternAddressMapper,
    program: Program,
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

/*
struct FuzzingParameterSet {
    gen: MT19937,
    //num_refresh_intervals: i32,
    //num_aggressors: i32,
    //agg_intra_distance: i32,
    //agg_inter_distance: i32,
    //num_activations_per_trefi: i32,
    //hammering_total_num_activations: i64,
    //base_period: i32,
    max_row_no: u8,
    //total_acts_pattern: i32,
    //start_row: Range<i32>,
    //num_aggressors_for_sync: Range<i32>,
    //bank_no: Range<i32>,
    //use_sequential_aggressors: Range<i32>,
    //amplitude: Range<i32>,
    //n_sided: Range<i32>,
    //sync_each_ref: Range<i32>,
    //wait_until_start_hammering_refs: Range<i32>,
    //    N_sided_probabilities: Distribution<i32>,
    fencing_strategy: FencingStrategy,
    flushing_strategy: FlushingStrategy,
}
impl FuzzingParameterSet {
    fn new(pattern: &HammeringPattern, measured_num_acts_per_ref: i32) -> Self {
        let mut gen = MT19937::new_with_slice_seed(&[12345]); // TODO random seed
        return FuzzingParameterSet {
            gen: gen,
            //num_refresh_intervals: 2_i32.pow(Range::new(0, 4).get_random_number(&mut gen)),
            //num_aggressors: Range::new(8, 96).get_random_number(&mut gen),
            //agg_intra_distance: Range::new(1, 24).get_random_number(&mut gen),
            //agg_inter_distance: (),
            //num_activations_per_trefi: (measured_num_acts_per_ref / 2) * 2, // make sure that num_acts is even
            //hammering_total_num_activations: pattern.code_jitter.total_activations,
            //base_period: (),
            //max_row_no: (),
            //total_acts_pattern: pattern.total_activations,
            //start_row: (),
            //num_aggressors_for_sync: (),
            //bank_no: (),
            //use_sequential_aggressors: (),
            //amplitude: (),
            //n_sided: Range::new(1, 2),
            //sync_each_ref: (),
            //wait_until_start_hammering_refs: (),
            fencing_strategy: FencingStrategy::LatestPossible,
            flushing_strategy: FlushingStrategy::EarliestPossible,
        };
    }
}
*/

pub struct HammerResult<S, R> {
    pub run: u64,
    pub attempt: u64,
    pub state: S,
    pub result: R,
}

impl Hammerer {
    pub fn hammer<FnInit, FnCheck, S: Copy, R>(
        &self,
        init: FnInit,
        check: FnCheck,
    ) -> Result<HammerResult<S, R>>
    where
        FnInit: Fn(Option<S>) -> S,
        FnCheck: Fn(S) -> Option<R>,
    {
        let num_retries = 100;
        let mut rng = rand::thread_rng();
        const REF_INTERVAL_LEN_US: f32 = 7.8;

        let mut run = 0;
        let mut state = init(None);
        loop {
            for attempt in 0..num_retries {
                let wait_until_start_hammering_refs = rng.gen_range(10..128); // range 10..128 is hard-coded in FuzzingParameterSet
                let wait_until_start_hammering_us =
                    wait_until_start_hammering_refs as f32 * REF_INTERVAL_LEN_US;
                let random_rows = self
                    .mapping
                    .get_random_nonaccessed_rows(self.base_msb, self.mem_config);
                info!(
                    "do random memory accesses for {} us before running jitted code",
                    wait_until_start_hammering_us as u128
                );
                self.do_random_accesses(&random_rows, wait_until_start_hammering_us as u128)?;
                info!("call into jitted program");
                let result = unsafe { self.program.call() };
                info!(
                    "jit call done: 0x{:02X} (attempt {}:{})",
                    result, run, attempt
                );
                let result = check(state);
                if let Some(result) = result {
                    return Ok(HammerResult {
                        run,
                        attempt,
                        state,
                        result,
                    });
                }
            }
            run += 1;
            state = init(Some(state));
        }
    }

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

impl HammeringPattern {
    fn determine_most_effective_mapping(&mut self) -> Option<PatternAddressMapper> {
        self.address_mappings
            .iter_mut()
            .max_by_key(|m| m.bit_flips.len())
            .cloned()
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
