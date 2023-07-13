use anyhow::Context;
use mt19937::MT19937;
use serde::Deserialize;
use serde_with::serde_as;
use std::{collections::HashMap, error::Error, fs::File, io::BufReader};

use crate::jitter::{CodeJitter, FencingStrategy, FlushingStrategy, Jitter};
use crate::memory::DRAMAddr;
use crate::util::MemConfiguration;

pub struct Hammerer {}

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
    //victim_rows: Vec<usize>,
    id: String,
    // #[serde(skip_deserializing)]
    // gen: MT19937,
    min_row: usize,
    max_row: usize,
    bank_no: usize,
    //bank_counter: i32, TODO?
    #[serde_as(as = "Vec<(_, _)>")]
    aggressor_to_addr: HashMap<Aggressor, DRAMAddr>,
    bit_flips: Vec<Vec<BitFlip>>,
    code_jitter: CodeJitter,
}

impl PatternAddressMapper {
    /*
    fn get_random_nonaccessed_rows(
        &mut self,
        gen: &mut MT19937,
        row_upper_bound: usize,
        mem_cfg: MemConfiguration,
        base_msb: *const libc::c_void,
    ) -> Vec<*const std::ffi::c_void> {
        let mut addresses = vec![];
        for _ in 0..1024 {
            let row_no = Range::new(self.max_row, self.max_row + self.min_row)
                .get_random_number(gen)
                % row_upper_bound;
            addresses.push(DRAMAddr::new(self.bank_no, row_no, 0).to_virt(base_msb, mem_cfg));
        }
        addresses
    }*/

    fn get_hammering_addresses(
        &self,
        aggressors: Vec<Aggressor>,
        base_msb: *const libc::c_void,
        mem_config: MemConfiguration,
    ) -> Vec<*const libc::c_void> {
        aggressors
            .iter()
            .map(|agg| self.aggressor_to_addr[agg].to_virt(base_msb, mem_config))
            .collect()
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

struct FuzzingParameterSet {
    gen: MT19937,
    //num_refresh_intervals: i32,
    //num_aggressors: i32,
    //agg_intra_distance: i32,
    //agg_inter_distance: i32,
    //num_activations_per_trefi: i32,
    //hammering_total_num_activations: i64,
    //base_period: i32,
    //max_row_no: i32,
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
/*
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

impl Hammerer {
    pub fn hammer_pattern(
        &self,
        mem_config: MemConfiguration,
        json_filename: String,
        pattern_id: String,
        base_msb: *mut libc::c_void,
    ) -> Result<(), Box<dyn Error>> {
        // load patterns from JSON
        let mut pattern = load_pattern_from_json(json_filename, pattern_id)?;

        let mapping: &mut PatternAddressMapper = &mut pattern
            .determine_most_effective_mapping()
            .with_context(|| "pattern contains no mappings")?;

        //let params = FuzzingParameterSet::new(&loaded_pattern, num_acts_per_trefi);

        //let mut gen = MT19937::default();
        /*let random_rows = mapping.get_random_nonaccessed_rows(
            &mut gen,
            mem_config.get_row_count(),
            mem_config,
            base_msb,
        );*/

        let hammering_addrs =
            mapping.get_hammering_addresses(pattern.access_ids, base_msb, mem_config);

        let acts_per_tref = pattern.total_activations / pattern.num_refresh_intervals;

        let program = mapping
            .code_jitter
            .jit(acts_per_tref.into(), &hammering_addrs)?;
        let result = program.call();
        println!("{:?}", result);

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
fn load_pattern_from_json(
    json_filename: String,
    pattern_id: String,
) -> Result<HammeringPattern, Box<dyn Error>> {
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
