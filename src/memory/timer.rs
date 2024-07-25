use anyhow::Result;
#[cfg(target_arch = "x86_64")]
use {core::arch::x86_64, core::ptr};

#[cfg(target_arch = "aarch64")]
use anyhow::bail;

pub trait MemoryTupleTimer {
    unsafe fn time_subsequent_access_from_ram(
        &self,
        a: *const u8,
        b: *const u8,
        rounds: usize,
    ) -> u64;
}

pub fn construct_memory_tuple_timer() -> Result<Box<dyn MemoryTupleTimer>> {
    #[cfg(target_arch = "x86_64")]
    return Ok(Box::new(DefaultMemoryTupleTimer {}));
    #[cfg(target_arch = "aarch64")]
    bail!("Only supported on x86_64")
}

#[cfg(target_arch = "x86_64")]
pub struct DefaultMemoryTupleTimer {}

#[cfg(target_arch = "x86_64")]
impl MemoryTupleTimer for DefaultMemoryTupleTimer {
    ///time_subsequent_access_from_ram measures the access time when accessing both memory locations back to back from ram.
    /// #Arguments
    /// * `a` pointer to first memory location
    /// * `b` pointer to second memory location
    /// * `rounds` average the access time over this many accesses
    unsafe fn time_subsequent_access_from_ram(
        &self,
        a: *const u8,
        b: *const u8,
        rounds: usize,
    ) -> u64 {
        let mut measurements = Vec::with_capacity(rounds);
        //flush data from cache
        x86_64::_mm_clflush(a);
        x86_64::_mm_clflush(b);
        let mut aux = 0;
        let mut run_idx = 0;
        let mut sum = 0;
        while run_idx < rounds {
            x86_64::_mm_mfence(); //ensures clean slate memory access time wise
            let before = x86_64::__rdtscp(&mut aux); // read timestamp counter
            x86_64::_mm_mfence(); //ensures clean slate memory access time wise
            ptr::read_volatile(a);
            ptr::read_volatile(b);
            let after = x86_64::__rdtscp(&mut aux); //read second timestamp
            x86_64::_mm_mfence(); //ensure rdtsc is done
            let time = after - before;
            measurements.push(time);
            sum += time;
            run_idx += 1;
            //flush data from cache
            x86_64::_mm_clflush(a);
            x86_64::_mm_clflush(b);
        }
        trace!("Measurements: {:?}", measurements);
        let _mean = sum / rounds as u64;
        let median = median(measurements);
        median
    }
}

fn median(mut list: Vec<u64>) -> u64 {
    list.sort();
    let mid = list.len() / 2;
    let median = (list[mid] + list[mid + 1]) / 2;
    median
}
