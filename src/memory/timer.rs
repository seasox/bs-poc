use anyhow::Result;
#[cfg(target_arch = "x86_64")]
use {core::arch::x86_64, core::ptr, std::arch::asm};

#[cfg(target_arch = "aarch64")]
use anyhow::bail;

pub trait MemoryTimer {
    unsafe fn time_access(&self, a: *const u8) -> u64;
    unsafe fn flush(&self, a: *const u8);
}

#[cfg(target_arch = "x86_64")]
pub struct DefaultMemoryTimer {}

#[cfg(target_arch = "x86_64")]
impl MemoryTimer for DefaultMemoryTimer {
    unsafe fn time_access(&self, a: *const u8) -> u64 {
        let mut timing = 0;
        asm!(
        "mfence",
        "rdtsc",      /*writes to edx:eax*/
        "shl rdx, 32", /*shift low 32 bits in edx to high bits*/
        "or rdx,rax",  /*add low bits stored in eax*/
        "mov rcx, rdx", /*stash measurement in rcx*/
        "mov rax,  [{a}]",
        "lfence",
        "rdtsc",
        "shl rdx, 32", /*shift low 32 bits in edx to high bits*/
        "or rdx,rax",  /*add low bits stored in eax*/
        "sub rdx, rcx", /*calculdate diff*/
        "mov {timing}, rdx",
        a = in(reg) a as u64,
        timing = inout(reg) timing,
        out("rdx") _, /*mark rdx as clobbered*/
        out("rax") _, /*mark rax as clobbered*/
        out("rcx") _, /*mark rcx as clobbered*/

        );
        return timing;
    }

    unsafe fn flush(&self, a: *const u8) {
        asm!(
        "clflush [{a}]",
        a = in(reg) a as u64,
        );
    }
}

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
        let mut sum = 0;
        //flush data from cache
        x86_64::_mm_clflush(a);
        x86_64::_mm_clflush(b);

        for _run_idx in 1..rounds {
            x86_64::_mm_mfence(); //ensures clean slate memory access time wise
            let before = x86_64::_rdtsc(); // read timestamp counter
            x86_64::_mm_lfence(); //ensure rdtsc is done
            ptr::read_volatile(a);
            ptr::read_volatile(b);
            x86_64::_mm_lfence(); //ensure accesses are done
            let after = x86_64::_rdtsc(); //read second timestamp
            sum += after - before;
            //flush data from cache
            x86_64::_mm_clflush(a);
            x86_64::_mm_clflush(b);
        }

        return sum / rounds as u64;
    }
}
