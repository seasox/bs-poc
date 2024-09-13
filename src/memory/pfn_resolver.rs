use super::{LinuxPageMap, VirtToPhysResolver};

pub trait PfnResolver {
    fn pfn(&self) -> anyhow::Result<u64>;
}

/// implementation for PfnResolver trait for raw pointers
impl<T> PfnResolver for *mut T {
    fn pfn(&self) -> anyhow::Result<u64> {
        let mut resolver = LinuxPageMap::new()?;
        resolver.get_phys(*self as u64)
    }
}
