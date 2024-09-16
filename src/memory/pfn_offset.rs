use crate::memory::keyed_cache::KeyedCache;
use crate::memory::mem_configuration::MemConfiguration;
use std::cell::RefCell;

type CacheKey = (MemConfiguration, u64);
type CacheValue = Option<usize>;
/// An enum representing a PFN offset that can be either fixed or dynamic.
/// A fixed PFN offset is a constant value that is set once and never changes.
/// A dynamic PFN offset is a value that is calculated at runtime.
/// Setting a fixed PFN offset potentially disables the logic around PFN offset calculation.
#[derive(Clone, Debug)]
pub enum PfnOffset {
    Fixed(usize),
    Dynamic(Box<RefCell<Option<(CacheValue, CacheKey)>>>), // a RefCell holding the cached value for the PFN offset as well as a key (mem_config, threshold)
}

/// A trait for a type that can provide a PFN offset.
pub trait CachedPfnOffset {
    /// Get the cached PFN offset.
    fn cached_offset(&self) -> &PfnOffset;
}

/// A cache for the PFN offset keyed by memory configuration and conflict threshold.
/// This allows the implementation to store a fixed PFN offset, effectively disabling logic around PFN offset calculation.
impl<T> KeyedCache<usize, (MemConfiguration, u64)> for T
where
    T: CachedPfnOffset,
{
    fn get_cached(&self, key: (MemConfiguration, u64)) -> Option<usize> {
        match self.cached_offset() {
            PfnOffset::Fixed(offset) => Some(*offset),
            PfnOffset::Dynamic(pfn_offset) => {
                let state = pfn_offset.borrow();
                match state.as_ref() {
                    Some((offset, cfg)) if offset.is_some() && *cfg == key => Some(offset.unwrap()),
                    _ => None,
                }
            }
        }
    }
    fn put(&self, state: Option<usize>, key: (MemConfiguration, u64)) -> Option<usize> {
        match self.cached_offset() {
            PfnOffset::Fixed(_) => panic!("Fixed offset should not be set"),
            PfnOffset::Dynamic(cell) => {
                let mut cell = cell.borrow_mut();
                *cell = Some((state, key));
                state
            }
        }
    }
}
