use crate::util::MemConfiguration;

use super::{pfn_offset::CachedPfnOffset, PfnOffset};

/// A trait for a cache that is keyed by a key of type K and stores values of type T.
pub trait KeyedCache<T, K> {
    /// Get the cached value for the given key.
    fn get_cached(&self, key: K) -> Option<T>;
    /// Put a value into the cache for the given key.
    fn put(&self, state: Option<T>, key: K) -> Option<T>;
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
