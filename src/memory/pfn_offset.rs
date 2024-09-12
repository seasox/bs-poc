use std::cell::RefCell;

use crate::util::MemConfiguration;

/// An enum representing a PFN offset that can be either fixed or dynamic.
/// A fixed PFN offset is a constant value that is set once and never changes.
/// A dynamic PFN offset is a value that is calculated at runtime.
/// Setting a fixed PFN offset potentially disables the logic around PFN offset calculation.
#[derive(Clone, Debug)]
pub enum PfnOffset {
    Fixed(usize),
    Dynamic(RefCell<Option<(Option<usize>, (MemConfiguration, u64))>>), // a RefCell holding the cached value for the PFN offset as well as a key (mem_config, threshold)
}

/// A trait for a type that can provide a PFN offset.
pub trait CachedPfnOffset {
    /// Get the cached PFN offset.
    fn cached_offset(&self) -> &PfnOffset;
}
