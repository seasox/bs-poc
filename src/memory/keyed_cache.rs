/// A trait for a cache that is keyed by a key of type K and stores values of type T.
pub trait KeyedCache<T, K> {
    /// Get the cached value for the given key.
    fn get_cached(&self, key: K) -> Option<T>;
    /// Put a value into the cache for the given key.
    fn put(&self, state: Option<T>, key: K) -> Option<T>;
}
