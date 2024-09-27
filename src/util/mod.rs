mod anyhow;
mod constants;
mod ipc;
mod named_progress;

pub use self::anyhow::Anyhow;
pub use self::constants::*;
pub use self::ipc::*;
pub use self::named_progress::NamedProgress;

use std::collections::HashMap;

use indicatif::MultiProgress;
use indicatif_log_bridge::LogWrapper;

pub fn init_logging_with_progress() -> anyhow::Result<MultiProgress> {
    let logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).build();
    let progress = MultiProgress::new();
    LogWrapper::new(progress.clone(), logger).try_init()?;
    Ok(progress)
}

pub trait GroupBy<V> {
    fn group_by<K: std::hash::Hash + std::cmp::Eq, F: Fn(&V) -> K>(
        self,
        f: F,
    ) -> HashMap<K, Vec<V>>;
}

impl<T> GroupBy<T> for Vec<T> {
    fn group_by<K: std::hash::Hash + std::cmp::Eq, F: Fn(&T) -> K>(
        self,
        f: F,
    ) -> HashMap<K, Vec<T>> {
        let mut out = HashMap::new();
        for elem in self {
            let k = f(&elem);
            out.entry(k).or_insert(vec![]).push(elem);
        }
        out
    }
}

pub fn make_vec<T>(n: usize, f: impl Fn(usize) -> T) -> Vec<T> {
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let val = f(i);
        v.push(val);
    }
    v
}

#[macro_export]
macro_rules! retry {
    ($f:expr) => {{
        let f = $f;
        loop {
            match f() {
                Ok(x) => break x,
                Err(e) => {
                    log::error!("{:?}", e);
                }
            }
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::GroupBy;

    #[test]
    fn test_group_mod2() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = addrs.group_by(|x| x % 2);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[&0], vec![0, 2, 4, 6, 8]);
        assert_eq!(groups[&1], vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn test_group_identity() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = addrs.group_by(|x| *x);
        for (i, group) in groups {
            assert_eq!(group.len(), 1);
            assert_eq!(group[0], i);
        }
    }

    #[test]
    fn test_group_prefix() {
        let addrs = vec!["apple", "banana", "apricot", "blueberry"];
        let groups = addrs.group_by(|x| &x[0..1]);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups["a"], vec!["apple", "apricot"]);
        assert_eq!(groups["b"], vec!["banana", "blueberry"]);
    }
}
