use std::collections::HashMap;

pub fn group<F, K: std::hash::Hash + std::cmp::Eq, T>(addrs: Vec<T>, f: F) -> Vec<Vec<T>>
where
    F: Fn(&T) -> K,
{
    let mut idx_lookup = HashMap::new();
    let mut out = vec![];
    for addr in addrs {
        let k = f(&addr);
        let idx = idx_lookup.entry(k).or_insert(out.len());
        if *idx == out.len() {
            out.push(vec![]);
        }
        out[*idx].push(addr);
    }
    out
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
    use crate::util::group;

    #[test]
    fn test_group_mod2() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = group(addrs, |x| x % 2);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0], vec![0, 2, 4, 6, 8]);
        assert_eq!(groups[1], vec![1, 3, 5, 7, 9]);
    }

    #[test]
    fn test_group_identity() {
        let addrs = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let groups = group(addrs, |x| *x);
        for (i, group) in groups.iter().enumerate() {
            assert_eq!(group.len(), 1);
            assert_eq!(group[0], i);
        }
    }
}
