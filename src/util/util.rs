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
