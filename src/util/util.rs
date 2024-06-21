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

/*
pub fn retry<F, T>(mut f: F) -> T
where
    F: FnMut() -> anyhow::Result<T>,
{
    loop {
        match f() {
            Ok(x) => return x,
            Err(e) => {
                error!("{:?}", e);
            }
        }
    }
}
*/

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
