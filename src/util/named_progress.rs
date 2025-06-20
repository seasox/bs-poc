use indicatif::ProgressStyle;

pub trait NamedProgress {
    fn named_bar(name: &str) -> Self;
}

impl NamedProgress for ProgressStyle {
    fn named_bar(name: &str) -> Self {
        let mut fmt = name.to_string();
        for _ in 0..(10 - name.len() as i64 - 1) {
            fmt += " ";
        }
        fmt += " {bar:40.cyan/blue} {pos:>6}/{len:<6} [{elapsed_precise} ({eta} remaining)] {msg}";
        ProgressStyle::default_bar()
            .template(&fmt)
            .unwrap_or(ProgressStyle::default_bar())
    }
}
