pub trait Anyhow<T> {
    fn anyhow(self) -> anyhow::Result<T>;
}

impl<T, E: std::fmt::Debug> Anyhow<T> for Result<T, E> {
    fn anyhow(self) -> anyhow::Result<T> {
        self.map_err(|e| anyhow::anyhow!("{:?}", e))
    }
}
