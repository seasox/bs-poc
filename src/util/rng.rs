use rand::{rngs::StdRng, Error, RngCore, SeedableRng};
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Rng {
    seed: u64,
    #[serde(skip_serializing)]
    rng: StdRng,
}

impl Rng {
    pub fn from_seed(seed: u64) -> Self {
        Self {
            seed,
            rng: StdRng::seed_from_u64(seed),
        }
    }
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.rng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.rng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.rng.fill_bytes(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.rng.try_fill_bytes(dest)
    }
}

impl Clone for Rng {
    fn clone(&self) -> Self {
        Self::from_seed(self.seed)
    }
}

mod test {
    use rand::RngCore;

    use crate::util::Rng;

    #[test]
    fn test_rng_clone() {
        let mut rng = Rng::from_seed(0x42);
        let a = rng.next_u64();
        let mut cloned_rng = rng.clone();
        let b = cloned_rng.next_u64();
        assert_eq!(a, b, "Cloned Rng should start with the same seed");
    }
}
