use rand::distributions::uniform::SampleUniform;
use rand::Rng;
use std::ops::{Div, Mul, Rem};

pub struct Range<T: SampleUniform> {
    min: T,
    max: T,
    step: T,
    dist: rand::distributions::Uniform<T>,
}

impl<
        T: Copy
            + PartialOrd
            + From<u8>
            + SampleUniform
            + Div<Output = T>
            + Rem<Output = T>
            + Mul<Output = T>,
    > Range<T>
{
    pub fn new(min: T, max: T) -> Self {
        let step = T::from(1);
        let dist = rand::distributions::Uniform::new(min, max);
        Self {
            min,
            max,
            step,
            dist,
        }
    }
    /*
        pub fn new_with_step(min: T, max: T, step: T) -> Self {
            if min % step != T::from(0) || max % step != T::from(0) {
                panic!("Range failed: min and max must both be divisible by step.");
            }
            let dist = rand::distributions::Uniform::new(min / step, max / step);
            Self {
                min,
                max,
                step,
                dist,
            }
        }
    */
    pub fn get_random_number<R: Rng>(&self, gen: &mut R) -> T {
        if self.min == self.max {
            return self.min;
        } else if self.max < self.min {
            return self.min;
        }
        let number = gen.sample(&self.dist);
        if self.step != T::from(1) {
            return number * self.step;
        }
        number
    }

    /*pub fn get_random_number_with_bound<R: Rng>(&self, upper_bound: T, gen: &mut R) -> T {
        let number = if self.max > upper_bound {
            Self::new(self.min, upper_bound).get_random_number(gen)
        } else {
            gen.sample(&self.dist)
        };
        if self.step != T::from(1) {
            return number * self.step;
        }
        number
    }*/
}
