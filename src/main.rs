mod jitter;

use jitter::JitStrict;

fn main() {
    let j = jitter::CodeJitter{};
    j.jit();
}
