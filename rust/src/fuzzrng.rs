//! Deterministic, zero-dependency PRNG for the in-repo property/differential
//! fuzz harnesses (compiled only under `#[cfg(test)]`).
//!
//! The project forbids third-party crates (`tools/check_zero_deps.sh`) and pins
//! a hermetic stable toolchain, so a coverage-guided fuzzer (libFuzzer/AFL++,
//! which pull in `libfuzzer-sys` and need nightly) would break both invariants.
//! Instead each security-critical FFI entry point is hammered with a large,
//! reproducible stream of structured random inputs while invariants are
//! asserted; a panic (out-of-bounds, arithmetic overflow in debug, `unwrap` on
//! a malformed parse) fails the test, and Rust's own bounds/overflow checks
//! stand in for a sanitizer. Deterministic seeding means a failure reproduces
//! exactly from the seed printed by the harness.
//!
//! SplitMix64 (Steele/Lea/Flood) — a well-distributed, fast, seedable generator
//! with a tiny state, adequate for input generation (not for cryptography).

pub(crate) struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub(crate) fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }

    pub(crate) fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub(crate) fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    /// A value in `0..n` (n == 0 yields 0).
    pub(crate) fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next_u32() % n
        }
    }

    /// Fill `buf` with random bytes.
    pub(crate) fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let word = self.next_u64().to_le_bytes();
            let take = core::cmp::min(8, buf.len() - i);
            buf[i..i + take].copy_from_slice(&word[..take]);
            i += take;
        }
    }
}
