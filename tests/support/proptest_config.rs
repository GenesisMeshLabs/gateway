//! Settings shared by the property tests (`tests/properties.rs` and the
//! `properties` module of `src/gateway/services.rs`).
//!
//! Deterministic by default: a fixed seed, so CI and the merge queue run the
//! same cases every time and a failure is a change, not a draw. No failure
//! files are written: a failure prints its minimal input and seed.
//!
//! - `PROPTEST_RANDOM=1`: a new random seed every run, to look for failures.
//! - `PROPTEST_RNG_SEED=<n>`: replay one seed (printed by a failing run).
//! - `PROPTEST_CASES=<n>`: run more (or fewer) cases.

use proptest::test_runner::{Config, RngSeed};

/// The seed every run uses unless the environment says otherwise.
pub const SEED: u64 = 0x6765_6e65_7369_736d;

/// The configuration for a property test of `cases` cases.
pub fn config(cases: u32) -> Config {
    let set = |name: &str| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    // `Config::default()` already reads PROPTEST_CASES and PROPTEST_RNG_SEED.
    let mut config = Config::default();
    if !set("PROPTEST_CASES") {
        config.cases = cases;
    }
    if !set("PROPTEST_RNG_SEED") && !set("PROPTEST_RANDOM") {
        config.rng_seed = RngSeed::Fixed(SEED);
    }
    config.failure_persistence = None;
    config
}
