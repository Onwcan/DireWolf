//! libFuzzer entry point. The invariants are in the shared target module.
#![no_main]

#[path = "../../crates/dwkd-authority/tests/fuzz_targets/mod.rs"]
mod targets;

libfuzzer_sys::fuzz_target!(|data: &[u8]| targets::policy_evaluate(data));
