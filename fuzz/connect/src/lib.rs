mod input;

use input::{CustomFuzzerTestOneInput, TestCase};
use libafl::{executors::ExitKind, inputs::BytesInput};
use piv_fuzz_common::{generate_coverage, launch_fuzzer};
use std::mem;

#[no_mangle]
pub fn main() -> i32 {
    let harness = |input: &BytesInput| {
        unsafe {
            let mut tc: TestCase = mem::zeroed();
            tc.from(input);
            CustomFuzzerTestOneInput(&tc as *const TestCase);
        }
        ExitKind::Ok
    };

    if cfg!(feature = "coverage") {
        generate_coverage(harness);
    } else {
        launch_fuzzer(harness);
    }
    0
}
