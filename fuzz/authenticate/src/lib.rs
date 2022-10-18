mod input;

use input::{CustomFuzzerTestOneInput, TestCase};
use libafl::{executors::ExitKind, inputs::BytesInput};
use piv_fuzz_common::{generate_coverage, launch_fuzzer};

#[no_mangle]
pub fn main() -> i32 {
    let harness = |input: &BytesInput| {
        unsafe {
            CustomFuzzerTestOneInput(&TestCase::from(input) as *const TestCase);
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
