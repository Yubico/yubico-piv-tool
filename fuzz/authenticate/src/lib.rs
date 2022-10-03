mod input;

use clap::Parser;
use input::{CustomFuzzerTestOneInput, TestCase};
use libafl::{executors::ExitKind, inputs::BytesInput};
use piv_fuzz_common::{launch_fuzzer, CliArgs};

#[no_mangle]
pub fn main() -> i32 {
    let cli_args = CliArgs::parse();
    if !cli_args.triage_run {
        libafl_main(&cli_args);
    }
    0
}

#[no_mangle]
pub fn libafl_main(cli_args: &CliArgs) {
    let harness = |input: &BytesInput| {
        unsafe {
            CustomFuzzerTestOneInput(&TestCase::from(input) as *const TestCase);
        }
        ExitKind::Ok
    };
    launch_fuzzer(cli_args, harness);
}
