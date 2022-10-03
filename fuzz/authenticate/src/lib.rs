mod input;

use clap::Parser;
use core::time::Duration;
use input::{CustomFuzzerTestOneInput, TestCase};
use libafl::{
    bolts::{
        core_affinity::Cores,
        current_nanos,
        launcher::Launcher,
        rands::StdRand,
        shmem::{ShMemProvider, StdShMemProvider},
        tuples::{tuple_list, Merge},
    },
    corpus::{InMemoryCorpus, OnDiskCorpus},
    events::EventConfig,
    executors::{inprocess::InProcessExecutor, ExitKind, TimeoutExecutor},
    feedback_or,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::BytesInput,
    monitors::SimpleMonitor,
    mutators::{
        scheduled::{havoc_mutations, tokens_mutations, StdScheduledMutator},
        token_mutations::I2SRandReplace,
        StdMOptMutator,
    },
    observers::{HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, IndexesLenTimeMinimizerScheduler, PowerQueueScheduler,
    },
    stages::{
        calibrate::CalibrationStage, power::StdPowerMutationalStage, StdMutationalStage,
        TracingStage,
    },
    state::StdState,
    Error,
};
use libafl_targets::{libfuzzer_initialize, CmpLogObserver, CMPLOG_MAP, EDGES_MAP, MAX_EDGES_NUM};
use std::{env, path::PathBuf};

#[derive(Parser)]
pub struct CliArgs {
    #[clap(short = 'i', long = "input", parse(from_os_str))]
    input_dir: PathBuf,
    #[clap(short = 'o', long = "output", parse(from_os_str))]
    output_dir: PathBuf,
    #[clap(short = 't', long = "timeout", default_value = "1000")]
    timeout: u64,
    #[clap(long = "triage-run", action = clap::ArgAction::Set, default_value = "false")]
    triage_run: bool,
}

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
    piv_fuzz_common(cli_args, harness);
}

pub fn piv_fuzz_common<H>(cli_args: &CliArgs, harness: H)
where
    H: FnMut(&BytesInput) -> ExitKind + Clone,
{
    let input_dirs = [PathBuf::from(&cli_args.input_dir)];
    let output_dir = PathBuf::from(&cli_args.output_dir);
    let timeout_ms = Duration::from_millis(cli_args.timeout);
    let shmem_provider = StdShMemProvider::new().expect("Failed to initialize shared memory");
    let monitor = SimpleMonitor::new(|s| println!("{}", s));
    let cores = Cores::from_cmdline("1").unwrap();

    let mut run_client = |state: Option<_>, mut mgr, _core_id| {
        // Create an observation channel using the coverage map
        let edges = unsafe { &mut EDGES_MAP[0..MAX_EDGES_NUM] };
        let edges_observer = HitcountsMapObserver::new(StdMapObserver::new("edges", edges));

        // Create an observation channel to keep track of the execution time
        let time_observer = TimeObserver::new("time");

        // Create the Cmp observer
        let cmplog = unsafe { &mut CMPLOG_MAP };
        let cmplog_observer = CmpLogObserver::new("cmplog", cmplog, true);

        // Feedback to rate the interestingness of an input
        // This one is composed by two Feedbacks in OR
        let mut feedback = feedback_or!(
            // New maximization map feedback linked to the edges observer and the feedback state
            MaxMapFeedback::new_tracking(&edges_observer, true, false),
            // Time feedback, this one does not need a feedback state
            TimeFeedback::new_with_observer(&time_observer)
        );

        // A feedback to choose if an input is a solution or not
        let mut objective = feedback_or!(CrashFeedback::new(), TimeoutFeedback::new());

        // If not restarting, create a State from scratch
        let mut state = state.unwrap_or_else(|| {
            StdState::new(
                // RNG
                StdRand::with_seed(current_nanos()),
                // Corpus that will be evolved, we keep it in memory for performance
                InMemoryCorpus::new(),
                // Corpus in which we store solutions (crashes in this example),
                // on disk so the user can get them after stopping the fuzzer
                OnDiskCorpus::new(output_dir.clone()).unwrap(),
                // States of the feedbacks.
                // The feedbacks can report the data that should persist in the State.
                &mut feedback,
                // Same for objective feedbacks
                &mut objective,
            )
            .unwrap()
        });

        let args: Vec<String> = env::args().collect();
        if libfuzzer_initialize(&args) == -1 {
            println!("Warning: LLVMFuzzerInitialize failed with -1")
        }

        let map_feedback = MaxMapFeedback::new_tracking(&edges_observer, true, false);
        let calibration = CalibrationStage::new(&map_feedback);

        let i2s =
            StdMutationalStage::new(StdScheduledMutator::new(tuple_list!(I2SRandReplace::new())));

        let mutator = StdMOptMutator::new(
            &mut state,
            havoc_mutations().merge(tokens_mutations()),
            7,
            5,
        )?;

        let power = StdPowerMutationalStage::new(mutator, &edges_observer);

        // A minimization+queue policy to get testcasess from the corpus
        let scheduler =
            IndexesLenTimeMinimizerScheduler::new(PowerQueueScheduler::new(PowerSchedule::FAST));

        // A fuzzer with feedbacks and a corpus scheduler
        let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

        // The wrapped harness function, calling out to the LLVM-style harness
        //let harness = |input: &BytesInput| {
        //    unsafe {
        //        CustomFuzzerTestOneInput(&TestCase::from(input) as *const TestCase);
        //    }
        //    ExitKind::Ok
        //};
        let mut executor_harness = harness.clone();
        let mut tracing_harness = harness.clone();

        // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
        let mut executor = TimeoutExecutor::new(
            InProcessExecutor::new(
                &mut executor_harness,
                tuple_list!(edges_observer, time_observer),
                &mut fuzzer,
                &mut state,
                &mut mgr,
            )?,
            timeout_ms,
        );

        // Setup a tracing stage in which we log comparisons
        let tracing = TracingStage::new(InProcessExecutor::new(
            &mut tracing_harness,
            tuple_list!(cmplog_observer),
            &mut fuzzer,
            &mut state,
            &mut mgr,
        )?);

        // The order of the stages matter!
        let mut stages = tuple_list!(calibration, tracing, i2s, power);

        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &input_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &input_dirs));

        fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;
        Ok(())
    };

    match Launcher::builder()
        .shmem_provider(shmem_provider)
        .configuration(EventConfig::from_build_id())
        .monitor(monitor)
        .run_client(&mut run_client)
        .cores(&cores)
        .broker_port(1337)
        .stdout_file(Some("stdout"))
        .build()
        .launch()
    {
        Ok(_) | Err(Error::ShuttingDown) => (),
        Err(e) => panic!("{:?}", e),
    };
}
