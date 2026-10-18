//! The netf binary: a runtime, [`netf::run`], and the exit code.
//!
//! Everything else is in the library. This file starts a single-threaded
//! Tokio runtime, handles Ctrl+C, prints the result, and exits. One thread
//! is enough: netf is I/O bound, and it runs a handful of HTTP requests at
//! a time.

use std::{
    io::{self, Write as _},
    process,
    sync::Arc,
};

use netf::{Invocation, Notice, Outcome};

/// The exit code after Ctrl+C: 128 + SIGINT, as shells report it.
const INTERRUPTED: u8 = 130;

fn main() {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("netf: cannot start: {error}");
            process::exit(1);
        }
    };
    let outcome = runtime.block_on(interruptible(
        Invocation::from_process(),
        tokio::signal::ctrl_c(),
    ));
    // Don't drop the runtime. Dropping it waits for the blocking tasks that
    // an interrupted run may leave behind. `exit` ends them with the
    // process.
    let mut stdout = io::stdout().lock();
    if let Err(error) = stdout
        .write_all(&outcome.stdout)
        .and_then(|()| stdout.flush())
    {
        // `netf … | head` closes the pipe early. A closed pipe is not a
        // failure.
        if error.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("netf: stdout: {error}");
            process::exit(1);
        }
    }
    process::exit(i32::from(outcome.code));
}

/// Runs `invocation` until it ends or `interrupt` fires.
///
/// The notice of the interrupt goes through the reporter of the run, so a
/// progress line on the terminal is erased first. The interrupt is checked
/// before the run.
async fn interruptible(
    invocation: Invocation,
    interrupt: impl Future<Output = io::Result<()>>,
) -> Outcome {
    let reporter = Arc::clone(&invocation.reporter);
    tokio::select! {
        biased;
        // Dropping the run drops its downloads. Temporary files delete
        // themselves, and finished cache files are already in place.
        Ok(()) = interrupt => {
            reporter.notice(&Notice::Interrupted);
            Outcome { code: INTERRUPTED, stdout: Vec::new() }
        }
        outcome = netf::run(invocation) => outcome,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use netf::Reporter;

    use super::*;

    /// Records what the run reports, in order.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Reporter for Recorder {
        fn notice(&self, notice: &Notice) {
            self.0.lock().unwrap().push(notice.to_string());
        }

        fn error(&self, message: &str) {
            self.0.lock().unwrap().push(message.to_owned());
        }

        fn progress(&self, _: u32, _: u32, _: &'static str) {}

        fn clear_progress(&self) {}
    }

    #[test]
    fn the_interrupt_is_reported_through_the_reporter() {
        let recorder = Arc::new(Recorder::default());
        let mut invocation = Invocation::from_process();
        invocation.reporter = Arc::clone(&recorder) as Arc<dyn Reporter>;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let outcome = runtime.block_on(interruptible(invocation, async { Ok(()) }));
        assert_eq!(outcome.code, INTERRUPTED);
        assert!(outcome.stdout.is_empty());
        assert_eq!(*recorder.0.lock().unwrap(), ["netf: interrupted"]);
    }
}
