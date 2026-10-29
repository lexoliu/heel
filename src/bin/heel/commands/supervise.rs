//! `heel supervise`: own a command's whole process tree. See
//! [`heel::supervisor`].

use std::os::fd::{FromRawFd, OwnedFd};
use std::process::ExitCode;

use heel::supervisor::Config;

use crate::cli::SuperviseArgs;
use crate::exit_code_from;

/// Run the command under supervision, exiting as the command did.
pub fn execute(args: SuperviseArgs) -> ExitCode {
    let mut command = args.command.into_iter();
    let Some(program) = command.next() else {
        unreachable!("clap requires a command");
    };
    // SAFETY: the library started this process with the socket open at this
    // descriptor and nothing else in the process refers to it.
    let control = unsafe { OwnedFd::from_raw_fd(args.control_fd) };
    let config = Config {
        mode: args.mode,
        control,
        reap_timeout: args.reap_timeout,
        program,
        args: command.collect(),
    };
    match heel::supervisor::run(config) {
        Ok(code) => exit_code_from(code),
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
