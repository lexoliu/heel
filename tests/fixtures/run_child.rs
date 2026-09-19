//! Run the given program with `std::process::Command::output`, forwarding the
//! child's streams and exit code.
//!
//! This is the spawn shape the Windows sandbox must support: a process inside
//! the container starting another by full path with captured output. Rust
//! wires the child's stdin to `NUL` for `output()`, so the spawn opens
//! `\Device\Null` from inside the container — the open an AppContainer cannot
//! perform without a grant on the device.

use std::process::Command;

fn main() {
    let mut args = std::env::args().skip(1);
    let program = args.next().expect("usage: run-child <program> [args...]");
    let output = Command::new(&program)
        .args(args)
        .output()
        .expect("the child runs");
    print!("{}", String::from_utf8_lossy(&output.stdout));
    eprint!("{}", String::from_utf8_lossy(&output.stderr));
    std::process::exit(output.status.code().unwrap_or(1));
}
