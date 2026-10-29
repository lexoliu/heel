//! Measures what the Linux broker costs per call.
//!
//! Runs a loop of create/write/close/unlink and a loop of read opens, each in
//! four sandboxes: with no broker, and with the broker with and without the
//! synchronous wake-up. Run it on the machine whose cost is wanted:
//!
//! ```text
//! cargo run --release --example broker_bench -- [count]
//! ```
//!
//! The count defaults to 100000 operations per loop. The broker's CPU can be
//! read from `/proc/<pid>/task/*/stat` of the `heel-broker` threads while it
//! runs.

#![allow(clippy::print_stdout)]

use std::path::Path;

use heel::{
    DenyAll, ReadDenylist, ResolvedPath, Sandbox, SandboxConfigBuilder, SecurityConfigBuilder,
    WriteDenylist,
};

const WORKLOAD: &str = include_str!("workload.rs");

#[derive(Clone, Copy)]
enum Arrangement {
    NoBroker,
    Broker { sync_wake_up: bool },
}

fn builder(
    arrangement: Arrangement,
    home: &Path,
    workload: &Path,
) -> SandboxConfigBuilder<DenyAll> {
    let security = SecurityConfigBuilder::from_permissive()
        .allow_hardware(false)
        .build();
    let base = SandboxConfigBuilder::default()
        .filesystem_strict(false)
        .security(security)
        .writable_file_system(true)
        .executable(ResolvedPath::new(workload).expect("the workload is a resolved path"));
    match arrangement {
        Arrangement::NoBroker => base,
        Arrangement::Broker { sync_wake_up } => base
            .read_denylist(ReadDenylist::credentials().home(home))
            .write_denylist(WriteDenylist::persistence().home(home))
            .broker_sync_wake_up(sync_wake_up),
    }
}

async fn measure(
    sandbox: &Sandbox<DenyAll>,
    workload: &Path,
    mode: &str,
    directory: &Path,
    count: u64,
) -> f64 {
    let output = sandbox
        .command(workload.to_str().expect("UTF-8 path"))
        .args([
            mode,
            directory.to_str().expect("UTF-8 path"),
            &count.to_string(),
        ])
        .output()
        .await
        .expect("the workload runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse()
        .expect("a number of microseconds")
}

#[tokio::main]
async fn main() {
    let count: u64 = std::env::args()
        .nth(1)
        .map_or(100_000, |count| count.parse().expect("a count"));
    let scratch = tempfile::tempdir().expect("scratch directory");
    let home = std::fs::canonicalize(scratch.path()).expect("canonical path");
    std::fs::create_dir_all(home.join(".ssh")).expect("stand-in credentials");
    std::fs::write(home.join(".ssh/id_ed25519"), "secret").expect("stand-in credentials");
    let work = home.join("work");
    std::fs::create_dir(&work).expect("work directory");

    let source = home.join("workload.rs");
    std::fs::write(&source, WORKLOAD).expect("workload source");
    let workload = home.join("workload");
    let compiled = std::process::Command::new("rustc")
        .args(["--edition=2021", "-O", "-o"])
        .arg(&workload)
        .arg(&source)
        .status()
        .expect("rustc runs");
    assert!(compiled.success(), "the workload did not compile");

    println!("{count} operations per loop; microseconds per operation");
    println!(
        "{:<28} {:>14} {:>14}",
        "arrangement", "create+unlink", "read open"
    );
    for (name, arrangement) in [
        ("no broker", Arrangement::NoBroker),
        (
            "broker, sync wake-up on",
            Arrangement::Broker { sync_wake_up: true },
        ),
        (
            "broker, sync wake-up off",
            Arrangement::Broker {
                sync_wake_up: false,
            },
        ),
    ] {
        let sandbox = Sandbox::with_config_and_executor(
            builder(arrangement, &home, &workload).build(),
            executor_core::tokio::TokioGlobal,
        )
        .await
        .expect("the sandbox starts");
        let create = measure(&sandbox, &workload, "create", &work, count).await;
        let read = measure(&sandbox, &workload, "read", &work, count).await;
        println!("{name:<28} {create:>14.2} {read:>14.2}");
    }
}
