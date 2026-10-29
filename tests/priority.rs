//! The scheduling priority a sandbox runs its processes at.
//!
//! The priority is set between fork and exec so that it is inherited rather
//! than applied to one process. What proves that is a grandchild: the sandbox
//! starts a shell, the shell runs a probe, and the probe reports the priority
//! it was born with — a value that came down the whole chain.

#![cfg(any(target_os = "macos", target_os = "linux"))]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::path::{Path, PathBuf};

use heel::{
    Access, CpuPriority, IoPriority, NiceLevel, ProcessPriority, Sandbox, SandboxConfigBuilder,
};

/// The raw I/O policy [`IoPriority::Utility`] must produce.
#[cfg(target_os = "macos")]
const UTILITY_POLICY: i64 = 4; // IOPOL_UTILITY
#[cfg(target_os = "linux")]
const UTILITY_POLICY: i64 = (2 << 13) | 7; // best effort, lowest level

/// The raw I/O policy [`IoPriority::Background`] must produce.
#[cfg(target_os = "macos")]
const BACKGROUND_POLICY: i64 = 3; // IOPOL_THROTTLE
#[cfg(target_os = "linux")]
const BACKGROUND_POLICY: i64 = 3 << 13; // the idle class

/// What the probe found about the process it ran as.
#[derive(Debug, PartialEq, Eq)]
struct Observed {
    nice: i32,
    io: i64,
}

/// Compile the priority probe into `dir` and return its path.
fn compile_probe(dir: &Path) -> PathBuf {
    let source = dir.join("priority_probe.rs");
    std::fs::write(&source, include_str!("fixtures/priority_probe.rs"))
        .expect("the host writes the probe source");

    let binary = dir.join("priority-probe");
    let compiled = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg("-O")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("the host compiles the probe");
    assert!(
        compiled.status.success(),
        "rustc: {}",
        String::from_utf8_lossy(&compiled.stderr)
    );

    binary
}

/// Run the probe two processes below a sandbox configured with `priority`.
async fn observe(priority: ProcessPriority) -> Observed {
    let tools = fixtures::tempdir();
    let probe = compile_probe(tools.path());

    let config = SandboxConfigBuilder::default()
        .grant(tools.path(), Access::READ | Access::EXEC)
        .priority(priority)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    // Through a shell, so the probe is a grandchild of the process the
    // sandbox launched rather than that process itself.
    let output = sandbox
        .command("/bin/sh")
        .arg("-c")
        .arg(probe.display().to_string())
        .output()
        .await
        .expect("the shell runs");
    assert!(
        output.status.success(),
        "the probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    parse(&String::from_utf8_lossy(&output.stdout))
}

/// Read back the `nice=<value> io=<value>` line the probe prints.
fn parse(reported: &str) -> Observed {
    let mut fields = reported.split_whitespace().map(|field| {
        field
            .split_once('=')
            .expect("every field is name=value")
            .1
            .to_owned()
    });

    Observed {
        nice: fields
            .next()
            .expect("a nice value")
            .parse()
            .expect("a number"),
        io: fields
            .next()
            .expect("an io value")
            .parse()
            .expect("a number"),
    }
}

/// The nice value this test process runs at.
fn own_nice() -> i32 {
    // SAFETY: reads the calling process's own nice value.
    unsafe { libc::getpriority(libc::PRIO_PROCESS as _, 0) }
}

/// Where a sandbox configured with `level` lands, given this process's own
/// priority: that many steps below it, but no further than the bottom.
fn expected_nice(level: NiceLevel) -> i32 {
    (own_nice() + i32::from(level.get())).min(i32::from(NiceLevel::HIGHEST.get()))
}

#[tokio::test]
async fn a_lowered_priority_reaches_a_grandchild() {
    let level = NiceLevel::new(3).unwrap();
    let observed = observe(ProcessPriority::new(
        CpuPriority::Nice(level),
        IoPriority::Utility,
    ))
    .await;

    // The level is relative, so the grandchild sits three steps below the
    // process that configured the sandbox — wherever that process itself runs.
    assert_eq!(
        observed,
        Observed {
            nice: expected_nice(level),
            io: UTILITY_POLICY,
        }
    );
}

#[tokio::test]
async fn the_background_policy_reaches_a_grandchild() {
    let observed = observe(ProcessPriority::new(
        CpuPriority::Nice(NiceLevel::HIGHEST),
        IoPriority::Background,
    ))
    .await;

    // The largest reduction cannot overshoot the bottom, whether the host it
    // steps down from is at the default or already niced.
    assert_eq!(
        observed,
        Observed {
            nice: expected_nice(NiceLevel::HIGHEST),
            io: BACKGROUND_POLICY,
        }
    );
}

#[tokio::test]
async fn an_unconfigured_sandbox_lowers_nothing() {
    let observed = observe(ProcessPriority::default()).await;

    assert_eq!(
        observed.nice,
        own_nice(),
        "the nice value must be untouched"
    );
    assert_ne!(observed.io, UTILITY_POLICY);
    assert_ne!(observed.io, BACKGROUND_POLICY);
}
