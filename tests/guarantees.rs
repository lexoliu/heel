//! The guarantees the sandbox makes, asserted on every platform it supports.
//!
//! Organised by guarantee rather than by backend. Each of the isolation bugs
//! this crate has had was the same shape: something promised in one place and
//! enforced in one backend, with nothing checking the others agreed. Landlock
//! granted execute on every writable path while SBPL denied it; `clone3` went
//! unfiltered on aarch64 while x86_64 blocked it; NTFS spells "run this file"
//! and "enter this directory" with one bit, so Windows granted execute
//! wherever the sandbox could write. Three absences, one cause: the guarantees
//! were written down once and checked per backend.
//!
//! So the guarantees are the tests here, and what varies is only how a platform
//! is asked. [`Probes`] holds those incantations, every item required, one
//! implementation per platform. Adding a backend means writing its probes, and
//! leaving one out is a compile error rather than a guarantee that quietly
//! stops being checked there.
//!
//! Anything true of only one platform belongs in `isolation.rs` or
//! `isolation_windows.rs`, which cover what a single backend does beyond this.

#![cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
#![allow(clippy::unwrap_used)]

use std::path::Path;
use std::process::Output;

use heel::{Sandbox, SandboxConfig};

/// How to ask one platform to do the things the guarantees are about.
trait Probes {
    /// A shell, and the flag that makes it run one command string.
    const SHELL: (&'static str, &'static str);

    /// Write a known string into the working directory and read it back.
    /// Must print `written`.
    const WRITE_AND_READ_BACK: &'static str;

    /// Print `FOUND` if the tool the network probe needs is present.
    const FETCH_TOOL_PRESENT: &'static str;

    /// Attempt to fetch a URL, printing `BLOCKED` if it fails.
    const FETCH: &'static str;

    /// Print `unset` when no proxy variable is set.
    const PRINT_PROXY: &'static str;

    /// Create a runnable program in the working directory. Must succeed.
    const CREATE_PROGRAM: &'static str;

    /// The file [`Probes::CREATE_PROGRAM`] creates, inside the working
    /// directory.
    const PROGRAM_NAME: &'static str;

    /// Run the program that [`Probes::CREATE_PROGRAM`] created.
    const RUN_PROGRAM: &'static str;

    /// Put whatever [`Probes::CREATE_PROGRAM`] needs into the working
    /// directory.
    ///
    /// A platform whose programs are ordinary text needs nothing here; one that
    /// requires a real executable cannot always build it inside the sandbox, so
    /// the host stages it.
    fn stage(working_dir: &Path);

    /// Read the file at `path`, which lies outside the sandbox.
    fn read(path: &Path) -> String;

    /// Write to `path`, which lies outside the sandbox.
    fn write(path: &Path) -> String;
}

/// The probes for this platform.
struct Platform;

#[cfg(unix)]
impl Probes for Platform {
    const SHELL: (&'static str, &'static str) = ("/bin/sh", "-c");
    const WRITE_AND_READ_BACK: &'static str = "printf %s written > probe.txt && cat probe.txt";
    const FETCH_TOOL_PRESENT: &'static str = "command -v curl >/dev/null && echo FOUND";
    const FETCH: &'static str = "curl --silent --max-time 5 http://example.com || echo BLOCKED";
    const PRINT_PROXY: &'static str = "printf %s \"${HTTP_PROXY:-unset}\"";
    const CREATE_PROGRAM: &'static str =
        "printf '#!/bin/sh\\necho executed\\n' > payload.sh && chmod +x payload.sh";
    const PROGRAM_NAME: &'static str = "payload.sh";
    const RUN_PROGRAM: &'static str = "./payload.sh";

    fn stage(_working_dir: &Path) {}

    fn read(path: &Path) -> String {
        format!("cat {}", path.display())
    }

    fn write(path: &Path) -> String {
        format!("printf %s escaped > {}", path.display())
    }
}

#[cfg(windows)]
impl Probes for Platform {
    const SHELL: (&'static str, &'static str) = ("cmd.exe", "/C");
    const WRITE_AND_READ_BACK: &'static str = "echo written> probe.txt && type probe.txt";
    const FETCH_TOOL_PRESENT: &'static str = "if exist %SystemRoot%\\System32\\curl.exe echo FOUND";
    const FETCH: &'static str = "curl.exe --silent --max-time 5 http://example.com || echo BLOCKED";
    // `if not defined`, because `cmd.exe` leaves an unset variable as the
    // literal `%HTTP_PROXY%` rather than expanding it to nothing, so comparing
    // it against an empty string is false exactly when the variable is absent.
    const PRINT_PROXY: &'static str = "if not defined HTTP_PROXY echo unset";
    // A batch file would prove nothing: `cmd.exe` interprets one after merely
    // reading it, which execute rights do not govern. It has to be a real
    // program, and the container cannot read the system's own, so the host
    // stages one for the sandbox to copy.
    const CREATE_PROGRAM: &'static str = "copy /Y source.exe payload.exe";
    const PROGRAM_NAME: &'static str = "payload.exe";
    const RUN_PROGRAM: &'static str = "payload.exe";

    fn stage(working_dir: &Path) {
        let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
        // Written rather than copied: `std::fs::copy` goes through CopyFileExW,
        // which can carry the source's own permissions onto the destination
        // instead of letting it inherit the working directory's.
        let program = std::fs::read(format!("{system_root}\\System32\\whoami.exe"))
            .expect("the host reads a program to stage");
        std::fs::write(working_dir.join("source.exe"), program).expect("the host stages it");
    }

    fn read(path: &Path) -> String {
        format!("type \"{}\"", path.display())
    }

    fn write(path: &Path) -> String {
        format!("echo escaped> \"{}\"", path.display())
    }
}

/// Run one command string through the platform's shell inside `sandbox`.
async fn shell(sandbox: &Sandbox<impl heel::NetworkPolicy>, script: &str) -> Output {
    sandbox
        .command(Platform::SHELL.0)
        .arg(Platform::SHELL.1)
        .arg(script)
        .output()
        .await
        .expect("the shell runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).trim().to_string()
}

/// A sandbox with the default, deny-everything configuration.
async fn default_sandbox() -> Sandbox {
    Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

/// A file outside the sandbox holding something recognisable.
fn secret_file() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("secret.txt");
    std::fs::write(&path, "token-value").expect("writes");
    (dir, path)
}

#[tokio::test]
async fn the_working_directory_is_readable_and_writable() {
    let sandbox = default_sandbox().await;
    let output = shell(&sandbox, Platform::WRITE_AND_READ_BACK).await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "written");
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_readable() {
    let (_dir, secret) = secret_file();
    let sandbox = default_sandbox().await;

    let output = shell(&sandbox, &Platform::read(&secret)).await;

    assert!(
        !stdout(&output).contains("token-value"),
        "reading {} must fail, but it printed {:?}",
        secret.display(),
        stdout(&output)
    );
}

#[tokio::test]
async fn files_outside_the_sandbox_are_not_writable() {
    let dir = tempfile::tempdir().expect("tempdir");
    let target = dir.path().join("escaped.txt");
    let sandbox = default_sandbox().await;

    shell(&sandbox, &Platform::write(&target)).await;

    assert!(
        !target.exists(),
        "{} must not have been created",
        target.display()
    );
}

#[tokio::test]
async fn nothing_the_sandbox_can_write_can_be_run() {
    // The guarantee that has been absent on two of the three backends at
    // different times, each time because "may write here" and "may run this"
    // are spelled differently by every kernel.
    let sandbox = default_sandbox().await;
    let working_dir = sandbox.working_dir().to_path_buf();
    Platform::stage(&working_dir);

    // Creating the program has to succeed, or refusing to run it would prove
    // nothing: a probe that never produced a payload passes for the wrong
    // reason, which is how this guarantee went unchecked on Windows.
    let created = shell(&sandbox, Platform::CREATE_PROGRAM).await;
    assert!(
        working_dir.join(Platform::PROGRAM_NAME).is_file(),
        "the sandbox must be able to write {}, or running it proves nothing: {}",
        Platform::PROGRAM_NAME,
        stderr(&created)
    );

    let ran = shell(&sandbox, Platform::RUN_PROGRAM).await;
    assert!(
        !ran.status.success() && !stdout(&ran).contains("executed"),
        "a program the sandbox wrote must not run, but it printed {:?}",
        stdout(&ran)
    );
}

#[tokio::test]
async fn outbound_traffic_is_denied_without_a_policy() {
    let sandbox = default_sandbox().await;

    // Guard against passing because the tool is missing rather than because the
    // connection was refused.
    let present = shell(&sandbox, Platform::FETCH_TOOL_PRESENT).await;
    assert_eq!(
        stdout(&present),
        "FOUND",
        "the network probe needs its tool to be present"
    );

    let output = shell(&sandbox, Platform::FETCH).await;

    assert!(
        stdout(&output).contains("BLOCKED"),
        "outbound traffic must be refused, got {:?}",
        stdout(&output)
    );
}

#[tokio::test]
async fn no_proxy_is_advertised_without_network_access() {
    let sandbox = default_sandbox().await;
    let output = shell(&sandbox, Platform::PRINT_PROXY).await;

    assert_eq!(stdout(&output), "unset");
    assert_eq!(sandbox.proxy_url(), None);
}

#[tokio::test]
async fn temporary_files_land_somewhere_the_sandbox_can_write() {
    // Asserted as behaviour rather than as a path: Unix points `TMPDIR` at the
    // working directory, while Windows redirects `TEMP` to a directory private
    // to the container. Both give temporary files a writable home inside the
    // sandbox, which is the guarantee.
    let sandbox = default_sandbox().await;
    let output = shell(&sandbox, Platform::WRITE_AND_READ_BACK).await;

    assert_eq!(stdout(&output), "written", "{}", stderr(&output));
}

#[tokio::test]
async fn the_working_directory_is_removed_when_the_sandbox_is_dropped() {
    let sandbox = default_sandbox().await;
    let working_dir = sandbox.working_dir().to_path_buf();
    assert!(working_dir.exists());

    drop(sandbox);

    assert!(
        !working_dir.exists(),
        "{} must not outlive the sandbox",
        working_dir.display()
    );
}
