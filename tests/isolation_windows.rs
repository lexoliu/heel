//! What the Windows sandbox does beyond the shared guarantees.
//!
//! The guarantees every backend owes -- reachable paths are the ones granted,
//! execution is a right of its own, a container without `internetClient` has no
//! network -- are asserted once in `guarantees.rs`, with this platform supplying
//! only the way to ask. What is left here is what only an AppContainer does:
//! Windows hands each container a temp directory inside its own package folder
//! and redirects `TEMP` there, overriding whatever the sandbox sets.

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::Output;

use heel::{Access, Sandbox, SandboxConfig, SandboxConfigBuilder};

/// Run `script` with `cmd.exe` inside `sandbox`.
async fn cmd(sandbox: &Sandbox<impl heel::NetworkPolicy>, script: &str) -> Output {
    sandbox
        .command("cmd.exe")
        .arg("/C")
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

#[tokio::test]
async fn the_temp_directory_is_private_to_the_container() {
    // Windows gives each AppContainer its own temp directory inside its package
    // folder and redirects `TEMP` there, overriding whatever the sandbox sets.
    // That is stronger than pointing at the working directory, not weaker: no
    // other container and no other user can read it.
    let sandbox = default_sandbox().await;

    let output = cmd(&sandbox, "echo %TEMP%").await;
    let temp = stdout(&output);
    assert!(
        temp.contains("\\Packages\\"),
        "temp must be the container's own, got {temp:?}"
    );

    let written = cmd(
        &sandbox,
        "echo written> %TEMP%\\probe.txt && type %TEMP%\\probe.txt",
    )
    .await;
    assert_eq!(stdout(&written), "written", "{}", stderr(&written));
}

#[tokio::test]
async fn a_writable_grant_lets_the_container_rename_and_remove_what_it_wrote() {
    // rustc emits `.rmeta` by writing a scratch file beside the output and
    // renaming it over the final name, then removing the scratch directory.
    // On Windows a rename is a delete of the source name, and a write grant
    // without the delete bits denies it — which is how a sandboxed build met
    // "Access is denied" writing its first `.rmeta`. `Access::WRITE` promises
    // creating and removing entries, so the grant has to carry them.
    let dir = tempfile::tempdir().expect("tempdir");
    let config = SandboxConfigBuilder::default()
        .grant(dir.path(), Access::WRITE)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");
    let root = dir.path().display();

    for (step, script, expected) in [
        (
            "file create in the granted root",
            format!("echo written> {root}\\direct.txt && type {root}\\direct.txt"),
            "written",
        ),
        (
            "mkdir under the grant",
            format!("mkdir {root}\\rmeta-tmp"),
            "",
        ),
        (
            "file create in a container-made child",
            format!("echo written> {root}\\rmeta-tmp\\full.rmeta"),
            "",
        ),
        (
            "rename within the grant",
            format!(
                "move /y {root}\\rmeta-tmp\\full.rmeta {root}\\lib.rmeta && type {root}\\lib.rmeta"
            ),
            "written",
        ),
        (
            "delete file and tree",
            format!("del {root}\\direct.txt && rd /s /q {root}\\rmeta-tmp"),
            "",
        ),
    ] {
        let output = cmd(&sandbox, &script).await;
        if stdout(&output) != expected {
            // Diagnose the denial from inside the container: the file's
            // effective ACL and the token's groups say whether the grant even
            // reached the object.
            for probe in [
                format!("C:\\Windows\\System32\\icacls.exe {root}\\rmeta-tmp\\full.rmeta"),
                format!("C:\\Windows\\System32\\icacls.exe {root}"),
                String::from("C:\\Windows\\System32\\whoami.exe /groups /fo list"),
            ] {
                let out = cmd(&sandbox, &probe).await;
                eprintln!("[{step}] {probe} =>\n{}{}", stdout(&out), stderr(&out));
            }
        }
        assert_eq!(
            stdout(&output),
            expected,
            "{step} failed: status={:?} stderr={:?}",
            output.status.code(),
            stderr(&output)
        );
    }
}

#[tokio::test]
async fn a_granted_directory_opens_children_deeper_than_max_path() {
    // A granted tree is walked so its existing children can be ACL'd, and a
    // tree like a cargo registry can nest past MAX_PATH. The named security
    // APIs refuse such paths unless they are spelled verbatim, and `read_dir`
    // cannot list a directory that deep either, so the grant once failed on
    // the first child it could not even name. `std::fs` accepts verbatim
    // `\\?\` paths and bypasses the limit, which is how the host stages the
    // tree; the grant itself stays an ordinary path, as a caller's would.
    let dir = tempfile::tempdir().expect("tempdir");
    let mut deep = PathBuf::from(format!(r"\\?\{}", dir.path().display()));
    while deep.as_os_str().len() < 300 {
        deep.push("a-directory-deeper-than-max-path");
    }
    std::fs::create_dir_all(&deep).expect("the host stages a tree past MAX_PATH");
    let staged = deep.join("staged.txt");
    std::fs::write(&staged, "deep-value").expect("the host stages a file");

    let config = SandboxConfigBuilder::default().readable(dir.path()).build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    // `type` is a cmd builtin, so it needs no PATH lookup inside the
    // container — the one the other probes lean on for the same reason —
    // and it opens a verbatim `\\?\` path like any other.
    let output = cmd(&sandbox, &format!("type {}", staged.display())).await;
    assert_eq!(stdout(&output), "deep-value", "{}", stderr(&output));
}

/// Stage a real program and a file for it to read into `dir`.
///
/// The copy mirrors how callers stage tool directories: the file lands before
/// the sandbox exists, so only the grant walk can have opened it.
fn stage_program(dir: &Path) -> (PathBuf, PathBuf) {
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    let staged = dir.join("staged-findstr.exe");
    std::fs::copy(format!("{system_root}\\System32\\findstr.exe"), &staged)
        .expect("the host stages an executable");
    let haystack = dir.join("haystack.txt");
    std::fs::write(&haystack, "needle").expect("the host stages a file to search");
    (staged, haystack)
}

/// A sandbox that grants `dir` read-and-execute.
async fn exec_granted_sandbox(dir: &Path) -> Sandbox {
    let config = SandboxConfigBuilder::default()
        .grant(dir, Access::READ | Access::EXEC)
        .build();
    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

/// Compile `run_child.rs`, the program that reproduces the production spawn
/// shape: a process inside the container starting another by full path with
/// `Command::output`, whose stdin is `NUL`.
///
/// The binary is staged alongside the target so the same grant covers both —
/// the grant walk must see it, so it is built before the sandbox exists.
fn compile_runner(dir: &Path) -> PathBuf {
    let source = dir.join("run_child.rs");
    std::fs::write(&source, include_str!("fixtures/run_child.rs"))
        .expect("the host writes the runner source");
    let runner = dir.join("run-child.exe");
    let output = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg("-O")
        .arg("-o")
        .arg(&runner)
        .arg(&source)
        .output()
        .expect("the host compiles the runner");
    assert!(
        output.status.success(),
        "rustc: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    runner
}

/// Run the staged program through a child of the container.
///
/// `Sandbox::command` launches the runner; the runner is what spawns the
/// staged program, by full path, with `Command::output` — the shape a build
/// tool takes when it probes a staged wrapper. The runner forwards the
/// child's streams, so `needle` reaching stdout proves the whole chain ran.
async fn run_staged_from_inside(sandbox: &Sandbox<impl heel::NetworkPolicy>, dir: &Path) -> Output {
    sandbox
        .command(dir.join("run-child.exe").to_str().expect("UTF-8 path"))
        .arg(dir.join("staged-findstr.exe").to_str().expect("UTF-8 path"))
        .arg("needle")
        .arg(dir.join("haystack.txt").to_str().expect("UTF-8 path"))
        .output()
        .await
        .expect("the runner launches")
}

/// Assert the chain ran end to end.
fn assert_needle(output: &Output) {
    assert!(
        output.status.success() && stdout(output).contains("needle"),
        "the staged program must run inside the sandbox: status={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        stdout(output),
        stderr(output)
    );
}

#[tokio::test]
async fn a_granted_directory_lets_the_container_run_staged_programs() {
    // A grant that allows execute must open the directory's programs to the
    // container exactly as much as the system's own. The binary is copied in
    // before the sandbox exists — so only the grant walk can have opened it —
    // and a process inside the container runs it afterwards, which is the
    // shape a build tool spawning a staged wrapper takes.
    let dir = tempfile::tempdir().expect("tempdir");
    stage_program(dir.path());
    compile_runner(dir.path());
    let sandbox = exec_granted_sandbox(dir.path()).await;

    assert_needle(&run_staged_from_inside(&sandbox, dir.path()).await);
}

#[tokio::test]
async fn a_staged_program_runs_when_spawned_by_full_path() {
    // Spawning the staged file itself takes the launch path rather than a
    // child of the container: the program is resolved, granted read+execute
    // on itself, and started inside the container.
    let dir = tempfile::tempdir().expect("tempdir");
    let (staged, haystack) = stage_program(dir.path());
    let sandbox = exec_granted_sandbox(dir.path()).await;

    let output = sandbox
        .command(staged.to_str().expect("the staged path is UTF-8"))
        .arg("needle")
        .arg(haystack.to_str().expect("the haystack path is UTF-8"))
        .output()
        .await
        .expect("the staged program launches");
    assert_needle(&output);
}

#[tokio::test]
async fn a_granted_directory_at_the_drive_root_lets_the_container_run_staged_programs() {
    // The failure this is a reproduction of staged its tools directory
    // directly under `C:\`, whose only ancestor is the drive root itself.
    // Staging under a temp directory instead would put ancestors with
    // explicit traverse grants between the program and the root, so the same
    // scenario is staged at the root here.
    let dir = tempfile::Builder::new()
        .prefix("heel-exec-")
        .tempdir_in("C:\\")
        .expect("a directory at the drive root");
    stage_program(dir.path());
    compile_runner(dir.path());
    let sandbox = exec_granted_sandbox(dir.path()).await;

    assert_needle(&run_staged_from_inside(&sandbox, dir.path()).await);
}
