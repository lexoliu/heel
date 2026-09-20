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

use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use heel::ipc::{IpcCommand, IpcRouter, NoArgs};
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

/// Compile a fixture program into `dir` and return its path.
fn compile_fixture(dir: &Path, fixture: &str, output: &str) -> PathBuf {
    let source = dir.join(format!("{fixture}.rs"));
    std::fs::write(
        &source,
        match fixture {
            "run_child" => include_str!("fixtures/run_child.rs"),
            "fs_probe" => include_str!("fixtures/fs_probe.rs"),
            other => unreachable!("no fixture named {other}"),
        },
    )
    .expect("the host writes the fixture source");
    let binary = dir.join(output);
    let output_result = std::process::Command::new("rustc")
        .arg("--edition=2021")
        .arg("-O")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("the host compiles the fixture");
    assert!(
        output_result.status.success(),
        "rustc: {}",
        String::from_utf8_lossy(&output_result.stderr)
    );
    binary
}

#[tokio::test]
async fn a_writable_grant_lets_the_container_rename_and_remove_what_it_wrote() {
    // rustc emits `.rmeta` by writing a scratch file beside the output and
    // renaming it over the final name, then removing the scratch directory.
    // On Windows a rename is a delete of the source name, and a write grant
    // without the delete bits denies it — which is how a sandboxed build met
    // "Access is denied" writing its first `.rmeta`. `Access::WRITE` promises
    // creating and removing entries, so the grant has to carry them.
    //
    // The probe is a staged binary rather than shell builtins so each
    // operation reports its own raw error instead of cmd's single "Access is
    // denied".
    let dir = tempfile::tempdir().expect("tempdir");
    let tools = tempfile::tempdir().expect("tools dir");
    let probe = compile_fixture(tools.path(), "fs_probe", "fs-probe.exe");
    let config = SandboxConfigBuilder::default()
        .grant(dir.path(), Access::WRITE)
        .grant(tools.path(), Access::READ | Access::EXEC)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sandbox
        .command(probe.to_str().expect("the staged path is UTF-8"))
        .arg(dir.path().to_str().expect("the granted path is UTF-8"))
        .output()
        .await
        .expect("the probe launches");
    let report = stdout(&output);
    assert!(
        !report.contains("=err"),
        "write grant must cover the container's own edits: {report} {}",
        stderr(&output)
    );
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
    compile_fixture(dir, "run_child", "run-child.exe")
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

/// A command that counts how often the sandbox called it.
struct Probe {
    calls: Arc<AtomicUsize>,
}

impl IpcCommand for Probe {
    fn name(&self) -> Cow<'static, str> {
        "probe".into()
    }

    type Args = NoArgs;
    type Response = ();

    async fn handle(&self, _args: NoArgs) {
        self.calls.fetch_add(1, Ordering::Relaxed);
    }
}

#[tokio::test]
async fn the_ipc_endpoint_reaches_the_host_from_inside_the_container() {
    // On Windows the IPC endpoint is a named pipe — a kernel object with an
    // access control list of its own, which names nothing an AppContainer
    // token carries by default. A sandboxed process that cannot reach it —
    // a capture wrapper reporting artifacts is the shape that hit this —
    // meets "Access is denied" on its first call. The pipe has to be opened
    // to the container the way the null device is.
    //
    // `heel ipc` is the real client, so this exercises the whole path:
    // connecting to the pipe, the request, dispatch, and the response.
    let calls = Arc::new(AtomicUsize::new(0));
    let config = SandboxConfigBuilder::default()
        .heel_binary(env!("CARGO_BIN_EXE_heel"))
        .ipc(IpcRouter::new().register(Probe {
            calls: Arc::clone(&calls),
        }))
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sandbox
        .command(env!("CARGO_BIN_EXE_heel"))
        .arg("ipc")
        .arg("probe")
        .output()
        .await
        .expect("heel ipc runs");

    assert!(
        output.status.success(),
        "the container must reach the IPC endpoint: status={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        stdout(&output),
        stderr(&output)
    );
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "the handler must run once"
    );
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
