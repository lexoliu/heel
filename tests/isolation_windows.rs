//! What the Windows sandbox does beyond the shared guarantees.
//!
//! The guarantees every backend owes -- reachable paths are the ones granted,
//! execution is a right of its own, a container without `internetClient` has no
//! network -- are asserted once in `guarantees.rs`, with this platform supplying
//! only the way to ask. What is left here is what only an AppContainer does:
//! The backend gives each container its own AppContainer profile folder and
//! sets `LOCALAPPDATA`, `TEMP`, `TMP` and `TMPDIR` to paths beneath it.

#![cfg(target_os = "windows")]
#![allow(clippy::unwrap_used)]

use std::borrow::Cow;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use heel::ipc::{IpcCommand, IpcError, IpcRouter, NoArgs};
use heel::{Access, Grant, Identity, Sandbox, SandboxConfig, SandboxConfigBuilder};

#[path = "fixtures/mod.rs"]
mod fixtures;

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

fn env_value(output: &Output, name: &str) -> String {
    assert!(output.status.success(), "{}", stderr(output));
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            key.eq_ignore_ascii_case(name).then(|| value.to_string())
        })
        .unwrap_or_else(|| {
            panic!(
                "{name} was absent from `set` output {:?}",
                String::from_utf8_lossy(&output.stdout)
            )
        })
}

/// A sandbox with the default, deny-everything configuration.
async fn default_sandbox() -> Sandbox {
    Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

struct IdentityCleanup {
    identity: Identity,
    active: bool,
}

impl IdentityCleanup {
    fn new(identity: Identity) -> Self {
        Self {
            identity,
            active: true,
        }
    }

    fn identity(&self) -> &Identity {
        &self.identity
    }

    fn remove(&mut self) {
        let result = self.identity.remove();
        self.active = false;
        result.expect("the test identity is removed");
    }
}

impl Drop for IdentityCleanup {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.identity.remove()
        {
            tracing::warn!(%error, "failed to remove test identity");
        }
    }
}

#[tokio::test]
async fn the_temp_directory_is_private_to_the_container() {
    // The backend sets TEMP beneath each AppContainer's profile folder, which
    // is private to that container rather than shared with another sandbox.
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
async fn named_sandbox_reads_ordinary_and_persistent_grants() {
    let directory = fixtures::tempdir();
    let ordinary = directory.path().join("ordinary");
    let persistent = directory.path().join("persistent");
    fs::create_dir(&ordinary).expect("the ordinary directory exists");
    fs::create_dir(&persistent).expect("the persistent directory exists");
    let ordinary_file = ordinary.join("ordinary.txt");
    let persistent_file = persistent.join("persistent.txt");
    fs::write(&ordinary_file, "ordinary").expect("the ordinary file is written");
    fs::write(&persistent_file, "persistent").expect("the persistent file is written");
    let mut identity = IdentityCleanup::new(
        Identity::named(format!("t-{:016x}", rand::random::<u64>()))
            .expect("the identity name is valid")
            .persistent_grant(Grant::new(&persistent, Access::READ)),
    );
    let config = SandboxConfigBuilder::default()
        .identity(identity.identity().clone())
        .grant(&ordinary, Access::READ)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("the named sandbox starts");

    let ordinary_output = read_inside(&sandbox, &ordinary_file, "ordinary").await;
    assert!(
        ordinary_output.status.success(),
        "ordinary grant failed: {}",
        stderr(&ordinary_output)
    );
    let persistent_output = read_inside(&sandbox, &persistent_file, "persistent").await;
    assert!(
        persistent_output.status.success(),
        "persistent grant failed: {}",
        stderr(&persistent_output)
    );

    drop(sandbox);
    identity.remove();
}

#[tokio::test]
async fn dropping_one_named_sandbox_preserves_the_other_ordinary_grant() {
    let directory = fixtures::tempdir();
    let file = directory.path().join("shared.txt");
    fs::write(&file, "shared").expect("the shared file is written");
    let mut identity = IdentityCleanup::new(
        Identity::named(format!("t-{:016x}", rand::random::<u64>()))
            .expect("the identity name is valid"),
    );
    let config = || {
        SandboxConfigBuilder::default()
            .identity(identity.identity().clone())
            .grant(directory.path(), Access::READ)
            .build()
    };
    let first = Sandbox::with_config_and_executor(config(), executor_core::tokio::TokioGlobal)
        .await
        .expect("the first named sandbox starts");
    let second = Sandbox::with_config_and_executor(config(), executor_core::tokio::TokioGlobal)
        .await
        .expect("the second named sandbox starts");

    drop(first);
    let output = read_inside(&second, &file, "shared").await;
    assert!(
        output.status.success(),
        "dropping the first sandbox removed the second grant: {}",
        stderr(&output)
    );

    drop(second);
    identity.remove();
}

#[tokio::test]
async fn unrelated_local_app_data_does_not_redirect_container_temp() {
    // A caller-supplied LOCALAPPDATA must not redirect the profile folders
    // Windows derives for the child.
    let unrelated = fixtures::tempdir();
    let unrelated_path = unrelated.path().to_string_lossy().to_string();
    let sandbox = default_sandbox().await;
    let environment = sandbox
        .command("cmd.exe")
        .arg("/C")
        .arg("set LOCALAPPDATA & set TEMP & set TMP & set TMPDIR")
        .env("LOCALAPPDATA", &unrelated_path)
        .env("TEMP", &unrelated_path)
        .env("TMP", &unrelated_path)
        .env("TMPDIR", &unrelated_path)
        .output()
        .await
        .expect("the environment probe runs");
    let local_app_data = env_value(&environment, "LOCALAPPDATA");
    let temp = env_value(&environment, "TEMP");
    let tmp = env_value(&environment, "TMP");
    let tmpdir = env_value(&environment, "TMPDIR");
    let unrelated_lower = unrelated_path.to_ascii_lowercase();

    assert!(
        !local_app_data
            .to_ascii_lowercase()
            .starts_with(&unrelated_lower)
            && !temp.to_ascii_lowercase().starts_with(&unrelated_lower)
            && !tmp.to_ascii_lowercase().starts_with(&unrelated_lower)
            && !tmpdir.to_ascii_lowercase().starts_with(&unrelated_lower),
        "the child must not use the unrelated LOCALAPPDATA {unrelated_path:?}; observed LOCALAPPDATA={local_app_data:?}, TEMP={temp:?}, TMP={tmp:?}, TMPDIR={tmpdir:?}"
    );
    let profile_folder = Path::new(&local_app_data);
    let profile_name = profile_folder
        .parent()
        .and_then(Path::file_name)
        .map(|name| name.to_string_lossy());
    let packages_folder = profile_folder
        .parent()
        .and_then(Path::parent)
        .and_then(Path::file_name);
    assert!(
        profile_folder
            .file_name()
            .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("AC"))
            && profile_name
                .as_ref()
                .is_some_and(|name| name.starts_with("heel-"))
            && packages_folder
                .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("Packages")),
        "LOCALAPPDATA must end in \\Packages\\heel-…\\AC, got {local_app_data:?}"
    );
    let expected_temp = format!("{}\\Temp", local_app_data.trim_end_matches(['\\', '/']));
    assert!(
        temp.eq_ignore_ascii_case(&expected_temp),
        "TEMP must be LOCALAPPDATA\\Temp: LOCALAPPDATA={local_app_data:?}, TEMP={temp:?}"
    );
    assert!(
        tmp.eq_ignore_ascii_case(&expected_temp),
        "TMP must be LOCALAPPDATA\\Temp: LOCALAPPDATA={local_app_data:?}, TMP={tmp:?}"
    );
    assert!(
        temp.eq_ignore_ascii_case(&tmp),
        "TEMP and TMP must agree: TEMP={temp:?}, TMP={tmp:?}"
    );
    assert!(
        tmpdir.eq_ignore_ascii_case(&temp),
        "TMPDIR must equal TEMP: TEMP={temp:?}, TMPDIR={tmpdir:?}"
    );

    let written = sandbox
        .command("cmd.exe")
        .arg("/C")
        .arg("echo written> %TEMP%\\probe.txt && type %TEMP%\\probe.txt")
        .env("LOCALAPPDATA", &unrelated_path)
        .output()
        .await
        .expect("the TEMP round trip runs");
    assert_eq!(stdout(&written), "written", "{}", stderr(&written));
}

#[tokio::test]
async fn passthrough_variables_reach_the_container_under_their_host_spelling() {
    // Windows stores the search path as `Path`, and a caller collecting names
    // from `std::env::vars_os` passes that spelling: a case-sensitive match
    // never saw it, so the container fell back to the System32 default.
    let username = std::env::var("USERNAME").expect("USERNAME is set");
    let path = std::env::var("PATH").expect("PATH is set");
    let config = SandboxConfigBuilder::default()
        .env_passthroughs(["Path", "uSeRnAmE"])
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = cmd(&sandbox, "set USERNAME").await;
    assert_eq!(env_value(&output, "USERNAME"), username);
    let output = cmd(&sandbox, "set PATH").await;
    assert_eq!(env_value(&output, "PATH"), path);
}

#[tokio::test]
async fn an_explicit_path_spelled_path_resolves_a_program_found_only_there() {
    let dir = fixtures::tempdir();
    let probe = dir.path().join("heel-path-probe.exe");
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    std::fs::copy(format!("{system_root}\\System32\\findstr.exe"), &probe)
        .expect("the host stages an executable under a name only PATH finds");
    let haystack = dir.path().join("haystack.txt");
    std::fs::write(&haystack, "needle").expect("the host stages a file to search");

    let path = std::env::join_paths(std::iter::once(dir.path().to_path_buf()).chain(
        std::env::split_paths(&std::env::var_os("PATH").expect("PATH is set")),
    ))
    .expect("the staged directory joins the host search path");
    let config = SandboxConfigBuilder::default()
        .grant(dir.path(), Access::READ | Access::EXEC)
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    let output = sandbox
        .command("heel-path-probe")
        .arg("/c:needle")
        .arg(haystack.to_string_lossy().as_ref())
        .env("Path", path.to_str().expect("the search path is UTF-8"))
        .output()
        .await
        .expect("the staged program resolves through the explicit Path");
    assert!(
        output.status.success() && stdout(&output).contains("needle"),
        "the staged program must run inside the sandbox: status={:?} stdout={:?} stderr={:?}",
        output.status.code(),
        stdout(&output),
        stderr(&output)
    );
}

/// Compile a fixture program into `dir` and return its path.
fn compile_fixture(dir: &Path, fixture: &str, output: &str) -> PathBuf {
    let source = match fixture {
        "run_child" => include_str!("fixtures/run_child.rs"),
        "fs_probe" => include_str!("fixtures/fs_probe.rs"),
        other => unreachable!("no fixture named {other}"),
    };
    fixtures::compile(dir, source, output)
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
    let dir = fixtures::tempdir();
    let tools = fixtures::tempdir();
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
    // A grant's entries propagate to its tree's existing children, and a
    // tree like a cargo registry can nest past MAX_PATH. The named security
    // APIs refuse such paths unless they are spelled verbatim, and `read_dir`
    // cannot list a directory that deep either, so the grant once failed on
    // the first child it could not even name. `std::fs` accepts verbatim
    // `\\?\` paths and bypasses the limit, which is how the host stages the
    // tree; the grant itself stays an ordinary path, as a caller's would.
    let dir = fixtures::tempdir();
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
/// the sandbox exists, so only the grant's propagation can have opened it.
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
/// the grant's propagation must reach it, so it is built before the sandbox
/// exists.
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
    // before the sandbox exists — so only the grant's propagation can have
    // opened it — and a process inside the container runs it afterwards,
    // which is the shape a build tool spawning a staged wrapper takes.
    let dir = fixtures::tempdir();
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
    let dir = fixtures::tempdir();
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

    async fn handle(&self, _args: NoArgs) -> Result<(), IpcError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
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

/// The access control list of `path` as `icacls` prints it, for failure
/// messages. `icacls` is a system binary, so the report works on a runner
/// whose PowerShell security module does not load.
fn acl_listing(path: &Path) -> String {
    let output = std::process::Command::new("icacls")
        .arg(path)
        .output()
        .expect("icacls runs");
    assert!(
        output.status.success(),
        "icacls on {}: {}",
        path.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Search `file` for `needle` with `findstr` inside `sandbox`: a read of the
/// file's contents, with the path passed as its own argument.
async fn read_inside(
    sandbox: &Sandbox<impl heel::NetworkPolicy>,
    file: &Path,
    needle: &str,
) -> Output {
    let system32 =
        Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set")).join("System32");
    sandbox
        .command(system32.join("findstr.exe").to_string_lossy())
        .arg(format!("/c:{needle}"))
        .arg(file.to_string_lossy())
        .output()
        .await
        .expect("findstr runs")
}

/// A sandbox with `path` granted `access`.
async fn sandbox_granting(path: &Path, access: Access) -> heel::Result<Sandbox> {
    let config = SandboxConfigBuilder::default().grant(path, access).build();
    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await
}

#[tokio::test]
async fn a_grant_writes_the_acl_only_where_the_container_lacks_access() {
    // Whether a grant writes the ACL at all is decided by what the
    // container already holds on the path — asked of Windows, not guessed
    // from the path, because a directory under a system root can carry a
    // DACL that opens nothing to a package.
    //
    // (a) `%SystemRoot%\System32` grants ALL APPLICATION PACKAGES read and
    // execute, so the grant must be a skip rather than a write — a write
    // there needs rights the sandbox user does not hold — and a file in it
    // is readable inside without it. The read goes through `findstr` on a
    // known file rather than `cmd`'s `dir`: `dir` queries the volume
    // through the drive root, which grants nothing to an AppContainer, so
    // it fails on every directory, granted or not.
    let system32 =
        Path::new(&std::env::var_os("SystemRoot").expect("SystemRoot is set")).join("System32");
    let sandbox = sandbox_granting(&system32, Access::READ | Access::EXEC)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "granting read/execute on the already-open {} failed; its DACL is {}: {error}",
                system32.display(),
                acl_listing(&system32)
            )
        });
    let hosts = system32.join(r"drivers\etc\hosts");
    let output = read_inside(&sandbox, &hosts, "localhost").await;
    assert!(
        output.status.success(),
        "a file in the already-open directory is readable inside; its DACL is {}: {}",
        acl_listing(&hosts),
        stderr(&output)
    );
    drop(sandbox);

    // (b) A fresh child of %ProgramFiles% with its inherited entries
    // stripped opens nothing to an AppContainer, so the grant has to add
    // real entries — and a runner without the rights to create it meets a
    // real error naming the path.
    let program_files =
        PathBuf::from(std::env::var_os("ProgramFiles").expect("ProgramFiles is set"));
    let child = program_files.join(format!("heel-grant-{}", std::process::id()));
    if let Err(source) = std::fs::create_dir(&child) {
        let error = sandbox_granting(&child, Access::READ | Access::EXEC)
            .await
            .err()
            .expect("a grant that cannot be written fails");
        assert!(
            error.to_string().contains(child.to_string_lossy().as_ref()),
            "the error must name the path it could not grant ({source}): {error}"
        );
        return;
    }

    // `/inheritance:r` removes the entries inherited from Program Files,
    // and the one entry put back opens the tree to Administrators — whom
    // this process runs as — and to nothing an AppContainer token
    // carries. The probe file is written afterwards so it inherits that
    // entry, and with it whatever the grant adds to the directory.
    let stripped = std::process::Command::new("icacls")
        .arg(&child)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)F")
        .output()
        .expect("icacls runs");
    assert!(
        stripped.status.success(),
        "icacls /inheritance:r on {}: {}",
        child.display(),
        String::from_utf8_lossy(&stripped.stderr)
    );
    let probe = child.join("probe.txt");
    std::fs::write(&probe, "heel-probe\n").expect("the probe file is written");

    let sandbox = sandbox_granting(&child, Access::READ | Access::EXEC)
        .await
        .unwrap_or_else(|error| {
            panic!(
                "granting read/execute on {} failed; its DACL is {}: {error}",
                child.display(),
                acl_listing(&child)
            )
        });
    let output = read_inside(&sandbox, &probe, "heel-probe").await;
    drop(sandbox);
    let listing = acl_listing(&probe);
    std::fs::remove_dir_all(&child).expect("the test's Program Files child is removed");
    assert!(
        output.status.success(),
        "a file in the granted directory is readable inside; its DACL is {listing}: {}",
        stderr(&output)
    );
}

/// Poll `children` until all exit or `timeout` passes — stragglers are killed
/// — then collect each one's output. Returns a failure line per child that
/// timed out or exited unsuccessfully, empty when every `role` succeeded.
fn collect_children(mut children: Vec<Child>, role: &str, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut finished = vec![false; children.len()];
    let mut timed_out = vec![false; children.len()];
    loop {
        let mut running = false;
        for (index, child) in children.iter_mut().enumerate() {
            if finished[index] {
                continue;
            }
            if child
                .try_wait()
                .unwrap_or_else(|source| panic!("a {role} cannot be polled: {source}"))
                .is_some()
            {
                finished[index] = true;
            } else {
                running = true;
            }
        }
        if !running {
            break;
        }
        if Instant::now() >= deadline {
            for (index, child) in children.iter_mut().enumerate() {
                if !finished[index] {
                    timed_out[index] = true;
                    child.kill().unwrap_or_else(|source| {
                        panic!("a timed-out {role} cannot be stopped: {source}")
                    });
                }
            }
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }

    let mut failures = Vec::new();
    for (index, child) in children.into_iter().enumerate() {
        let output = child
            .wait_with_output()
            .unwrap_or_else(|source| panic!("a {role}'s output cannot be collected: {source}"));
        if timed_out[index] || !output.status.success() {
            failures.push(format!(
                "{role} {index} timed_out={} status={:?} stderr={} stdout={}",
                timed_out[index],
                output.status.code(),
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            ));
        }
    }
    failures
}

#[tokio::test]
async fn acl_concurrency_child() {
    // This child role is a no-op in the regular suite; the parent supplies the
    // shared tree and release file so separate processes grant it together.
    let Some(shared_dir) = std::env::var_os("HEEL_ACL_CONCURRENCY_DIR") else {
        return;
    };
    let go_file =
        std::env::var_os("HEEL_ACL_CONCURRENCY_GO").expect("the parent supplies the release file");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !Path::new(&go_file).exists() {
        assert!(
            Instant::now() < deadline,
            "the parent did not release the ACL grant workers"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let shared_dir = PathBuf::from(shared_dir);
    let sandbox = sandbox_granting(&shared_dir, Access::READ)
        .await
        .expect("the shared directory grant succeeds");
    let known_file = shared_dir.join("known.txt");
    let output = read_inside(&sandbox, &known_file, "heel-acl-concurrency").await;
    assert!(
        output.status.success() && stdout(&output).contains("heel-acl-concurrency"),
        "the shared file is readable: status={:?} stderr={}",
        output.status.code(),
        stderr(&output)
    );
}

#[tokio::test]
async fn concurrent_acl_grants_preserve_each_container_entry() {
    // Reproduce #69's lost update with independent processes changing the
    // same directory; 1,200 files widen the propagation window.
    const CHILDREN: usize = 6;
    const ROUNDS: usize = 3;
    const SHARED_FILES: usize = 1_200;
    const ROUND_TIMEOUT: Duration = Duration::from_secs(20);

    let test_binary = std::env::current_exe().expect("the test binary path is available");
    for round in 0..ROUNDS {
        let shared = fixtures::tempdir();
        fs::write(shared.path().join("known.txt"), "heel-acl-concurrency\n")
            .expect("the known file is staged");
        for index in 0..SHARED_FILES {
            fs::write(shared.path().join(format!("entry-{index}")), b"shared")
                .expect("the propagation tree is staged");
        }

        let go_file = shared.path().join("go");
        let mut children = Vec::with_capacity(CHILDREN);
        for _ in 0..CHILDREN {
            children.push(
                Command::new(&test_binary)
                    .args(["--exact", "acl_concurrency_child", "--nocapture"])
                    .env("HEEL_ACL_CONCURRENCY_DIR", shared.path())
                    .env("HEEL_ACL_CONCURRENCY_GO", &go_file)
                    .env("RUST_LOG", "off")
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .expect("a grant worker starts"),
            );
        }
        fs::File::create(&go_file)
            .expect("the release file is created after every worker starts")
            .write_all(b"go")
            .expect("the release file is written");

        let failures = collect_children(children, "worker", ROUND_TIMEOUT);
        assert!(
            failures.is_empty(),
            "ACL grant round {round} failed:\n{}",
            failures.join("\n")
        );
    }
}

#[test]
fn profile_open_child() {
    // This child role is a no-op in the regular suite; the parent supplies the
    // identity name and release file so separate processes open one profile
    // together.
    let Some(name) = std::env::var_os("HEEL_PROFILE_OPEN_NAME") else {
        return;
    };
    let go_file =
        std::env::var_os("HEEL_PROFILE_OPEN_GO").expect("the parent supplies the release file");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !Path::new(&go_file).exists() {
        assert!(
            Instant::now() < deadline,
            "the parent did not release the profile openers"
        );
        thread::sleep(Duration::from_millis(10));
    }

    Identity::named(name.to_string_lossy())
        .expect("the identity name is valid")
        .prepare()
        .expect("the shared identity opens");
}

#[test]
fn concurrent_opens_of_one_identity_all_succeed() {
    // Reproduce #98's race with independent processes opening one fresh named
    // profile together: a colliding first-time create failed one caller, and
    // an ALREADY_EXISTS follower could reach the profile folder before its
    // creator made it. Each opener is the test binary re-executed; all are
    // released at once by the file the parent writes last.
    const OPENERS: usize = 8;
    const OPEN_TIMEOUT: Duration = Duration::from_secs(60);

    let mut identity = IdentityCleanup::new(
        Identity::named(format!("t-{:016x}", rand::random::<u64>()))
            .expect("the identity name is valid"),
    );
    let release = fixtures::tempdir();
    let go_file = release.path().join("go");
    let test_binary = std::env::current_exe().expect("the test binary path is available");
    let mut children = Vec::with_capacity(OPENERS);
    for _ in 0..OPENERS {
        children.push(
            Command::new(&test_binary)
                .args(["--exact", "profile_open_child", "--nocapture"])
                .env("HEEL_PROFILE_OPEN_NAME", identity.identity().name())
                .env("HEEL_PROFILE_OPEN_GO", &go_file)
                .env("RUST_LOG", "off")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("a profile opener starts"),
        );
    }
    fs::File::create(&go_file)
        .expect("the release file is created after every opener starts")
        .write_all(b"go")
        .expect("the release file is written");

    let failures = collect_children(children, "opener", OPEN_TIMEOUT);
    assert!(
        failures.is_empty(),
        "concurrent opens of one identity failed:\n{}",
        failures.join("\n")
    );

    identity.remove();
}

#[tokio::test]
async fn a_junction_inside_a_granted_directory_does_not_open_its_target() {
    // A grant's entries propagate through the tree it names, and a junction
    // planted in that tree must not carry them to wherever it points: the
    // target lies outside the grant, so neither its own path nor the path
    // through the junction may reach it.
    let granted = fixtures::tempdir();
    let outside = fixtures::tempdir();
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, "secret-value").expect("the host writes a secret");
    let junction = granted.path().join("junction");
    let created = std::process::Command::new("cmd.exe")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(&junction)
        .arg(outside.path())
        .output()
        .expect("cmd runs");
    assert!(
        created.status.success(),
        "mklink /J must create the junction: {}",
        stderr(&created)
    );

    let config = SandboxConfigBuilder::default()
        .readable(granted.path())
        .build();
    let sandbox = Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts");

    for path in [secret.clone(), junction.join("secret.txt")] {
        let output = cmd(&sandbox, &format!("type {}", path.display())).await;
        assert_ne!(
            stdout(&output),
            "secret-value",
            "{} lies outside the grant and must stay closed",
            path.display()
        );
    }
}

/// A file in the host's shared temp directory, which no container reaches
/// unless the configuration opens it.
fn shared_temp_file(content: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir_in(std::env::temp_dir()).expect("a directory in shared temp");
    let file = dir.path().join("shared.txt");
    fs::write(&file, content).expect("writes");
    (dir, file)
}

async fn sandbox_with(config: SandboxConfig) -> Sandbox {
    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

#[tokio::test]
async fn strict_mode_keeps_shared_temp_closed() {
    let (_dir, file) = shared_temp_file("shared-needle");
    let sandbox = sandbox_with(
        SandboxConfigBuilder::default()
            .filesystem_strict(true)
            .build(),
    )
    .await;

    let output = read_inside(&sandbox, &file, "shared-needle").await;

    assert!(
        !output.status.success(),
        "strict mode must not read shared temp: {}",
        stdout(&output)
    );
}

#[tokio::test]
async fn relaxed_mode_reads_shared_temp() {
    let (_dir, file) = shared_temp_file("shared-needle");
    let sandbox = sandbox_with(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .build(),
    )
    .await;

    let output = read_inside(&sandbox, &file, "shared-needle").await;

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("shared-needle"));
}

#[tokio::test]
async fn relaxed_mode_does_not_make_shared_temp_writable() {
    let (dir, _file) = shared_temp_file("shared-needle");
    let sandbox = sandbox_with(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .build(),
    )
    .await;

    let probe = dir.path().join("probe.txt");
    let output = cmd(&sandbox, &format!("echo x> \"{}\"", probe.display())).await;

    assert!(!output.status.success(), "shared temp must not be writable");
    assert!(!probe.exists());
}

#[tokio::test]
async fn a_writable_file_system_is_refused_rather_than_run_as_strict() {
    let config = SandboxConfigBuilder::default()
        .filesystem_strict(false)
        .writable_file_system(true)
        .build();

    let Err(error) =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await
    else {
        panic!("the setting has no AppContainer equivalent and must be refused");
    };

    assert!(
        matches!(
            error,
            heel::Error::UnsupportedSetting {
                setting: "writable_file_system",
                platform: "windows"
            }
        ),
        "unexpected error: {error}"
    );
}

/// The host's own non-loopback address, learned the way a client picks its
/// source address: "connecting" a UDP socket to a public address selects the
/// route without sending a packet.
fn host_address() -> std::net::IpAddr {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("a UDP socket binds");
    socket
        .connect("8.8.8.8:80")
        .expect("the route to a public address resolves");
    socket.local_addr().expect("the socket has an address").ip()
}

/// Run the TCP probe in `sandbox` against `address` and return its exit code:
/// 0 connected, 2 refused by the sandbox, 3 any other failure.
async fn probe_connect(
    sandbox: &Sandbox<impl heel::NetworkPolicy>,
    probe: &Path,
    address: std::net::SocketAddr,
) -> Option<i32> {
    sandbox
        .command(probe.to_str().expect("the probe path is UTF-8"))
        .arg(address.to_string())
        .output()
        .await
        .expect("the probe runs")
        .status
        .code()
}

#[tokio::test]
async fn a_deny_all_sandbox_does_not_inherit_its_identitys_loopback_exemption() {
    let directory = fixtures::tempdir();
    let probe = fixtures::compile(
        directory.path(),
        include_str!("fixtures/tcp_probe.rs"),
        "tcp-probe",
    );
    let mut identity = IdentityCleanup::new(
        Identity::named(format!("t-{:016x}", rand::random::<u64>()))
            .expect("the identity name is valid"),
    );
    let listener = std::net::TcpListener::bind("0.0.0.0:0").expect("the listener binds");
    let port = listener
        .local_addr()
        .expect("the listener has an address")
        .port();
    let host = std::net::SocketAddr::new(host_address(), port);
    let loopback = std::net::SocketAddr::from(([127, 0, 0, 1], port));

    // A proxied sandbox under the identity gives its package SID the
    // loopback exemption. It reaches the listener, which shows the listener
    // is reachable from a container that holds the exemption.
    let proxied = Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default()
            .network(heel::AllowAll)
            .identity(identity.identity().clone())
            .executable(&probe)
            .build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("the proxied named sandbox starts");
    assert_eq!(
        probe_connect(&proxied, &probe, host).await,
        Some(0),
        "the exempted proxied sandbox must reach the host's own address"
    );
    drop(proxied);

    let deny_all = Sandbox::with_config_and_executor(
        SandboxConfigBuilder::default()
            .identity(identity.identity().clone())
            .executable(&probe)
            .build(),
        executor_core::tokio::TokioGlobal,
    )
    .await
    .expect("the deny-all named sandbox starts");
    for address in [host, loopback] {
        assert_eq!(
            probe_connect(&deny_all, &probe, address).await,
            Some(2),
            "the deny-all sandbox must not reach {address}"
        );
    }

    drop(deny_all);
    drop(listener);
    identity.remove();
}
