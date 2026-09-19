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

use heel::{Access, AllowAll, Sandbox, SandboxConfig, SandboxConfigBuilder};

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

#[tokio::test]
async fn a_network_capability_lets_the_container_spawn_children() {
    // Every container-side spawn is denied under the default policy. If the
    // same command runs once the token carries a capability, the difference is
    // the capability list, not the grant.
    let dir = tempfile::tempdir().expect("tempdir");
    let (staged, haystack) = stage_program(dir.path());
    let config = SandboxConfigBuilder::default()
        .network(AllowAll)
        .grant(dir.path(), Access::READ | Access::EXEC)
        .build();
    let sandbox: Sandbox<AllowAll> =
        Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
            .await
            .expect("sandbox starts");

    let mut dump = String::new();
    for script in [
        format!("{} needle {}", staged.display(), haystack.display()),
        "%SystemRoot%\\System32\\whoami.exe".to_string(),
    ] {
        let output = cmd(&sandbox, &script).await;
        dump.push_str(&format!(
            "\n> {script}\nstdout: {}\nstderr: {}\n",
            stdout(&output),
            stderr(&output)
        ));
    }
    assert!(dump.contains("needle"), "the probes denied spawn:{dump}");
}

/// Run `program` inside `sandbox` through the launch path, not through a
/// shell: the host resolves and starts the program directly in the container.
async fn probe(
    sandbox: &Sandbox<impl heel::NetworkPolicy>,
    program: &str,
    args: &[&str],
) -> Output {
    sandbox
        .command(program)
        .args(args.iter().copied())
        .output()
        .await
        .expect("the probe launches")
}

/// Dump the security state a denied spawn needs to be diagnosed from.
///
/// `whoami /all` names every SID and capability the container token actually
/// carries, which is what the ACEs get checked against; `icacls` shows whether
/// the grant landed on the staged file and every directory above it, from both
/// the container's and the host's view. The probes go through the launch path
/// itself because a child spawned from inside the container is exactly what is
/// under investigation, and the `cmd /C` probes keep the failing shape for
/// comparison.
async fn security_state(sandbox: &Sandbox<impl heel::NetworkPolicy>, staged: &Path) -> String {
    let haystack = staged.with_file_name("haystack.txt");
    let system_root = std::env::var("SystemRoot").expect("SystemRoot is set");
    let whoami = format!(r"{system_root}\System32\whoami.exe");
    let icacls = format!(r"{system_root}\System32\icacls.exe");
    let findstr = format!(r"{system_root}\System32\findstr.exe");

    let mut dump = String::new();
    let mut record = |label: String, output: &Output| {
        dump.push_str(&format!(
            "\n> {label}\nstdout: {}\nstderr: {}\n",
            stdout(output),
            stderr(output)
        ));
    };

    // Programs the host launches straight into the container.
    for (program, args) in [
        (whoami.as_str(), vec!["/all"]),
        (
            staged.to_str().expect("the staged path is UTF-8"),
            vec![
                "needle",
                haystack.to_str().expect("the haystack path is UTF-8"),
            ],
        ),
        (
            findstr.as_str(),
            vec![
                "needle",
                haystack.to_str().expect("the haystack path is UTF-8"),
            ],
        ),
    ] {
        let output = probe(sandbox, program, &args).await;
        record(format!("{program} {}", args.join(" ")), &output);
    }
    for ancestor in staged.ancestors() {
        let target = ancestor.to_str().expect("the ancestor path is UTF-8");
        let output = probe(sandbox, &icacls, &[target]).await;
        record(format!("{icacls} {target}"), &output);
    }

    // The same paths opened through a shell inside the container: this is the
    // shape the production failure takes.
    let scripts = [
        format!("{} needle {}", staged.display(), haystack.display()),
        format!("type {}", staged.display()),
        format!("dir /b {}", staged.parent().expect("a parent").display()),
        format!("{} needle {}", findstr, haystack.display()),
        "echo %USERNAME% %USERDOMAIN%".to_string(),
    ];
    for script in scripts {
        let output = cmd(sandbox, &script).await;
        record(script, &output);
    }

    // The same DACLs read on the host, where nothing can interfere.
    for ancestor in staged.ancestors() {
        let output = std::process::Command::new(&icacls)
            .arg(ancestor)
            .output()
            .expect("the host reads a DACL");
        record(format!("host {icacls} {}", ancestor.display()), &output);
    }
    dump
}

#[tokio::test]
async fn a_granted_directory_lets_the_container_run_staged_programs() {
    // A grant that allows execute must open the directory's programs to the
    // container exactly as much as the system's own: staging copies a real
    // binary in before the sandbox exists and `cmd /C` runs it afterwards,
    // which is the shape a build tool spawning a wrapper takes.
    let dir = tempfile::tempdir().expect("tempdir");
    let (staged, haystack) = stage_program(dir.path());
    let sandbox = exec_granted_sandbox(dir.path()).await;

    let output = cmd(
        &sandbox,
        &format!("{} needle {}", staged.display(), haystack.display()),
    )
    .await;
    assert!(
        output.status.success() && stdout(&output).contains("needle"),
        "the staged program must run inside the sandbox: status={:?} stdout={:?} stderr={:?}\n\
         security state:{}",
        output.status.code(),
        stdout(&output),
        stderr(&output),
        security_state(&sandbox, &staged).await
    );
}

#[tokio::test]
async fn a_staged_program_runs_when_spawned_by_full_path() {
    // Spawning the staged file itself takes the launch path rather than a
    // shell: the program is resolved, granted read+execute on itself, and
    // started inside the container.
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
    assert!(
        output.status.success() && stdout(&output).contains("needle"),
        "the staged program must run inside the sandbox: status={:?} stdout={:?} stderr={:?}\n\
         security state:{}",
        output.status.code(),
        stdout(&output),
        stderr(&output),
        security_state(&sandbox, &staged).await
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
    let (staged, haystack) = stage_program(dir.path());
    let sandbox = exec_granted_sandbox(dir.path()).await;

    let output = cmd(
        &sandbox,
        &format!("{} needle {}", staged.display(), haystack.display()),
    )
    .await;
    assert!(
        output.status.success() && stdout(&output).contains("needle"),
        "the staged program must run inside the sandbox: status={:?} stdout={:?} stderr={:?}\n\
         security state:{}",
        output.status.code(),
        stdout(&output),
        stderr(&output),
        security_state(&sandbox, &staged).await
    );
}
