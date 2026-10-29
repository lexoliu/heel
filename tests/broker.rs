//! The Linux broker, end to end: real system calls made by a probe inside a
//! sandbox that carries the host protection policies.
//!
//! Each test asserts on what the kernel answered the probe, and on the
//! filesystem afterwards, so a call that was refused but still took effect fails
//! too. They need a Linux kernel with Landlock ABI 4 and `ptrace_scope` of 1 or
//! lower; the x32 test needs a kernel with x32 enabled to mean anything.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;

use fixtures::host::{home_with, open_security, sh, start, stderr, stdout};
use heel::{
    AllowAll, DenyAll, InodePool, NetworkPolicy, ReadDenylist, Sandbox, SandboxConfigBuilder,
    WriteDenylist,
};

const EPERM: i32 = 1;
const ENOENT: i32 = 2;
const EACCES: i32 = 13;
const EBUSY: i32 = 16;
const EEXIST: i32 = 17;
const ENOTDIR: i32 = 20;
const EISDIR: i32 = 21;
const ENOSPC: i32 = 28;
const ENAMETOOLONG: i32 = 36;
#[cfg(target_arch = "x86_64")]
const ENOSYS: i32 = 38;
const ELOOP: i32 = 40;

/// The probe, compiled once into a directory that outlives the test.
struct Probe {
    _directory: tempfile::TempDir,
    binary: PathBuf,
}

fn probe() -> Probe {
    let directory = fixtures::tempdir();
    let binary = fixtures::compile(
        directory.path(),
        include_str!("fixtures/broker_probe.rs"),
        "broker-probe",
    );
    Probe {
        _directory: directory,
        binary,
    }
}

/// A canonical home directory of stand-ins, with a scratch directory in it.
fn home(files: &[&str]) -> (tempfile::TempDir, PathBuf) {
    let home = home_with(files);
    let root = std::fs::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(root.join("scratch")).unwrap();
    (home, root)
}

/// Both denylists, aimed at `home`, with the probe runnable.
fn protected<N: NetworkPolicy>(network: N, home: &Path, probe: &Probe) -> SandboxConfigBuilder<N> {
    SandboxConfigBuilder::default()
        .network(network)
        .filesystem_strict(false)
        .security(open_security())
        .writable_file_system(true)
        .executable(fixtures::resolved(&probe.binary))
        .read_denylist(ReadDenylist::credentials().home(home))
        .write_denylist(WriteDenylist::persistence().home(home))
}

/// Run the probe and return what it printed.
async fn ask<N: NetworkPolicy>(sandbox: &Sandbox<N>, probe: &Probe, args: &[&str]) -> String {
    let output = sandbox
        .command(probe.binary.to_str().unwrap())
        .args(args)
        .output()
        .await
        .expect("the probe runs");
    assert!(
        output.status.success(),
        "probe {args:?}: {}",
        stderr(&output)
    );
    stdout(&output)
}

/// The errno in a probe's answer, if it failed.
fn errno(answer: &str) -> Option<i32> {
    answer.strip_prefix("errno ")?.parse().ok()
}

#[track_caller]
fn assert_errno(answer: &str, expected: i32, what: &str) {
    assert_eq!(errno(answer), Some(expected), "{what}: {answer}");
}

fn text(output: &Output) -> String {
    format!("{} {}", stdout(output), stderr(output))
}

#[tokio::test]
async fn missing_persistence_files_cannot_be_created_by_any_route() {
    let probe = probe();
    let (_guard, root) = home(&[".cargo/bin/cargo", ".ssh/id_ed25519"]);
    std::fs::write(root.join("scratch/source"), "payload").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let scratch = root.join("scratch/source");
    let scratch = scratch.to_str().unwrap();
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    let attempts: Vec<(&str, Vec<String>, String)> = vec![
        (
            "open O_CREAT",
            vec!["create".into(), at(".zshrc")],
            ".zshrc".into(),
        ),
        (
            "creat",
            vec!["creat".into(), at(".bashrc")],
            ".bashrc".into(),
        ),
        (
            "openat2",
            vec!["openat2".into(), at(".zshenv")],
            ".zshenv".into(),
        ),
        (
            "mkdir",
            vec!["mkdir".into(), at(".cargo/bin/evil")],
            ".cargo/bin/evil".into(),
        ),
        (
            "mknod file",
            vec!["mknod-file".into(), at(".profile")],
            ".profile".into(),
        ),
        (
            "mknod fifo",
            vec!["mknod-fifo".into(), at(".bash_profile")],
            ".bash_profile".into(),
        ),
        (
            "symlink",
            vec!["symlink".into(), "/etc/passwd".into(), at(".bash_login")],
            ".bash_login".into(),
        ),
        (
            "link",
            vec!["link".into(), scratch.into(), at(".zlogin")],
            ".zlogin".into(),
        ),
        (
            "rename",
            vec!["rename".into(), scratch.into(), at(".zprofile")],
            ".zprofile".into(),
        ),
        (
            "socket bind",
            vec!["bind".into(), at(".inputrc")],
            ".inputrc".into(),
        ),
        (
            "O_TMPFILE and linkat",
            vec!["tmpfile".into(), at("scratch"), at(".vimrc")],
            ".vimrc".into(),
        ),
    ];
    for (what, args, created) in attempts {
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let answer = ask(&sandbox, &probe, &args).await;
        assert_errno(&answer, EACCES, what);
        assert!(
            std::fs::symlink_metadata(root.join(&created)).is_err(),
            "{what} left {created} behind"
        );
    }
    assert!(
        root.join("scratch/source").exists(),
        "the rename moved its source"
    );
}

#[tokio::test]
async fn existing_persistence_files_cannot_be_changed_by_any_route() {
    let probe = probe();
    let (_guard, root) = home(&[".zshrc", ".bashrc", ".profile", ".zshenv"]);
    std::fs::write(root.join("scratch/other"), "other").unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let target = root.join(".zshrc");
    let target = target.to_str().unwrap();
    let other = root.join("scratch/other");
    let other = other.to_str().unwrap();
    let mode_before = std::fs::metadata(target).unwrap().permissions().mode() & 0o777;

    for (what, args) in [
        ("append", vec!["write", target]),
        ("read-write open", vec!["read-write", target]),
        ("truncate", vec!["truncate", target]),
        ("chmod", vec!["chmod", target]),
        ("setxattr", vec!["setxattr", target]),
        ("utimes", vec!["utimes", target]),
        ("unlink", vec!["unlink", target]),
        ("rename away", vec!["rename", target, other]),
        ("exchange", vec!["exchange", target, other]),
        ("link", vec!["link", target, &format!("{other}.link")]),
    ] {
        let answer = ask(&sandbox, &probe, &args).await;
        assert_errno(&answer, EACCES, what);
    }
    assert_eq!(std::fs::read_to_string(target).unwrap(), "secret");
    assert_eq!(std::fs::read_to_string(other).unwrap(), "other");
    assert_eq!(
        std::fs::metadata(target).unwrap().permissions().mode() & 0o777,
        mode_before,
        "the mode changed"
    );
}

#[tokio::test]
async fn a_denied_file_never_appears_while_the_path_changes_under_the_call() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let iterations = std::env::var("HEEL_RACE_ITERATIONS").unwrap_or_else(|_| "20000".into());
    std::fs::create_dir_all(root.join("scratch/ok")).unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;

    let link = root.join("scratch/link");
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "race-symlink",
            link.to_str().unwrap(),
            root.to_str().unwrap(),
            root.join("scratch/ok").to_str().unwrap(),
            &iterations,
        ],
    )
    .await;
    assert_eq!(answer, "ok");
    assert!(
        std::fs::symlink_metadata(root.join(".zshrc")).is_err(),
        "a symbolic link flipped under the call let a denied file be created"
    );

    let bad = root.join(".zshrc");
    let good = root.join("xzshrc");
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "race-buffer",
            good.to_str().unwrap(),
            bad.to_str().unwrap(),
            &iterations,
        ],
    )
    .await;
    assert_eq!(answer, "ok");
    assert!(
        std::fs::symlink_metadata(&bad).is_err(),
        "a path rewritten under the call let a denied file be created"
    );
}

#[tokio::test]
async fn paths_that_mean_something_else_to_the_broker_mean_the_callers_thing() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;

    let output = sh(&sandbox, "echo through-stderr > /dev/stderr").await;
    assert!(
        stderr(&output).contains("through-stderr"),
        "{}",
        text(&output)
    );

    let output = sh(&sandbox, "echo through-proc > /proc/self/fd/1").await;
    assert_eq!(stdout(&output), "through-proc", "{}", text(&output));

    let before = std::fs::read_to_string("/proc/self/comm").unwrap();
    let output = sh(
        &sandbox,
        "echo renamed > /proc/self/comm; cat /proc/self/comm",
    )
    .await;
    assert!(!stdout(&output).is_empty(), "{}", text(&output));
    assert_eq!(std::fs::read_to_string("/proc/self/comm").unwrap(), before);
    assert!(
        !std::fs::read_dir("/proc/self/task")
            .unwrap()
            .flatten()
            .any(|task| std::fs::read_to_string(task.path().join("comm"))
                .is_ok_and(|comm| comm.trim() == "renamed")),
        "the broker's own thread was renamed"
    );
}

#[tokio::test]
async fn new_entries_above_a_denied_path_work_like_their_siblings() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".config/gh/hosts.yml", "keep/file"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let root_text = root.display();

    let output = sh(
        &sandbox,
        &format!(
            "mkdir '{root_text}/made' && echo 'echo ran' > '{root_text}/made/run.sh' \
             && sh '{root_text}/made/run.sh' && mkdir '{root_text}/made/inner' \
             && echo x > '{root_text}/made/inner/file' && cat '{root_text}/made/inner/file' \
             && ls '{root_text}' > /dev/null && ls '{root_text}/.config' > /dev/null \
             && echo y > '{root_text}/note' && cat '{root_text}/note' \
             && mv '{root_text}/note' '{root_text}/note2' && rm '{root_text}/note2'"
        ),
    )
    .await;
    assert!(output.status.success(), "{}", text(&output));
    assert_eq!(stdout(&output), "ran\nx\ny");

    let credential = sh(&sandbox, &format!("cat '{root_text}/.ssh/id_ed25519'")).await;
    assert!(!credential.status.success());
}

#[tokio::test]
async fn sandboxes_in_one_process_each_get_a_pool_of_their_own() {
    async fn one(probe: &Probe) {
        let (_guard, root) = home(&[".ssh/id_ed25519"]);
        let sandbox = start(protected(DenyAll, &root, probe)).await;
        let root_text = root.display();
        for round in 0..3 {
            let output = sh(
                &sandbox,
                &format!(
                    "mkdir '{root_text}/made{round}' && echo x > '{root_text}/made{round}/file' \
                     && cat '{root_text}/made{round}/file'"
                ),
            )
            .await;
            assert!(output.status.success(), "{}", text(&output));
            assert_eq!(stdout(&output), "x");
        }
    }

    let probe = probe();
    tokio::join!(
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe),
        one(&probe)
    );
}

#[tokio::test]
async fn the_inode_pool_runs_out_with_enospc() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe).inode_pool(InodePool::new(2, 2))).await;

    let answer = ask(
        &sandbox,
        &probe,
        &["create-many", root.to_str().unwrap(), "3"],
    )
    .await;
    assert!(
        answer.starts_with("failed 1") && answer.contains(&format!("{ENOSPC}: 1")),
        "{answer}"
    );
}

#[tokio::test]
async fn calls_behave_as_they_do_without_the_broker() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", "scratch/existing"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    let answer = ask(&sandbox, &probe, &["umask-create", &at("scratch/m"), "027"]).await;
    assert_eq!(answer, "mode 640");
    let answer = ask(&sandbox, &probe, &["umask-create", &at("m"), "077"]).await;
    assert_eq!(answer, "mode 600", "an entry above a denied path");

    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/existing")]).await,
        EEXIST,
        "exists",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/no/such")]).await,
        ENOENT,
        "missing directory",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["create", &at(&format!("scratch/{}", "n".repeat(300)))],
        )
        .await,
        ENAMETOOLONG,
        "long name",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["write", &at("scratch")]).await,
        EISDIR,
        "directory",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["create", &at("scratch/existing/x")]).await,
        ENOTDIR,
        "through a file",
    );
    std::os::unix::fs::symlink(root.join("scratch/b"), root.join("scratch/a")).unwrap();
    std::os::unix::fs::symlink(root.join("scratch/a"), root.join("scratch/b")).unwrap();
    assert_errno(
        &ask(&sandbox, &probe, &["write", &at("scratch/a")]).await,
        ELOOP,
        "symlink loop",
    );

    let answer = ask(&sandbox, &probe, &["cloexec", &at("scratch/c")]).await;
    assert_eq!(answer, "cloexec 1", "O_CLOEXEC is kept");
}

#[tokio::test]
async fn repository_files_are_protected_wherever_the_repository_is() {
    let probe = probe();
    let (_guard, root) = home(&[
        "work/repo/.git/hooks/pre-commit",
        "work/repo/.git/config",
        "work/repo/.git/modules/x/hooks/post-commit",
        "work/repo/.git/modules/x/config",
        "cache/git/checkout/.git/hooks/sample",
        "work/repo/.git/index",
    ]);
    let exempt = root.join("cache/git");
    let sandbox = start(
        protected(DenyAll, &root, &probe)
            .write_denylist(WriteDenylist::persistence().home(&root).except(&exempt)),
    )
    .await;
    let at = |name: &str| root.join(name).to_str().unwrap().to_owned();

    for denied in [
        "work/repo/.git/hooks/pre-commit",
        "work/repo/.git/config",
        "work/repo/.git/modules/x/hooks/post-commit",
        "work/repo/.git/modules/x/config",
    ] {
        assert_errno(
            &ask(&sandbox, &probe, &["write", &at(denied)]).await,
            EACCES,
            denied,
        );
    }
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["create", &at("work/repo/.git/hooks/new")],
        )
        .await,
        EACCES,
        "a new hook",
    );
    assert_eq!(
        ask(&sandbox, &probe, &["write", &at("work/repo/.git/index")]).await,
        "ok"
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["write", &at("cache/git/checkout/.git/hooks/sample")]
        )
        .await,
        "ok",
        "an exempt directory"
    );
}

#[tokio::test]
async fn credential_agents_and_foreign_endpoints_cannot_be_connected_to() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let agent = root.join("scratch/agent.sock");
    let _agent = std::os::unix::net::UnixListener::bind(&agent).unwrap();
    let ordinary = root.join("scratch/ordinary.sock");
    let _ordinary = std::os::unix::net::UnixListener::bind(&ordinary).unwrap();
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = target.local_addr().unwrap().port();

    let sandbox = start(
        SandboxConfigBuilder::default()
            .network(AllowAll)
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary))
            .read_denylist(ReadDenylist::credentials().home(&root).socket(&agent)),
    )
    .await;
    let proxy_port: u16 = sandbox
        .proxy_url()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();

    assert_errno(
        &ask(&sandbox, &probe, &["connect-unix", agent.to_str().unwrap()]).await,
        EACCES,
        "agent socket",
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect-unix", ordinary.to_str().unwrap()]
        )
        .await,
        "ok",
        "an ordinary socket"
    );
    assert_errno(
        &ask(&sandbox, &probe, &["connect-abstract", "heel-test"]).await,
        EACCES,
        "abstract socket",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{other_port}")],
        )
        .await,
        EACCES,
        "loopback on another port",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("1.2.3.4:{proxy_port}")],
        )
        .await,
        EACCES,
        "another host on the proxy's port",
    );
    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{proxy_port}")]
        )
        .await,
        "ok",
        "the proxy"
    );
}

#[tokio::test]
async fn a_detached_descendant_is_still_served() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let output = sh(
        &sandbox,
        &format!(
            "(setsid sh -c 'sleep 1; echo daemon > \"{0}/scratch/daemon\"; echo x > \"{0}/.zshrc\"' \
             </dev/null >/dev/null 2>&1 &); sleep 3; cat '{0}/scratch/daemon'",
            root.display()
        ),
    )
    .await;
    assert_eq!(stdout(&output), "daemon", "{}", text(&output));
    assert!(!root.join(".zshrc").exists());
}

#[tokio::test]
async fn a_signal_storm_does_not_break_creation() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    std::fs::create_dir_all(root.join("scratch/many")).unwrap();
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let answer = ask(
        &sandbox,
        &probe,
        &[
            "storm",
            root.join("scratch/many").to_str().unwrap(),
            "20000",
        ],
    )
    .await;
    assert!(answer.starts_with("failed 0 "), "{answer}");
}

#[tokio::test]
async fn the_sandbox_cannot_get_around_the_broker() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    assert_errno(
        &ask(&sandbox, &probe, &["nested-filter"]).await,
        EBUSY,
        "a nested listener",
    );
    assert_errno(
        &ask(&sandbox, &probe, &["dumpable"]).await,
        EPERM,
        "PR_SET_DUMPABLE",
    );
}

#[tokio::test]
async fn denials_name_every_operation_and_path() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519", ".zshrc"]);
    let sandbox = start(protected(DenyAll, &root, &probe)).await;
    let recorder = sandbox.record_denials().await.unwrap();

    let secret = root.join(".ssh/id_ed25519");
    let created = root.join(".bashrc");
    let existing = root.join(".zshrc");
    for args in [
        vec!["read", secret.to_str().unwrap()],
        vec!["create", created.to_str().unwrap()],
        vec!["write", existing.to_str().unwrap()],
        vec!["unlink", existing.to_str().unwrap()],
        vec!["chmod", existing.to_str().unwrap()],
    ] {
        ask(&sandbox, &probe, &args).await;
    }
    let denials = recorder.finish().await.unwrap();
    for (operation, path) in [
        ("file-read-data", &secret),
        ("file-write-create", &created),
        ("file-write-data", &existing),
        ("file-write-unlink", &existing),
        ("file-write-mode", &existing),
    ] {
        assert!(
            denials
                .iter()
                .any(|d| d.operation == operation && d.target == path.display().to_string()),
            "no {operation} denial for {}: {denials:#?}",
            path.display()
        );
    }
}

// -- #107 -----------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn x32_system_calls_are_refused_in_every_filter() {
    let probe = probe();
    let (_guard, root) = home(&[".ssh/id_ed25519"]);
    // The broker's filter, and the general filter on its own.
    let broker = start(protected(DenyAll, &root, &probe)).await;
    let plain = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    for (sandbox, what) in [(&broker, "with the broker"), (&plain, "without it")] {
        assert_errno(&ask(sandbox, &probe, &["x32"]).await, ENOSYS, what);
    }
}

// -- #108 -----------------------------------------------------------------

#[tokio::test]
async fn terminal_injection_ioctls_are_refused() {
    let probe = probe();
    let sandbox = start(
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    // Not a terminal, so an ioctl that reached the kernel would say ENOTTY.
    assert_errno(&ask(&sandbox, &probe, &["tiocsti"]).await, EPERM, "TIOCSTI");
    assert_errno(
        &ask(&sandbox, &probe, &["tioclinux"]).await,
        EPERM,
        "TIOCLINUX",
    );
}

// -- #109 -----------------------------------------------------------------

#[tokio::test]
async fn outbound_tcp_reaches_only_the_proxy_address_and_port() {
    let probe = probe();
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let other_port = target.local_addr().unwrap().port();
    // No denylist: the connect-only broker is what limits the address.
    let sandbox = start(
        SandboxConfigBuilder::default()
            .network(AllowAll)
            .filesystem_strict(false)
            .security(open_security())
            .executable(fixtures::resolved(&probe.binary)),
    )
    .await;
    let proxy_port: u16 = sandbox
        .proxy_url()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .trim_end_matches('/')
        .parse()
        .unwrap();

    assert_eq!(
        ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{proxy_port}")]
        )
        .await,
        "ok"
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("1.2.3.4:{proxy_port}")],
        )
        .await,
        EACCES,
        "a non-loopback address on the proxy's port",
    );
    assert_errno(
        &ask(
            &sandbox,
            &probe,
            &["connect", &format!("127.0.0.1:{other_port}")],
        )
        .await,
        EACCES,
        "loopback on another port",
    );
}
