//! A host can tell which processes run under a sandbox, however they left it.
//!
//! The processes here are the hard case: a descendant that daemonizes (forks,
//! the parent exits, the child calls `setsid` and executes `/bin/sleep`) ends
//! up with launchd as its parent and a process group of its own, and the
//! sandbox's root has exited by the time the host asks.

#![cfg(target_os = "macos")]
#![allow(clippy::unwrap_used)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use heel::{Membership, Sandbox, SandboxConfig};

/// How long any bounded condition in these tests may take before it fails.
const BOUND: Duration = Duration::from_secs(20);

/// Processes started by a test, killed by pid when it ends, however it ends.
#[derive(Default)]
struct Pids(Vec<u32>);

impl Drop for Pids {
    fn drop(&mut self) {
        for pid in &self.0 {
            // SAFETY: a pid this test started; SIGKILL only ends that process.
            unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
        }
    }
}

/// Retry `condition` until it yields a value, failing after [`BOUND`].
fn until<T>(what: &str, mut condition: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + BOUND;
    loop {
        if let Some(value) = condition() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out on {what}");
        std::thread::yield_now();
        std::thread::park_timeout(Duration::from_millis(50));
    }
}

async fn sandbox() -> Sandbox {
    Sandbox::with_config_and_executor(SandboxConfig::new(), executor_core::tokio::TokioGlobal)
        .await
        .unwrap()
}

/// The parent and process group of `pid`, when it runs `/bin/sleep`.
fn sleeper_ancestry(pid: u32) -> Option<(u32, u32)> {
    let ps = Command::new("/bin/ps")
        .args(["-o", "ppid=,pgid=,comm=", "-p", &pid.to_string()])
        .output()
        .unwrap();
    let line = String::from_utf8_lossy(&ps.stdout).into_owned();
    let mut fields = line.split_whitespace();
    let ppid = fields.next()?.parse().ok()?;
    let pgid = fields.next()?.parse().ok()?;
    fields.next()?.ends_with("sleep").then_some((ppid, pgid))
}

/// Daemonize `/bin/sleep` from inside `sandbox` and return its pid, once the
/// command that started it has exited.
async fn daemonize(sandbox: &Sandbox, pids: &mut Pids) -> u32 {
    let pid_file = sandbox.working_dir().join("daemon.pid");
    let script = format!(
        r#"use POSIX qw(setsid);
fork and exit;
setsid;
open(my $out, ">", "{}") or die;
print $out $$;
close $out;
open STDIN, "<", "/dev/null";
open STDOUT, ">", "/dev/null";
open STDERR, ">&", \*STDOUT;
exec "/bin/sleep", "120";"#,
        pid_file.display()
    );
    let output = sandbox
        .command("/usr/bin/perl")
        .arg("-e")
        .arg(script)
        .output()
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let pid: u32 = until("the daemon to report its pid", || {
        std::fs::read_to_string(&pid_file).ok()?.trim().parse().ok()
    });
    pids.0.push(pid);

    // The process really left: launchd is its parent and it leads its own
    // process group, so nothing but its profile ties it to the sandbox.
    let ancestry = until("the daemon to execute sleep", || sleeper_ancestry(pid));
    assert_eq!(ancestry, (1, pid));

    pid
}

#[tokio::test(flavor = "multi_thread")]
async fn a_daemonized_descendant_is_attributed_after_its_root_exited() {
    let mut pids = Pids::default();
    let sandbox = sandbox().await;
    let daemon = daemonize(&sandbox, &mut pids).await;

    assert_eq!(sandbox.membership(daemon).unwrap(), Membership::Member);
}

#[tokio::test(flavor = "multi_thread")]
async fn another_sandboxs_process_is_not_attributed() {
    let mut pids = Pids::default();
    let mine = sandbox().await;
    let other = sandbox().await;
    let mine_daemon = daemonize(&mine, &mut pids).await;
    let other_daemon = daemonize(&other, &mut pids).await;

    assert_eq!(mine.membership(mine_daemon).unwrap(), Membership::Member);
    assert_eq!(
        mine.membership(other_daemon).unwrap(),
        Membership::NotMember
    );
    assert_eq!(other.membership(other_daemon).unwrap(), Membership::Member);
    assert_eq!(
        other.membership(mine_daemon).unwrap(),
        Membership::NotMember
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_unsandboxed_process_is_not_attributed() {
    let mut pids = Pids::default();
    let sandbox = sandbox().await;

    let mut child = Command::new("/bin/sleep")
        .arg("120")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    pids.0.push(child.id());

    assert_eq!(
        sandbox.membership(child.id()).unwrap(),
        Membership::NotMember
    );
    assert_eq!(
        sandbox.membership(std::process::id()).unwrap(),
        Membership::NotMember
    );

    child.kill().unwrap();
    child.wait().unwrap();
    assert_eq!(sandbox.membership(child.id()).unwrap(), Membership::Gone);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_exited_is_gone() {
    let mut pids = Pids::default();
    let sandbox = sandbox().await;
    let daemon = daemonize(&sandbox, &mut pids).await;

    // SAFETY: the pid of the process this test started.
    unsafe { libc::kill(daemon as i32, libc::SIGKILL) };
    until("launchd to reap the daemon", || {
        (sandbox.membership(daemon).unwrap() == Membership::Gone).then_some(())
    });
}
