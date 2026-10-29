//! A sandboxed command's whole process tree, owned by a supervisor.
//!
//! Every test runs the real `heel supervise` inside the real sandbox, and
//! asserts on the processes the kernel lists afterwards. Every wait is bounded.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use heel::supervisor::{Background, Foreground};
use heel::{Sandbox, SandboxConfigBuilder};

/// Long enough for a loaded CI machine, short enough to fail a stuck test.
const BOUND: Duration = Duration::from_secs(30);

/// The budget a teardown gets to see the processes it killed exit.
const REAP: Duration = Duration::from_secs(10);

async fn sandbox() -> Sandbox {
    let config = SandboxConfigBuilder::default()
        .heel_binary(env!("CARGO_BIN_EXE_heel"))
        .supervised_spawn(true)
        .build();
    Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal)
        .await
        .expect("sandbox starts")
}

/// Run `future`, failing the test if it takes longer than [`BOUND`].
async fn bounded<T>(what: &str, future: impl Future<Output = T>) -> T {
    tokio::time::timeout(BOUND, future)
        .await
        .unwrap_or_else(|_| panic!("{what} did not finish within {BOUND:?}"))
}

/// Poll `condition` until it holds, failing the test after [`BOUND`].
async fn eventually(what: &str, mut condition: impl FnMut() -> bool) {
    bounded(what, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

/// The process id the command wrote to `name` in the working directory.
async fn pid_file(dir: &Path, name: &str) -> u32 {
    let path = dir.join(name);
    let mut pid = None;
    eventually(name, || {
        pid = std::fs::read_to_string(&path)
            .ok()
            .and_then(|text| text.trim().parse().ok());
        pid.is_some()
    })
    .await;
    pid.unwrap()
}

/// Whether the kernel still lists `pid`, as a zombie or otherwise.
fn listed(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// `(pid, ppid)` of every process.
fn table() -> Vec<(u32, u32)> {
    std::fs::read_dir("/proc")
        .unwrap()
        .filter_map(|entry| {
            let pid: u32 = entry.ok()?.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
            let after_name = stat.get(stat.rfind(')')? + 1..)?;
            let ppid = after_name.split_whitespace().nth(1)?.parse().ok()?;
            Some((pid, ppid))
        })
        .collect()
}

/// Every live descendant of `root`, however many reparentings away.
fn descendants(root: u32) -> Vec<u32> {
    let table = table();
    let mut found = vec![root];
    let mut index = 0;
    while let Some(&parent) = found.get(index) {
        found.extend(
            table
                .iter()
                .filter(|&&(_, ppid)| ppid == parent)
                .map(|&(pid, _)| pid),
        );
        index += 1;
    }
    found.remove(0);
    found
}

/// Zombies among the children of this very process.
fn zombie_children() -> Vec<u32> {
    let me = std::process::id();
    table()
        .into_iter()
        .filter(|&(_, ppid)| ppid == me)
        .map(|(pid, _)| pid)
        .filter(|pid| {
            std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| Some(stat.get(stat.rfind(')')? + 2..)?.starts_with('Z')))
                .unwrap_or(false)
        })
        .collect()
}

#[tokio::test]
async fn a_setsid_descendant_that_outlives_its_parent_is_killed_and_reported() {
    let sandbox = sandbox().await;
    // The helper leaves the command's session and keeps running after the
    // shell exits. The shell waits for its exec so its name is settled.
    let script = "setsid sleep 300 & pid=$!; echo $pid > helper; \
                  until read name < /proc/$pid/comm && [ \"$name\" = sleep ]; do :; done; \
                  exit 7";
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", script])
        .spawn_supervised(Foreground { reap_timeout: REAP })
        .await
        .expect("spawns");

    let exit = bounded("the foreground command", child.wait())
        .await
        .expect("the supervisor reports");
    let helper = pid_file(sandbox.working_dir(), "helper").await;

    assert_eq!(exit.status.code(), Some(7), "the command's status is kept");
    assert!(
        exit.report
            .killed
            .iter()
            .any(|process| process.pid == helper && process.name == "sleep"),
        "the helper is reported by pid and name: {:?}",
        exit.report
    );
    assert!(exit.report.survivors.is_empty());
    assert!(!listed(helper), "the helper is gone, zombie included");
}

#[tokio::test]
async fn a_background_command_stays_until_its_descendant_exits() {
    let sandbox = sandbox().await;
    let script = "echo $$ > shell; \
                  setsid sh -c 'while [ ! -e release ]; do sleep 0.05; done' & \
                  echo $! > helper";
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", script])
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("spawns");

    let dir = sandbox.working_dir();
    let shell = pid_file(dir, "shell").await;
    let helper = pid_file(dir, "helper").await;
    eventually("the shell to be reaped", || !listed(shell)).await;

    assert!(
        child.child_mut().try_wait().unwrap().is_none(),
        "the supervisor outlives the command while a descendant runs"
    );
    assert!(listed(helper), "the helper is still running");

    std::fs::write(dir.join("release"), "").unwrap();
    let status = bounded("the background command", child.wait())
        .await
        .expect("the supervisor reports");

    assert!(status.success(), "the command's status is kept: {status:?}");
    assert!(!listed(helper));
}

#[tokio::test]
async fn a_tree_kill_ends_every_descendant_including_a_forking_loop() {
    let sandbox = sandbox().await;
    // The loop is a session of its own and keeps forking; the shell stays in
    // the foreground waiting for it.
    let script = "setsid sh -c 'while :; do sleep 100 & sleep 0.01; done' & \
                  echo $! > looper; wait";
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", script])
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("spawns");
    let supervisor = child.id();

    pid_file(sandbox.working_dir(), "looper").await;
    eventually("the loop to have forked", || {
        descendants(supervisor).len() >= 8
    })
    .await;
    let before = descendants(supervisor);

    let report = bounded("the tree kill", child.kill_tree())
        .await
        .expect("every descendant dies");

    assert!(report.survivors.is_empty(), "nothing survived: {report:?}");
    assert!(!report.killed.is_empty(), "the kill reports what it killed");
    assert!(
        descendants(supervisor).is_empty(),
        "no descendant remains: {:?}",
        descendants(supervisor)
    );
    for pid in before {
        assert!(!listed(pid), "{pid} outlived the kill");
    }

    let status = bounded("the killed command", child.wait())
        .await
        .expect("the supervisor reports");
    assert!(!status.success(), "the command was killed: {status:?}");
}

#[tokio::test]
async fn no_zombie_remains_under_the_host() {
    let sandbox = sandbox().await;
    let script = "setsid sleep 300 & setsid sleep 300 & echo $! > last; \
                  sleep 0.2; exit 0";
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", script])
        .spawn_supervised(Foreground { reap_timeout: REAP })
        .await
        .expect("spawns");
    let supervisor = child.id();

    let exit = bounded("the foreground command", child.wait())
        .await
        .expect("the supervisor reports");
    assert_eq!(exit.report.killed.len(), 2, "{:?}", exit.report);

    assert!(!listed(supervisor), "the supervisor itself is reaped");
    for killed in &exit.report.killed {
        assert!(!listed(killed.pid), "{killed:?} left a zombie");
    }
    assert!(
        zombie_children().iter().all(|&pid| pid != supervisor),
        "no zombie child of the host is a supervisor"
    );
}

#[tokio::test]
async fn killing_a_foreground_command_that_is_still_running_reports_the_tree() {
    let sandbox = sandbox().await;
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", "sleep 300 & echo $! > sleeper; wait"])
        .spawn_supervised(Foreground { reap_timeout: REAP })
        .await
        .expect("spawns");

    let sleeper = pid_file(sandbox.working_dir(), "sleeper").await;
    let report = bounded("the tree kill", child.kill_tree())
        .await
        .expect("the tree dies");
    assert!(
        report.killed.iter().any(|process| process.pid == sleeper),
        "{report:?}"
    );

    let exit = bounded("the killed command", child.wait())
        .await
        .expect("the supervisor reports");
    assert!(!exit.status.success());
    assert_eq!(exit.report, report);
    assert!(!listed(sleeper));
}

#[tokio::test]
async fn killing_a_tree_that_has_already_ended_is_not_an_error() {
    let sandbox = sandbox().await;
    let mut child = sandbox
        .command("/bin/true")
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("spawns");
    let control = child.tree_control();

    let status = bounded("the command", child.wait()).await.unwrap();
    assert!(status.success());

    let report = bounded("the late kill", control.kill())
        .await
        .expect("an ended tree is already killed");
    assert!(report.killed.is_empty() && report.survivors.is_empty());
}
