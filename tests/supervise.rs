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
use heel::{Error, Sandbox, SandboxConfigBuilder};

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

/// The fields of `/proc/<pid>/stat` after the name: state, ppid, pgrp, session.
fn stat_fields(pid: u32) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.get(stat.rfind(')')? + 1..)?;
    Some(after_name.split_whitespace().map(str::to_owned).collect())
}

/// The kernel's state letter for `pid`, `Z` for a zombie.
fn state(pid: u32) -> Option<char> {
    stat_fields(pid)?.first()?.chars().next()
}

/// Whether `pid` is a session leader, which `setsid` makes it.
fn leads_its_session(pid: u32) -> bool {
    stat_fields(pid).is_some_and(|fields| fields.get(3).and_then(|id| id.parse().ok()) == Some(pid))
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
    // The shell exits only once the helper has left its session, so the helper
    // is outside the supervisor's process group when it is orphaned: the case a
    // reap limited to that group cannot see. Field 6 of the stat line is the
    // session, which is the helper's own pid after `setsid`.
    let script = "setsid sh -c 'while [ ! -e release ]; do sleep 0.05; done' & pid=$!; \
                  echo $pid > helper; \
                  until [ \"$(cut -d' ' -f6 /proc/$pid/stat)\" = \"$pid\" ]; do sleep 0.01; done; \
                  echo $$ > shell";
    let mut child = sandbox
        .command("/bin/sh")
        .args(["-c", script])
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("spawns");
    let supervisor = child.id();

    let dir = sandbox.working_dir();
    let shell = pid_file(dir, "shell").await;
    let helper = pid_file(dir, "helper").await;
    eventually("the supervisor to reap the shell", || !listed(shell)).await;
    // A supervisor that was going to exit on reaping the shell does so within
    // moments, and would be a zombie of this process by then.
    tokio::time::sleep(Duration::from_millis(300)).await;

    assert!(
        state(supervisor).is_some_and(|state| state != 'Z'),
        "the supervisor outlives the command while a descendant runs"
    );
    assert!(leads_its_session(helper), "the helper is still running");

    std::fs::write(dir.join("release"), "").unwrap();
    let status = bounded("the background command", child.wait())
        .await
        .expect("the supervisor reports");

    assert!(status.success(), "the command's status is kept: {status:?}");
    assert!(!listed(helper), "the helper is gone, zombie included");
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
    // Both helpers are in sessions of their own before the shell exits.
    let script = "setsid sleep 300 & a=$!; setsid sleep 300 & b=$!; \
                  for pid in $a $b; do \
                    until [ \"$(cut -d' ' -f6 /proc/$pid/stat)\" = \"$pid\" ]; do sleep 0.01; done; \
                  done; exit 0";
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

/// A command that leaves a `setsid` helper behind and stays in the foreground.
const SETSID_HELPER: &str = "setsid sleep 300 & echo $! > helper; wait";

/// Spawn [`SETSID_HELPER`] and return the helper, once it is in its own session.
async fn spawn_with_helper(
    sandbox: &Sandbox,
) -> (heel::supervisor::SupervisedChild<Background>, u32) {
    let child = sandbox
        .command("/bin/sh")
        .args(["-c", SETSID_HELPER])
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("spawns");
    let helper = pid_file(sandbox.working_dir(), "helper").await;
    eventually("the helper to leave the session", || {
        leads_its_session(helper)
    })
    .await;
    (child, helper)
}

#[tokio::test]
async fn dropping_the_sandbox_leaves_no_setsid_descendant_running() {
    let sandbox = sandbox().await;
    let (child, helper) = spawn_with_helper(&sandbox).await;
    let supervisor = child.id();

    // The handle is still alive: the sandbox ends the tree through the
    // supervisor, and does not signal the supervisor's process group, which the
    // helper has left.
    drop(sandbox);

    assert!(!listed(helper), "the helper survived the sandbox");
    assert!(!listed(supervisor), "the supervisor is reaped");
    drop(child);
}

#[tokio::test]
async fn dropping_the_handle_then_the_sandbox_leaves_no_setsid_descendant_running() {
    let sandbox = sandbox().await;
    let (child, helper) = spawn_with_helper(&sandbox).await;
    let supervisor = child.id();

    // Closing the control socket makes the supervisor tear the tree down; the
    // sandbox then waits for that teardown instead of racing it.
    drop(child);
    drop(sandbox);

    assert!(!listed(helper), "the helper survived the sandbox");
    assert!(!listed(supervisor), "the supervisor is reaped");
}

#[tokio::test]
async fn a_command_that_cannot_start_is_a_typed_spawn_error_in_both_modes() {
    let sandbox = sandbox().await;

    let mut foreground = sandbox
        .command("/nonexistent/program")
        .spawn_supervised(Foreground { reap_timeout: REAP })
        .await
        .expect("the supervisor starts");
    match bounded("the foreground spawn failure", foreground.wait()).await {
        Err(Error::SupervisedSpawnFailed(failure)) => {
            assert_eq!(failure.os_error, Some(libc::ENOENT), "{failure}");
        }
        other => panic!("expected a spawn failure, got {other:?}"),
    }

    let mut background = sandbox
        .command("/nonexistent/program")
        .spawn_supervised(Background { reap_timeout: REAP })
        .await
        .expect("the supervisor starts");
    match bounded("the background spawn failure", background.wait()).await {
        Err(Error::SupervisedSpawnFailed(failure)) => {
            assert_eq!(failure.os_error, Some(libc::ENOENT), "{failure}");
        }
        other => panic!("expected a spawn failure, got {other:?}"),
    }
}
