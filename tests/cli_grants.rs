//! A grant that persists across `heel` runs is resolved once per run, and a
//! link the previous run's sandbox planted is refused rather than followed.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::path::Path;
use std::process::Output;

/// Run `heel run` with `args` and `/bin/sh -c script` inside it.
fn heel_run(args: &[&Path], script: &str) -> Output {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_heel"));
    command.arg("run");
    for path in args {
        command.arg("--writable").arg(path);
    }
    command
        .args(["--", "/bin/sh", "-c", script])
        .output()
        .expect("heel runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn a_directory_the_sandbox_replaced_with_a_link_is_refused_on_the_next_run() {
    let guard = fixtures::tempdir();
    let root = guard.path();
    let parent = root.join("parent");
    let granted = parent.join("granted");
    let target = root.join("target");
    std::fs::create_dir_all(&granted).unwrap();
    std::fs::create_dir_all(&target).unwrap();
    let grants = [parent.as_path(), granted.as_path()];

    let swap = format!(
        "cd / && rmdir {granted} && ln -s {target} {granted}",
        granted = granted.display(),
        target = target.display()
    );
    let first = heel_run(&grants, &swap);
    assert!(
        first.status.success(),
        "the sandbox plants it: {}",
        stderr(&first)
    );
    assert!(
        std::fs::symlink_metadata(&granted)
            .unwrap()
            .file_type()
            .is_symlink(),
        "the first run must have left a link"
    );

    let write = format!("echo escaped > {}/escaped.txt", target.display());
    let second = heel_run(&grants, &write);

    assert!(
        !second.status.success(),
        "the next run must refuse the link"
    );
    assert!(
        stderr(&second).contains("symbolic link") && stderr(&second).contains("granted"),
        "the refusal names the grant: {}",
        stderr(&second)
    );
    assert_eq!(
        std::fs::read_dir(&target).unwrap().count(),
        0,
        "nothing may have been written at the link's target"
    );
}

#[test]
fn a_link_outside_writable_territory_still_works() {
    let guard = fixtures::tempdir();
    let root = guard.path();
    let real = root.join("real");
    std::fs::create_dir_all(real.join("granted")).unwrap();
    std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();
    let granted = root.join("alias").join("granted");

    let output = heel_run(
        &[&granted],
        &format!("echo ok > {}/ok.txt", real.join("granted").display()),
    );

    assert!(output.status.success(), "{}", stderr(&output));
    assert!(real.join("granted/ok.txt").exists());
}
