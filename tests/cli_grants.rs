//! A grant that persists across `heel` runs is resolved once per run, and a
//! link the previous run's sandbox planted is refused rather than followed.

#![cfg(unix)]
#![allow(clippy::unwrap_used)]

mod fixtures;

use std::path::{Path, PathBuf};
use std::process::Output;

/// Run `heel run` with `args` and `/bin/sh -c script` inside it.
fn heel_run(args: &[&Path], script: &str) -> Output {
    let writable: Vec<_> = args
        .iter()
        .flat_map(|path| ["--writable".as_ref(), path.as_os_str()])
        .collect();
    heel_run_with(&writable, script)
}

/// Run `heel run` with the given flags and `/bin/sh -c script` inside it.
fn heel_run_with(flags: &[&std::ffi::OsStr], script: &str) -> Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_heel"))
        .arg("run")
        .args(flags)
        .args(["--", "/bin/sh", "-c", script])
        .output()
        .expect("heel runs")
}

/// `root/alias -> root/real`, with `root/real/parent/granted` and a `target`
/// beside them: a layout whose writable paths are reached through a link
/// above them, as `/tmp/...` is on macOS, and so are not spelled canonically.
struct Aliased {
    _guard: tempfile::TempDir,
    /// `root/alias/parent`, as a user spells it.
    spelled_parent: PathBuf,
    /// `root/alias/parent/granted`, as a user spells it.
    spelled_granted: PathBuf,
    /// `root/real/parent/granted`, where a sandbox plants the link.
    granted: PathBuf,
    target: PathBuf,
}

impl Aliased {
    fn new() -> Self {
        let guard = fixtures::tempdir();
        let root = guard.path().to_path_buf();
        let real = root.join("real");
        let granted = real.join("parent/granted");
        let target = root.join("target");
        std::fs::create_dir_all(&granted).unwrap();
        std::fs::create_dir_all(&target).unwrap();
        std::os::unix::fs::symlink(&real, root.join("alias")).unwrap();
        Self {
            spelled_parent: root.join("alias/parent"),
            spelled_granted: root.join("alias/parent/granted"),
            _guard: guard,
            granted,
            target,
        }
    }

    /// The first run's sandbox replaces the granted directory with a link.
    fn plant(&self, flags: &[&std::ffi::OsStr]) {
        let first = heel_run_with(
            flags,
            &format!(
                "cd / && rmdir {granted} && ln -s {target} {granted}",
                granted = self.granted.display(),
                target = self.target.display()
            ),
        );
        assert!(
            first.status.success(),
            "the sandbox plants it: {}",
            stderr(&first)
        );
        assert!(
            std::fs::symlink_metadata(&self.granted)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the first run must have left a link"
        );
    }

    /// The second run must be refused, and nothing may reach the target.
    fn assert_next_run_refused(&self, flags: &[&std::ffi::OsStr]) {
        let second = heel_run_with(
            flags,
            &format!("echo escaped > {}/escaped.txt", self.target.display()),
        );

        assert!(
            !second.status.success(),
            "the next run must refuse the link: {}",
            stderr(&second)
        );
        assert!(
            stderr(&second).contains("symbolic link"),
            "the refusal says why: {}",
            stderr(&second)
        );
        assert_eq!(
            std::fs::read_dir(&self.target).unwrap().count(),
            0,
            "nothing may have been written at the link's target"
        );
    }
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

/// The flags that make `granted` writable, and on platforms where removing a
/// directory needs the right on its parent (Linux, Windows), the parent too. On
/// macOS the grant alone lets the sandbox remove and replace the directory, so
/// the planted link is the only writable thing the spelling can hide.
fn spelled_flags<'a>(layout: &'a Aliased, last: &'static str) -> Vec<&'a std::ffi::OsStr> {
    let mut flags: Vec<&std::ffi::OsStr> = Vec::new();
    if !cfg!(target_os = "macos") {
        flags.extend(["--writable".as_ref(), layout.spelled_parent.as_os_str()]);
    }
    flags.extend([last.as_ref(), layout.spelled_granted.as_os_str()]);
    flags
}

#[test]
fn a_grant_spelled_through_a_link_above_it_is_refused_on_the_next_run() {
    // `heel run --writable /tmp/...` on macOS: the spelling crosses `/tmp`, so
    // the link the sandbox plants sits at a path the spelling does not name.
    let layout = Aliased::new();
    let flags = spelled_flags(&layout, "--writable");

    layout.plant(&flags);
    layout.assert_next_run_refused(&flags);
}

#[test]
fn a_working_directory_spelled_through_a_link_above_it_is_refused_on_the_next_run() {
    let layout = Aliased::new();
    let flags = spelled_flags(&layout, "--working-dir");

    layout.plant(&flags);
    layout.assert_next_run_refused(&flags);
}
