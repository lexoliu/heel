//! Trace sandbox execution to find where EINVAL comes from

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};

#[cfg(target_os = "linux")]
fn main() {
    println!("Test 1: Plain command (no pre_exec)");
    let result = Command::new("echo")
        .args(["test1"])
        .stdout(Stdio::piped())
        .output();
    match result {
        Ok(o) => println!("  OK: {}", String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("\nTest 2: Command with empty pre_exec");
    let mut cmd = Command::new("echo");
    cmd.args(["test2"]);
    cmd.stdout(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            eprintln!("  pre_exec: called");
            Ok(())
        });
    }
    match cmd.output() {
        Ok(o) => println!("  OK: {}", String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("\nTest 3: Command with Landlock in pre_exec");
    let mut cmd = Command::new("echo");
    cmd.args(["test3"]);
    cmd.stdout(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            eprintln!("  pre_exec: applying Landlock");
            use landlock::{
                ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
                RulesetCreatedAttr,
            };

            let ruleset = Ruleset::default()
                .handle_access(AccessFs::from_all(ABI::V4))
                .map_err(|e| std::io::Error::other(format!("handle_access: {}", e)))?
                .create()
                .map_err(|e| std::io::Error::other(format!("create: {}", e)))?;

            // Add /tmp rule
            let ruleset = if let Ok(path_fd) = PathFd::new("/tmp") {
                ruleset
                    .add_rule(PathBeneath::new(path_fd, AccessFs::from_all(ABI::V4)))
                    .map_err(|e| std::io::Error::other(format!("add_rule: {}", e)))?
            } else {
                ruleset
            };

            let status = ruleset
                .restrict_self()
                .map_err(|e| std::io::Error::other(format!("restrict_self: {}", e)))?;

            eprintln!("  pre_exec: Landlock status = {:?}", status.ruleset);
            Ok(())
        });
    }
    match cmd.output() {
        Ok(o) => println!("  OK: {}", String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("\nTest 4: Command with Seccomp in pre_exec");
    let mut cmd = Command::new("echo");
    cmd.args(["test4"]);
    cmd.stdout(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            eprintln!("  pre_exec: applying Seccomp");
            use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
            use std::collections::BTreeMap;

            let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                TargetArch::aarch64,
            )
            .map_err(|e| std::io::Error::other(format!("SeccompFilter: {:?}", e)))?;

            let program: seccompiler::BpfProgram = filter
                .try_into()
                .map_err(|e| std::io::Error::other(format!("BpfProgram: {:?}", e)))?;

            seccompiler::apply_filter(&program)
                .map_err(|e| std::io::Error::other(format!("apply_filter: {:?}", e)))?;

            eprintln!("  pre_exec: Seccomp applied");
            Ok(())
        });
    }
    match cmd.output() {
        Ok(o) => println!("  OK: {}", String::from_utf8_lossy(&o.stdout).trim()),
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("\nTest 5: Command with both Landlock and Seccomp in pre_exec");
    let mut cmd = Command::new("echo");
    cmd.args(["test5"]);
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    unsafe {
        cmd.pre_exec(|| {
            eprintln!("  pre_exec: applying both");

            // Landlock
            use landlock::{
                ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
                RulesetCreatedAttr,
            };

            let ruleset = Ruleset::default()
                .handle_access(AccessFs::from_all(ABI::V4))
                .map_err(|e| std::io::Error::other(format!("handle_access: {}", e)))?
                .create()
                .map_err(|e| std::io::Error::other(format!("create: {}", e)))?;

            let ruleset = if let Ok(path_fd) = PathFd::new("/tmp") {
                ruleset
                    .add_rule(PathBeneath::new(path_fd, AccessFs::from_all(ABI::V4)))
                    .map_err(|e| std::io::Error::other(format!("add_rule: {}", e)))?
            } else {
                ruleset
            };

            match ruleset.restrict_self() {
                Ok(status) => eprintln!("  pre_exec: Landlock status = {:?}", status.ruleset),
                Err(e) => {
                    eprintln!("  pre_exec: Landlock restrict_self FAILED: {}", e);
                    return Err(std::io::Error::other(format!("restrict_self: {}", e)));
                }
            }

            // Seccomp
            use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
            use std::collections::BTreeMap;

            let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();
            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                TargetArch::aarch64,
            )
            .map_err(|e| std::io::Error::other(format!("SeccompFilter: {:?}", e)))?;

            let program: seccompiler::BpfProgram = filter
                .try_into()
                .map_err(|e| std::io::Error::other(format!("BpfProgram: {:?}", e)))?;

            seccompiler::apply_filter(&program)
                .map_err(|e| std::io::Error::other(format!("apply_filter: {:?}", e)))?;

            eprintln!("  pre_exec: Seccomp done");
            Ok(())
        });
    }
    match cmd.output() {
        Ok(o) => {
            println!("  exit status: {:?}", o.status);
            println!("  exit code: {:?}", o.status.code());
            println!("  stdout: {}", String::from_utf8_lossy(&o.stdout).trim());
            println!("  stderr: {}", String::from_utf8_lossy(&o.stderr).trim());
        }
        Err(e) => println!("  FAIL: {}", e),
    }

    println!("\nDone!");
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only runs on Linux.");
}
