//! Minimal test to isolate Landlock vs Seccomp issue

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing Landlock only...");

    // Test 1: Landlock only
    let mut cmd = Command::new("echo");
    cmd.args(["Landlock test"]);

    unsafe {
        cmd.pre_exec(|| {
            use landlock::{ABI, Access, AccessFs, Ruleset, RulesetAttr};

            let abi = ABI::V4;
            let ruleset = Ruleset::default()
                .handle_access(AccessFs::from_all(abi))
                .map_err(|e| std::io::Error::other(format!("handle_access: {}", e)))?
                .create()
                .map_err(|e| std::io::Error::other(format!("create: {}", e)))?;

            let status = ruleset
                .restrict_self()
                .map_err(|e| std::io::Error::other(format!("restrict_self: {}", e)))?;

            println!("Landlock status: {:?}", status);
            Ok(())
        });
    }

    match cmd.output() {
        Ok(out) => {
            println!("Landlock test succeeded!");
            println!("Output: {}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => {
            println!("Landlock test failed: {}", e);
        }
    }

    println!("\nTesting Seccomp only...");

    // Test 2: Seccomp only
    let mut cmd2 = Command::new("echo");
    cmd2.args(["Seccomp test"]);

    unsafe {
        cmd2.pre_exec(|| {
            use seccompiler::{SeccompAction, SeccompFilter, TargetArch};
            use std::collections::BTreeMap;

            let rules: BTreeMap<i64, Vec<seccompiler::SeccompRule>> = BTreeMap::new();

            // Simple allow-all filter
            let filter = SeccompFilter::new(
                rules,
                SeccompAction::Errno(libc::EPERM as u32),
                SeccompAction::Allow,
                TargetArch::aarch64, // Adjust based on arch
            )
            .map_err(|e| std::io::Error::other(format!("SeccompFilter::new: {:?}", e)))?;

            let program: seccompiler::BpfProgram = filter
                .try_into()
                .map_err(|e| std::io::Error::other(format!("BpfProgram: {:?}", e)))?;

            seccompiler::apply_filter(&program)
                .map_err(|e| std::io::Error::other(format!("apply_filter: {:?}", e)))?;

            Ok(())
        });
    }

    match cmd2.output() {
        Ok(out) => {
            println!("Seccomp test succeeded!");
            println!("Output: {}", String::from_utf8_lossy(&out.stdout));
        }
        Err(e) => {
            println!("Seccomp test failed: {}", e);
        }
    }

    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This example only runs on Linux.");
}
