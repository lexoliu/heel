#![allow(dead_code, clippy::unwrap_used)]

use std::path::{Path, PathBuf};

pub fn compile(dir: &Path, source: &str, name: &str) -> PathBuf {
    let binary = dir
        .join(name)
        .with_extension(std::env::consts::EXE_EXTENSION);
    let input = dir.join(name).with_extension("rs");
    std::fs::write(&input, source).expect("fixture source");
    let result = std::process::Command::new("rustc")
        .args(["--edition=2021", "-O", "-o"])
        .arg(&binary)
        .arg(&input)
        .output()
        .expect("fixture compiler");
    assert!(
        result.status.success(),
        "rustc: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    binary
}

/// Helpers for the tests that run commands in a sandbox carrying the host
/// protection policies.
#[cfg(unix)]
pub mod host {
    use std::path::Path;
    use std::process::Output;

    use heel::{
        DenyAll, NetworkPolicy, ReadDenylist, Sandbox, SandboxConfigBuilder, SecurityConfig,
        SecurityConfigBuilder, WriteDenylist,
    };

    /// The data protections off, hardware off: the denylists are the whole policy.
    pub fn open_security() -> SecurityConfig {
        SecurityConfigBuilder::from_permissive()
            .allow_hardware(false)
            .allow_tcc_prompts(false)
            .build()
    }

    /// A sandbox that reads everything the denylist leaves and writes only what it
    /// is granted.
    pub fn reader<N: NetworkPolicy>(network: N, home: &Path) -> SandboxConfigBuilder<N> {
        SandboxConfigBuilder::default()
            .network(network)
            .filesystem_strict(false)
            .security(open_security())
            .read_denylist(ReadDenylist::credentials().home(home))
    }

    /// A sandbox that writes everything the denylist leaves, as a default build does.
    pub fn writer(home: &Path) -> SandboxConfigBuilder<DenyAll> {
        SandboxConfigBuilder::default()
            .filesystem_strict(false)
            .security(open_security())
            .writable_file_system(true)
            .write_denylist(WriteDenylist::persistence().home(home))
    }

    pub async fn start<N: NetworkPolicy>(builder: SandboxConfigBuilder<N>) -> Sandbox<N> {
        Sandbox::with_config_and_executor(builder.build(), executor_core::tokio::TokioGlobal)
            .await
            .expect("the sandbox starts")
    }

    pub async fn sh<N: NetworkPolicy>(sandbox: &Sandbox<N>, script: &str) -> Output {
        sandbox
            .command("/bin/sh")
            .arg("-c")
            .arg(script)
            .output()
            .await
            .expect("the shell runs")
    }

    pub fn stderr(output: &Output) -> String {
        String::from_utf8_lossy(&output.stderr).trim().to_owned()
    }

    pub fn stdout(output: &Output) -> String {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    }

    /// A home directory holding a file at each of `relative`.
    pub fn home_with(relative: &[&str]) -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        for path in relative {
            let path = home.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, "secret").unwrap();
        }
        home
    }
}
