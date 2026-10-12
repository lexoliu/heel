//! Native zero-capability launch regressions independent of shell environment preparation.
#![cfg(windows)]

use rappct::capability::SecurityCapabilitiesBuilder;
use rappct::launch::{LaunchOptions, StdioConfig, launch_in_container_with_io};
use rappct::profile::AppContainerProfile;

fn launch_without_environment(stdio: StdioConfig) {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("rappct=trace")
        .try_init();
    let name = format!("heel-launch-probe-{:016x}", rand::random::<u64>());
    let profile =
        AppContainerProfile::ensure(&name, "heel launch regression", None).expect("profile");
    let capabilities = SecurityCapabilitiesBuilder::new(&profile.sid)
        .build()
        .expect("capabilities");
    let root = std::env::var_os("SystemRoot").expect("Windows SystemRoot");
    let options = LaunchOptions {
        exe: std::path::PathBuf::from(root)
            .join("System32")
            .join("cmd.exe"),
        cmdline: Some("cmd.exe /D /S /C exit 0".to_owned()),
        cwd: None,
        env: None,
        stdio,
        ..LaunchOptions::default()
    };
    let result = launch_in_container_with_io(&capabilities, &options)
        .and_then(|process| process.wait(Some(std::time::Duration::from_secs(10))));
    profile.delete().expect("delete owned profile");
    assert_eq!(
        result.expect("zero-capability native launch with inherited environment"),
        0
    );
}

#[test]
fn zero_capability_launch_with_inherited_environment() {
    launch_without_environment(StdioConfig::Inherit);
}

#[test]
fn zero_capability_launch_with_null_stdio_and_inherited_environment() {
    launch_without_environment(StdioConfig::Null);
}
