//! Native zero-capability launch regressions independent of shell environment preparation.
#![cfg(windows)]

use std::io::Read;
use std::path::PathBuf;

use windows::Win32::Security::EqualSid;
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;

use super::child::AppContainerChild;
use super::container::Container;
use super::launch::{self, Launch, SecurityCapabilities, Stdio};
use crate::command::StdioConfig;
use crate::platform::SpawnRequest;
use crate::platform::child::ProcessHandle;
use crate::priority::ProcessPriority;

struct LaunchFixture {
    container: Container,
    config: crate::SandboxConfig,
    directory: tempfile::TempDir,
}

impl LaunchFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("native launch directory");
        let config = crate::SandboxConfig::builder()
            .working_dir(directory.path())
            .build();
        let container = Container::create().expect("native profile");
        container
            .grant_configured_paths(config.data())
            .expect("native launch grants");
        Self {
            container,
            config,
            directory,
        }
    }
}

/// Launch `cmd.exe` with `args` inside the fixture's container and return the
/// child, whose streams the caller may still want.
fn cmd(fixture: &LaunchFixture, args: &[&str], stdio: Stdio) -> AppContainerChild {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("heel=trace")
        .try_init();
    let program_args: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    let request = SpawnRequest {
        config: fixture.config.data(),
        proxy_port: None,
        program: "cmd.exe",
        args: &program_args,
        envs: &[],
        current_dir: Some(fixture.directory.path()),
        stdin: StdioConfig::Inherit,
        stdout: StdioConfig::Inherit,
        stderr: StdioConfig::Inherit,
    };
    let root = std::env::var_os("SystemRoot").expect("Windows SystemRoot");
    let options = Launch {
        package: fixture.container.sid(),
        capabilities: &[],
        exe: PathBuf::from(&root).join("System32").join("cmd.exe"),
        cmdline: super::command_line(&request),
        cwd: fixture.directory.path().to_owned(),
        env: super::environment(
            &request,
            fixture.container.local_app_data(),
            fixture.container.profile_folder(),
        ),
        stdio,
        memory_bytes: None,
        priority: ProcessPriority::default(),
    };
    let launched = launch::launch(&options).expect("zero-capability native launch");
    AppContainerChild::new(launched, None)
}

#[test]
fn zero_capability_launch_with_inherited_stdio() {
    let fixture = LaunchFixture::new();
    let mut child = cmd(&fixture, &["/D", "/S", "/C", "exit 0"], Stdio::Inherit);
    assert!(child.wait().expect("native launch wait").success());
}

#[test]
fn zero_capability_launch_with_null_stdio() {
    let fixture = LaunchFixture::new();
    let mut child = cmd(&fixture, &["/D", "/S", "/C", "exit 0"], Stdio::Null);
    assert!(child.wait().expect("native launch wait").success());
}

#[test]
fn zero_capability_launch_with_piped_stdio_reports_output() {
    let fixture = LaunchFixture::new();
    let mut child = cmd(&fixture, &["/D", "/S", "/C", "echo heel"], Stdio::Pipe);

    let mut stdout = String::new();
    child
        .stdout()
        .as_mut()
        .expect("piped stdout")
        .read_to_string(&mut stdout)
        .expect("read piped stdout");
    assert!(child.wait().expect("native launch wait").success());
    assert!(stdout.contains("heel"), "unexpected stdout: {stdout}");
}

#[test]
fn no_capability_builds_a_null_array() {
    let package = super::capability::internet_client().expect("well-known SID");
    let capabilities = SecurityCapabilities::new(&package, &[]);
    assert!(capabilities.value.Capabilities.is_null());
    assert_eq!(capabilities.value.CapabilityCount, 0);
}

#[test]
fn internet_client_builds_one_enabled_entry() {
    let package = super::capability::internet_client().expect("well-known SID");
    let capability = super::capability::internet_client().expect("well-known SID");
    let capabilities = SecurityCapabilities::new(&package, std::slice::from_ref(&capability));
    assert!(!capabilities.value.Capabilities.is_null());
    assert_eq!(capabilities.value.CapabilityCount, 1);
    // SAFETY: `Capabilities` names the one entry `capabilities` owns, which
    // outlives this read.
    let entry = unsafe { &*capabilities.value.Capabilities };
    assert_eq!(entry.Attributes, SE_GROUP_ENABLED as u32);
    // SAFETY: both are valid SIDs for the duration of the call.
    assert!(unsafe { EqualSid(entry.Sid, capability.as_psid()) }.is_ok());
}

#[test]
fn launch_keeps_two_capability_entries_in_order() {
    let package = super::capability::internet_client().expect("well-known SID");
    let first = super::capability::internet_client().expect("well-known SID");
    let second =
        super::capability::derived("heel-sandbox-launch-test").expect("named capability SID");
    let expected = [first, second];
    let capabilities = SecurityCapabilities::new(&package, &expected);

    assert_eq!(capabilities.value.CapabilityCount, 2);
    // SAFETY: `Capabilities` names the two entries `capabilities` owns.
    let entries = unsafe { std::slice::from_raw_parts(capabilities.value.Capabilities, 2) };
    for (entry, sid) in entries.iter().zip(&expected) {
        assert_eq!(entry.Attributes, SE_GROUP_ENABLED as u32);
        // SAFETY: both are valid SIDs for the duration of the call.
        assert!(unsafe { EqualSid(entry.Sid, sid.as_psid()) }.is_ok());
    }
}
