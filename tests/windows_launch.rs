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
        cwd: Some(
            std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"))
                .join("System32"),
        ),
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

fn raw_zero_capability_launch(
    profile: &AppContainerProfile,
    null_array: bool,
) -> windows::core::Result<()> {
    use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::{PSID, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};
    use windows::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, PROCESS_INFORMATION, STARTUPINFOEXW,
        STARTUPINFOW, UpdateProcThreadAttribute, WaitForSingleObject,
    };
    use windows::core::{PCWSTR, PWSTR};

    let sid_text = rappct::util::to_utf16(profile.sid.as_string());
    let root = std::path::PathBuf::from(std::env::var_os("SystemRoot").expect("SystemRoot"));
    let directory = root.join("System32");
    let cwd = rappct::util::to_utf16_os(directory.as_os_str());
    let exe = rappct::util::to_utf16_os(directory.join("cmd.exe").as_os_str());
    let mut command = rappct::util::to_utf16("cmd.exe /D /S /C exit 0");
    let entries: Vec<SID_AND_ATTRIBUTES> = Vec::new();
    let mut sid = PSID::default();
    // SAFETY: all input strings are terminated, owned SID and attribute storage outlive CreateProcessW, and successful process handles are closed once.
    unsafe {
        ConvertStringSidToSidW(PCWSTR(sid_text.as_ptr()), &mut sid)?;
        let _sid_owner = rappct::util::LocalFreeGuard::new(sid.0);
        let capabilities = SECURITY_CAPABILITIES {
            AppContainerSid: sid,
            Capabilities: if null_array {
                std::ptr::null_mut()
            } else {
                entries.as_ptr().cast_mut()
            },
            CapabilityCount: 0,
            Reserved: 0,
        };
        let mut length = 0;
        let _ = InitializeProcThreadAttributeList(None, 1, None, &mut length);
        let mut storage = vec![0usize; length.div_ceil(std::mem::size_of::<usize>())];
        let attributes = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast());
        InitializeProcThreadAttributeList(Some(attributes), 1, None, &mut length)?;
        let startup = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                ..Default::default()
            },
            lpAttributeList: attributes,
        };
        let mut process = PROCESS_INFORMATION::default();
        let result = UpdateProcThreadAttribute(
            attributes,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            Some(std::ptr::from_ref(&capabilities).cast()),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .and_then(|()| {
            CreateProcessW(
                PCWSTR(exe.as_ptr()),
                Some(PWSTR(command.as_mut_ptr())),
                None,
                None,
                false,
                EXTENDED_STARTUPINFO_PRESENT,
                None,
                PCWSTR(cwd.as_ptr()),
                std::ptr::from_ref(&startup).cast(),
                &mut process,
            )
        });
        DeleteProcThreadAttributeList(attributes);
        result?;
        let waited = WaitForSingleObject(process.hProcess, 10_000);
        CloseHandle(process.hThread)?;
        CloseHandle(process.hProcess)?;
        assert_eq!(waited, WAIT_OBJECT_0);
        Ok(())
    }
}

#[test]
fn empty_capability_array_is_null_for_native_launch() {
    let _ = tracing_subscriber::fmt().try_init();
    let name = format!("heel-raw-launch-{:016x}", rand::random::<u64>());
    let profile = AppContainerProfile::ensure(&name, "heel native parameter regression", None)
        .expect("profile");
    let null_result = raw_zero_capability_launch(&profile, true);
    let dangling_result = raw_zero_capability_launch(&profile, false);
    tracing::info!(
        ?null_result,
        ?dangling_result,
        "zero-capability array pointer comparison"
    );
    profile.delete().expect("owned profile cleanup");
    null_result.expect("native zero-capability launch uses a null array pointer");
}

#[test]
fn zero_capability_launch_with_inherited_environment() {
    launch_without_environment(StdioConfig::Inherit);
}

#[test]
fn zero_capability_launch_with_null_stdio_and_inherited_environment() {
    launch_without_environment(StdioConfig::Null);
}
