//! A `heel` binary of another version than the library is refused.
//!
//! This test process sets `HEEL_BIN`, so it holds the only test in its file.

#![cfg(any(target_os = "macos", target_os = "linux"))]

use std::os::unix::fs::PermissionsExt;

use heel::{Error, HeelBinary, Sandbox, SandboxConfigBuilder};

fn assert_names_both_versions(error: &Error) {
    let Error::InitFailed(message) = error else {
        panic!("{error:?}");
    };
    assert!(message.contains("version 0.0.1"), "{message}");
    assert!(
        message.contains(&format!("version {}", env!("CARGO_PKG_VERSION"))),
        "{message}"
    );
}

#[test]
fn a_stale_binary_fails_verification_and_lookup() {
    let dir = tempfile::tempdir().expect("tempdir");
    let stale = dir.path().join("heel");
    std::fs::write(&stale, "#!/bin/sh\necho 'heel 0.0.1'\n").expect("writes");
    std::fs::set_permissions(&stale, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let error = HeelBinary::verify(&stale).expect_err("a mismatched binary is refused");
    assert_names_both_versions(&error);

    // A configuration without a binary looks one up, and the lookup verifies.
    // SAFETY: nothing else runs in this process yet, so no thread reads the
    // environment while it is changed.
    unsafe { std::env::set_var("HEEL_BIN", &stale) };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("runtime");
    let error = runtime
        .block_on(async {
            let config = SandboxConfigBuilder::default()
                .ipc(heel::IpcRouter::new())
                .build();
            Sandbox::with_config_and_executor(config, executor_core::tokio::TokioGlobal).await
        })
        .err()
        .expect("sandbox creation refuses the stale HEEL_BIN");
    assert_names_both_versions(&error);

    let error = HeelBinary::locate().expect_err("locate refuses it too");
    assert_names_both_versions(&error);
}
