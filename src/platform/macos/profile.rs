//! SBPL profile generation using compile-time templates.

use std::path::{Path, PathBuf};

use askama::Template;

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};

/// A Python virtual environment as the template sees it.
struct VenvRules {
    path: String,
    writable: bool,
}

/// SBPL profile template.
#[derive(Template)]
#[template(path = "sandbox.txt", escape = "none")]
struct SandboxProfile {
    readable_paths: Vec<String>,
    writable_paths: Vec<String>,
    executable_paths: Vec<String>,
    working_dir: String,
    ipc_bin_dir: Option<String>,
    ipc_socket_dir: Option<String>,
    ipc_socket: Option<String>,
    traversal_paths: Vec<String>,
    python_venv: Option<VenvRules>,
    writable_file_system: bool,
    filesystem_strict: bool,
    // Security protection flags
    protect_user_home: bool,
    allow_tcc_prompts: bool,
    protect_credentials: bool,
    protect_cloud_config: bool,
    protect_browser_data: bool,
    protect_keychain: bool,
    protect_shell_history: bool,
    protect_package_credentials: bool,
    // Hardware access flags
    allow_gpu: bool,
    allow_npu: bool,
    allow_hardware: bool,
    // Network
    proxy_port: Option<u16>,
    // Terminal access
    allow_tty_write: bool,
}

/// Generate an SBPL profile from a sandbox configuration.
///
/// `proxy_port` is `Some` only when the network policy permits traffic; when it
/// is `None` the profile denies all outbound connections in the kernel.
pub fn generate_profile(config: &SandboxConfigData, proxy_port: Option<u16>) -> Result<String> {
    let security = config.security();

    let mut template = SandboxProfile {
        readable_paths: sbpl_paths(config.readable_paths())?,
        writable_paths: sbpl_paths(config.writable_paths())?,
        executable_paths: sbpl_paths(config.executable_paths())?,
        working_dir: sbpl_path(config.working_dir())?,
        ipc_bin_dir: config
            .ipc_socket()
            .map(|_| crate::ipc::IpcLayout::new(config.working_dir()))
            .map(|layout| sbpl_path(layout.bin_dir()))
            .transpose()?,
        ipc_socket_dir: config
            .ipc_socket()
            .and_then(Path::parent)
            .map(sbpl_path)
            .transpose()?,
        // The socket file itself may not exist yet when a profile is generated
        // before the server binds, so it is escaped rather than canonicalized;
        // its directory is canonical already.
        ipc_socket: config
            .ipc_socket()
            .map(|socket| -> Result<String> {
                let dir = socket.parent().unwrap_or(Path::new("/"));
                let name = socket.file_name().unwrap_or_default();
                escape_path(
                    &std::fs::canonicalize(dir)
                        .map_err(|e| Error::path(dir, e))?
                        .join(name),
                )
            })
            .transpose()?,
        python_venv: config
            .python()
            .map(|python| -> Result<VenvRules> {
                Ok(VenvRules {
                    path: sbpl_path(python.venv().path())?,
                    writable: python.allow_pip_install(),
                })
            })
            .transpose()?,
        writable_file_system: config.writable_file_system(),
        filesystem_strict: config.filesystem_strict(),
        protect_user_home: security.protect_user_home(),
        allow_tcc_prompts: security.allow_tcc_prompts(),
        protect_credentials: security.protect_credentials(),
        protect_cloud_config: security.protect_cloud_config(),
        protect_browser_data: security.protect_browser_data(),
        protect_keychain: security.protect_keychain(),
        protect_shell_history: security.protect_shell_history(),
        protect_package_credentials: security.protect_package_credentials(),
        allow_gpu: security.allow_gpu(),
        allow_npu: security.allow_npu(),
        allow_hardware: security.allow_hardware(),
        proxy_port,
        allow_tty_write: config.allow_tty_write(),
        traversal_paths: Vec::new(),
    };
    template.traversal_paths = traversal_paths(&template);

    let profile = template.render()?;

    tracing::debug!(
        strict = config.filesystem_strict(),
        proxy_port,
        working_dir = %config.working_dir().display(),
        "generated SBPL profile"
    );
    tracing::trace!("SBPL profile:\n{profile}");

    Ok(profile)
}

/// Every ancestor directory of every granted path.
///
/// A protection rule that covers an ancestor of a granted path makes that path
/// unreachable even though the path itself is allowed: the kernel refuses to
/// resolve through the denied component, so `chdir` into an allowed directory
/// fails. Re-allowing each ancestor as a literal restores traversal while
/// leaving its other children denied.
fn traversal_paths(profile: &SandboxProfile) -> Vec<String> {
    let granted = profile
        .readable_paths
        .iter()
        .chain(&profile.writable_paths)
        .chain(&profile.executable_paths)
        .chain(std::iter::once(&profile.working_dir))
        .chain(profile.ipc_bin_dir.iter())
        .chain(profile.ipc_socket_dir.iter())
        .chain(profile.python_venv.iter().map(|venv| &venv.path));

    let mut ancestors: Vec<String> = granted
        .flat_map(|path| {
            Path::new(path)
                .ancestors()
                .skip(1)
                .filter(|ancestor| !ancestor.as_os_str().is_empty())
                .map(|ancestor| ancestor.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        })
        .collect();

    ancestors.sort_unstable();
    ancestors.dedup();
    ancestors
}

/// Canonicalize and escape a list of configured paths.
fn sbpl_paths(paths: &[PathBuf]) -> Result<Vec<String>> {
    paths.iter().map(|path| sbpl_path(path)).collect()
}

/// Canonicalize a path and escape it for an SBPL string literal.
///
/// Canonicalization is a correctness requirement rather than tidiness: the
/// macOS sandbox matches rules against fully resolved paths, so a rule naming
/// `/tmp/data` never matches the kernel's `/private/tmp/data` and would
/// silently grant nothing. A path that cannot be resolved is an error, because
/// emitting a rule that matches nothing is exactly the failure this avoids.
fn sbpl_path(path: &Path) -> Result<String> {
    let canonical = std::fs::canonicalize(path).map_err(|source| Error::path(path, source))?;
    escape_path(&canonical)
}

/// Escape a path for use inside an SBPL double-quoted string.
fn escape_path(path: &Path) -> Result<String> {
    let path_str = path.to_string_lossy();
    let mut escaped = String::with_capacity(path_str.len() + 16);

    for c in path_str.chars() {
        match c {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            // A null byte would truncate the string literal and silently
            // broaden the rule, so refuse the path outright.
            '\0' => {
                return Err(Error::InvalidProfile(format!(
                    "path contains a null byte: {}",
                    path.display()
                )));
            }
            _ => escaped.push(c),
        }
    }

    Ok(escaped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SandboxConfig, SandboxConfigData};
    use crate::network::AllowAll;
    use crate::workdir::WorkingDir;
    use std::process::Command;

    /// A configuration whose working directory exists, as it would at runtime.
    fn prepared_config<N: crate::network::NetworkPolicy>(
        config: SandboxConfig<N>,
    ) -> (SandboxConfigData, WorkingDir) {
        let (_policy, mut data, _ipc) = config.into_parts();
        let dir = WorkingDir::create(data.working_dir(), data.working_dir_is_auto())
            .expect("working directory is created");
        data.set_working_dir(dir.path().to_path_buf());
        (data, dir)
    }

    #[test]
    fn deny_all_profile_has_no_outbound_rule() {
        let (data, _dir) = prepared_config(SandboxConfig::new());
        let profile = generate_profile(&data, None).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
        assert!(!profile.contains("network-outbound"));
    }

    #[test]
    fn proxy_port_is_allowed_when_network_is_enabled() {
        let (data, _dir) = prepared_config(SandboxConfig::builder().network(AllowAll).build());
        let profile = generate_profile(&data, Some(23456)).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:23456\"))"));
    }

    #[test]
    fn writable_locations_cannot_be_executed() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let (data, dir) = prepared_config(
            SandboxConfig::builder()
                .writable_path(scratch.path())
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();

        let scratch_canonical = std::fs::canonicalize(scratch.path()).expect("canonical");
        assert!(profile.contains(&format!(
            "(deny process-exec (subpath \"{}\"))",
            scratch_canonical.display()
        )));
        assert!(profile.contains(&format!(
            "(deny process-exec (subpath \"{}\"))",
            dir.path().display()
        )));
        assert!(profile.contains("(deny process-exec (subpath \"/private/tmp\"))"));
    }

    #[test]
    fn paths_are_canonicalized_into_the_profile() {
        // /tmp is a symlink to /private/tmp on macOS; the profile must name the
        // resolved path or the rule matches nothing.
        let scratch = Path::new("/tmp").join(crate::workdir::generate_working_dir_name());
        std::fs::create_dir_all(&scratch).expect("creates");

        let (data, _dir) =
            prepared_config(SandboxConfig::builder().readable_path(&scratch).build());
        let profile = generate_profile(&data, None).unwrap();

        assert!(
            profile.contains("(allow file-read* (subpath \"/private/tmp/"),
            "expected a resolved path in:\n{profile}"
        );
        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn missing_configured_paths_are_rejected() {
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable_path("/definitely/not/a/real/path")
                .build(),
        );

        let error = generate_profile(&data, None).unwrap_err();
        assert!(
            matches!(error, Error::Path { .. }),
            "expected a path error, got {error:?}"
        );
    }

    #[test]
    fn strict_mode_denies_user_data() {
        let (data, _dir) =
            prepared_config(SandboxConfig::builder().filesystem_strict(true).build());
        let profile = generate_profile(&data, None).unwrap();
        assert!(profile.contains("(deny file-read* (subpath \"/Users\")"));
    }

    #[test]
    fn shared_temp_is_readable_but_not_writable_outside_strict_mode() {
        let (data, _dir) =
            prepared_config(SandboxConfig::builder().filesystem_strict(false).build());
        let profile = generate_profile(&data, None).unwrap();

        assert!(!profile.contains("(deny file-read* (subpath \"/Users\")"));
        assert!(profile.contains("(allow file-read* (subpath \"/private/tmp\"))"));
        assert!(
            !profile.contains("(allow file-write* (subpath \"/private/tmp\"))"),
            "the sandbox has its own writable directory; shared temp is not one"
        );
    }

    #[test]
    fn escaping_covers_sbpl_string_metacharacters() {
        assert_eq!(escape_path(Path::new("/usr/bin")).unwrap(), "/usr/bin");
        assert_eq!(
            escape_path(Path::new("/path/with spaces")).unwrap(),
            "/path/with spaces"
        );
        assert_eq!(
            escape_path(Path::new(r#"/path/with"quote"#)).unwrap(),
            r#"/path/with\"quote"#
        );
        assert_eq!(
            escape_path(Path::new(r"/path\with\backslash")).unwrap(),
            r"/path\\with\\backslash"
        );
        assert_eq!(
            escape_path(Path::new("/path/with\nnewline")).unwrap(),
            "/path/with\\nnewline"
        );
    }

    #[test]
    fn null_bytes_are_rejected_rather_than_dropped() {
        let error = escape_path(Path::new("/path/with\0null")).unwrap_err();
        assert!(matches!(error, Error::InvalidProfile(_)));
    }

    #[test]
    fn generated_profile_allows_ephemeral_loopback_server() {
        let (data, _dir) = prepared_config(SandboxConfig::new());
        let profile = generate_profile(&data, None).unwrap();

        let output = Command::new("sandbox-exec")
            .args([
                "-p",
                &profile,
                "/usr/bin/ruby",
                "-rsocket",
                "-e",
                "server = TCPServer.new('127.0.0.1', 0); server.close",
            ])
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "loopback bind failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
