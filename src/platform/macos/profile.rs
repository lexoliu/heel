//! SBPL profile generation using compile-time templates

use std::path::Path;

use askama::Template;

use crate::config::SandboxConfigData;
use crate::error::Result;

/// SBPL profile template
#[derive(Template)]
#[template(path = "sandbox.txt", escape = "none")]
struct SandboxProfile {
    readable_paths: Vec<String>,
    writable_paths: Vec<String>,
    executable_paths: Vec<String>,
    working_dir: String,
    python_venv_path: Option<String>,
    writable_file_system: bool,
    network_deny_all: bool,
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
    proxy_port: u16,
    ipc_port: Option<u16>,
    // Terminal access
    allow_tty_write: bool,
}

/// Generate an SBPL profile from sandbox configuration
///
/// If network is enabled, sandboxed processes are restricted to connecting only to the proxy port.
/// When network is disabled, all network access is denied.
pub fn generate_profile(config: &SandboxConfigData, proxy_port: u16) -> Result<String> {
    // Log the configuration
    tracing::debug!("sandbox policy: deny all by default");
    if config.filesystem_strict() {
        tracing::warn!(
            "macOS backend ignores filesystem_strict and uses broad reads with explicit sensitive-path denies"
        );
    }

    for path in config.readable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow read");
    }

    for path in config.writable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow write");
    }

    for path in config.executable_paths() {
        tracing::debug!(path = %path.display(), "sandbox: allow exec");
    }

    tracing::debug!(path = %config.working_dir().display(), "sandbox: allow write (working dir)");

    if let Some(python_config) = config.python() {
        tracing::debug!(path = %python_config.venv().path().display(), "sandbox: allow python venv");
    }

    if config.network_deny_all() {
        tracing::debug!("sandbox: network disabled");
    } else {
        tracing::debug!(
            proxy_port = proxy_port,
            "sandbox: network restricted to proxy port only"
        );
    }

    let security = config.security();
    if security.allow_gpu {
        tracing::debug!("sandbox: allow GPU access");
    }
    if security.allow_npu {
        tracing::debug!("sandbox: allow NPU access");
    }
    if security.allow_hardware {
        tracing::debug!("sandbox: allow general hardware access");
    }

    // Prepare template data
    let template = SandboxProfile {
        readable_paths: config
            .readable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        writable_paths: config
            .writable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        executable_paths: config
            .executable_paths()
            .iter()
            .map(|p| escape_path(p))
            .collect(),
        working_dir: escape_path(config.working_dir()),
        python_venv_path: config.python().map(|p| escape_path(p.venv().path())),
        writable_file_system: config.writable_file_system(),
        network_deny_all: config.network_deny_all(),
        // Security protection flags
        protect_user_home: security.protect_user_home,
        allow_tcc_prompts: security.allow_tcc_prompts,
        protect_credentials: security.protect_credentials,
        protect_cloud_config: security.protect_cloud_config,
        protect_browser_data: security.protect_browser_data,
        protect_keychain: security.protect_keychain,
        protect_shell_history: security.protect_shell_history,
        protect_package_credentials: security.protect_package_credentials,
        // Hardware access flags
        allow_gpu: security.allow_gpu,
        allow_npu: security.allow_npu,
        allow_hardware: security.allow_hardware,
        proxy_port,
        ipc_port: config.ipc_port(),
        // Terminal access
        allow_tty_write: config.allow_tty_write(),
    };

    let profile = template.render().map_err(|e| {
        crate::error::Error::InvalidProfile(format!("Template render error: {}", e))
    })?;

    tracing::debug!("Generated SBPL profile:\n{}", profile);

    Ok(profile)
}

/// Escape a path for use in SBPL string literals
///
/// SBPL uses Scheme-like syntax where strings are double-quoted.
/// This function escapes all special characters that could break
/// the string literal or allow injection attacks.
fn escape_path(path: &Path) -> String {
    let path_str = path.to_string_lossy();
    let mut escaped = String::with_capacity(path_str.len() + 16);

    for c in path_str.chars() {
        match c {
            // Characters that MUST be escaped in SBPL strings
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            // Null byte would truncate the string - reject entirely
            '\0' => {
                tracing::error!(path = %path.display(), "path contains null byte, skipping");
                return String::new();
            }
            // SBPL special characters that could break parsing if unquoted
            // These are safe inside a quoted string
            '(' | ')' | ';' => {
                // These are safe inside quotes, but log a warning
                tracing::warn!(path = %path.display(), char = %c, "path contains SBPL special character");
                escaped.push(c);
            }
            // All other characters pass through
            _ => escaped.push(c),
        }
    }

    escaped
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SandboxConfig;
    use crate::network::AllowAll;
    use crate::network::DenyAll;
    use std::process::Command;

    #[test]
    fn test_generate_basic_profile() {
        let config = SandboxConfig::<DenyAll>::new().unwrap();
        let working_dir = config.working_dir().to_path_buf();
        let (_policy, config_data) = config.into_parts();
        let profile = generate_profile(&config_data, 12345).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-inbound (local tcp \"localhost:*\"))"));
        // Verify deny-all has no allow rule for proxy
        assert!(!profile.contains("(allow network-outbound (remote ip \"localhost:12345\"))"));

        // Clean up the random working directory
        std::fs::remove_dir(&working_dir).ok();
    }

    #[test]
    fn test_generate_profile_allows_proxy_when_enabled() {
        let config = SandboxConfig::builder().network(AllowAll).build().unwrap();
        let working_dir = config.working_dir().to_path_buf();
        let (_policy, config_data) = config.into_parts();
        let profile = generate_profile(&config_data, 23456).unwrap();

        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow network-outbound (remote ip \"localhost:23456\"))"));

        // Clean up the random working directory
        std::fs::remove_dir(&working_dir).ok();
    }

    #[test]
    fn generated_profile_allows_ephemeral_loopback_server() {
        let config = SandboxConfig::<DenyAll>::new().unwrap();
        let working_dir = config.working_dir().to_path_buf();
        let (_policy, config_data) = config.into_parts();
        let profile = generate_profile(&config_data, 12345).unwrap();

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

        std::fs::remove_dir(&working_dir).ok();
    }

    #[test]
    fn test_escape_path() {
        // Normal paths pass through unchanged
        assert_eq!(escape_path(Path::new("/usr/bin")), "/usr/bin");
        assert_eq!(
            escape_path(Path::new("/path/with spaces")),
            "/path/with spaces"
        );

        // Double quotes are escaped
        assert_eq!(
            escape_path(Path::new(r#"/path/with"quote"#)),
            r#"/path/with\"quote"#
        );

        // Backslashes are escaped
        assert_eq!(
            escape_path(Path::new(r"/path\with\backslash")),
            r"/path\\with\\backslash"
        );

        // Newlines and tabs are escaped
        assert_eq!(
            escape_path(Path::new("/path/with\nnewline")),
            "/path/with\\nnewline"
        );
        assert_eq!(
            escape_path(Path::new("/path/with\ttab")),
            "/path/with\\ttab"
        );

        // Null bytes return empty string (rejected)
        assert_eq!(escape_path(Path::new("/path/with\0null")), "");
    }
}
