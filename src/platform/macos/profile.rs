//! SBPL profile generation using compile-time templates.

use std::path::Path;

use askama::Template;

use crate::config::SandboxConfigData;
use crate::denial::denial_tag;
use crate::error::{Error, Result};
use crate::grant::Grant;
use crate::platform::unresolved;
use crate::policy::{Pattern, Resolved};

/// A Python virtual environment as the template sees it.
struct VenvRules {
    path: String,
    writable: bool,
}

/// How SBPL matches one configured path.
///
/// The two filters are not interchangeable: `literal` matches exactly one path,
/// so naming a directory with it grants nothing at all, while `subpath` covers
/// the whole tree beneath it. Which one a rule needs follows from what the
/// granted path is, and is decided once, when the profile is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathFilter {
    /// One path, matched exactly: a grant naming a single file.
    Literal,
    /// A directory and everything beneath it.
    Subpath,
}

impl PathFilter {
    /// The filter that grants `path`, which must already be resolved.
    fn for_path(path: &Path) -> Result<Self> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|source| Error::path(path, source))?;
        Ok(if metadata.is_dir() {
            Self::Subpath
        } else {
            Self::Literal
        })
    }
}

impl std::fmt::Display for PathFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Literal => "literal",
            Self::Subpath => "subpath",
        })
    }
}

/// One configured grant as the template sees it.
///
/// The template emits the whole grant as one block, so the rule order that
/// decides the outcome — read, then write, then the exec allow or deny that
/// SBPL's last-match-wins resolution settles on — is a property of this one
/// loop rather than of how three separate loops happen to be arranged.
struct GrantRules {
    path: String,
    filter: PathFilter,
    writable: bool,
    executable: bool,
}

/// A host protection policy as the template sees it: every path already
/// resolved and escaped, every filter already written.
struct HostRules {
    trees: Vec<String>,
    /// Complete filters for the entries found beneath any directory.
    anywhere: Vec<String>,
    /// Complete filters for the directories that contain those entries.
    anywhere_parents: Vec<String>,
    sockets: Vec<String>,
    guarded_parents: Vec<String>,
}

impl HostRules {
    /// Render `resolved`, leaving the any-directory entries alone beneath each
    /// of its exemptions.
    fn new(resolved: &Resolved) -> Result<Self> {
        let exemptions = resolved
            .exempt
            .iter()
            .map(|path| -> Result<String> {
                Ok(format!(
                    "(require-not (subpath \"{}\"))",
                    escape_path(path)?
                ))
            })
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        let guard = |pattern: &Pattern, filter: String| {
            if exemptions.is_empty() || !pattern.is_anywhere() {
                filter
            } else {
                format!("(require-all {filter} {exemptions})")
            }
        };

        let mut anywhere = Vec::new();
        let mut anywhere_parents = Vec::new();
        for pattern in &resolved.patterns {
            anywhere.push(guard(
                pattern,
                format!("(regex #\"{}\")", quote_regex(&pattern.regex(true))),
            ));
            // `.git/hooks` is held in place by `.git`, and `.git` by nothing a
            // table can name, so every proper prefix is guarded too.
            for parent in pattern.guarded_parents() {
                anywhere_parents.push(guard(
                    pattern,
                    format!("(regex #\"{}\")", quote_regex(&parent.regex(false))),
                ));
            }
        }

        Ok(Self {
            trees: resolved
                .trees
                .iter()
                .map(|path| escape_path(path))
                .collect::<Result<_>>()?,
            anywhere,
            anywhere_parents,
            sockets: resolved
                .sockets
                .iter()
                .map(|path| escape_path(path))
                .collect::<Result<_>>()?,
            guarded_parents: resolved
                .guarded_parents
                .iter()
                .map(|path| escape_path(path))
                .collect::<Result<_>>()?,
        })
    }
}

/// SBPL profile template.
#[derive(Template)]
#[template(path = "sandbox.txt", escape = "none")]
struct SandboxProfile {
    grants: Vec<GrantRules>,
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
    // Host protection
    audit: String,
    deny_keychain_services: bool,
    read_rules: Option<HostRules>,
    write_rules: Option<HostRules>,
}

/// Generate an SBPL profile from a sandbox configuration.
///
/// `proxy_port` is `Some` only when the network policy permits traffic; when it
/// is `None` the profile denies all outbound connections in the kernel.
pub fn generate_profile(config: &SandboxConfigData, proxy_port: Option<u16>) -> Result<String> {
    let security = config.security();

    let mut template = SandboxProfile {
        grants: grant_rules(config.grants())?,
        working_dir: sbpl_path(config.working_dir())?,
        ipc_bin_dir: config.ipc_bin_dir().map(sbpl_path).transpose()?,
        ipc_socket_dir: config
            .ipc_socket()
            .and_then(Path::parent)
            .map(sbpl_path)
            .transpose()?,
        // The socket file itself may not exist yet when a profile is generated
        // before the server binds, so only its directory is verified.
        ipc_socket: config
            .ipc_socket()
            .map(|socket| -> Result<String> {
                let dir = socket.parent().unwrap_or(Path::new("/"));
                let name = socket.file_name().unwrap_or_default();
                unresolved::verify(dir)?;
                escape_path(&dir.join(name))
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
        audit: format!(
            "(with message \"{}\")",
            escape_str(&denial_tag(config.working_dir()))
        ),
        deny_keychain_services: security.protect_keychain() || config.read_denylist().is_some(),
        read_rules: config
            .read_denylist()
            .map(|denylist| HostRules::new(&denylist.resolve()?))
            .transpose()?,
        write_rules: config
            .write_denylist()
            .map(|denylist| HostRules::new(&denylist.resolve()?))
            .transpose()?,
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
        .grants
        .iter()
        .map(|grant| &grant.path)
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

/// Verify a granted path and escape it for an SBPL string literal.
fn sbpl_path(path: &Path) -> Result<String> {
    unresolved::verify(path)?;
    escape_path(path)
}

/// Build the rules for the configured grants, choosing a filter per path.
///
/// A grant naming a directory covers the whole tree beneath it, which is what
/// makes a build cache that is written and then executed usable; a grant naming
/// a file stays that one file.
fn grant_rules(grants: &[Grant]) -> Result<Vec<GrantRules>> {
    grants
        .iter()
        .map(|grant| {
            // The kernel matches rules against resolved paths, so the path is
            // emitted as the caller resolved it. A component that has become
            // a link since is refused rather than followed.
            unresolved::verify(grant.path())?;
            Ok(GrantRules {
                filter: PathFilter::for_path(grant.path())?,
                path: escape_path(grant.path())?,
                writable: grant.access().can_write(),
                executable: grant.access().can_execute(),
            })
        })
        .collect()
}

/// Make a regex safe inside an SBPL `#"..."` string, where a backslash is the
/// regex's own escape and only the quote needs one.
fn quote_regex(regex: &str) -> String {
    regex.replace('"', "\\\"")
}

/// Escape text with no null byte for use inside an SBPL double-quoted string.
fn escape_str(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
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
    use crate::grant::Access;
    use crate::network::AllowAll;
    use crate::workdir::WorkingDir;
    use std::path::PathBuf;
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

    /// A temporary directory's path as a caller must pass it: resolved.
    fn resolved(dir: &tempfile::TempDir) -> PathBuf {
        std::fs::canonicalize(dir.path()).expect("the temporary directory resolves")
    }

    #[test]
    fn deny_all_profile_has_no_outbound_rule() {
        let (data, _dir) = prepared_config(SandboxConfig::new());
        let profile = generate_profile(&data, None).unwrap();

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default (with message"));
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
                .writable(resolved(&scratch))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();

        let scratch_canonical = resolved(&scratch);
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
    fn an_executable_directory_is_granted_as_a_subpath() {
        let tools = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .executable(resolved(&tools))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();

        let canonical = resolved(&tools);
        assert!(
            profile.contains(&format!(
                "(allow process-exec (subpath \"{}\"))",
                canonical.display()
            )),
            "a directory grant must cover the tree:\n{profile}"
        );
        assert!(profile.contains(&format!(
            "(allow file-read* (subpath \"{}\"))",
            canonical.display()
        )));
    }

    #[test]
    fn an_executable_file_is_granted_as_a_literal() {
        let tools = tempfile::tempdir().expect("tempdir");
        let binary = resolved(&tools).join("tool");
        std::fs::write(&binary, b"#!/bin/sh\n").expect("writes");

        let (data, _dir) = prepared_config(SandboxConfig::builder().executable(&binary).build());
        let profile = generate_profile(&data, None).unwrap();

        let canonical = std::fs::canonicalize(&binary).expect("canonical");
        assert!(
            profile.contains(&format!(
                "(allow process-exec (literal \"{}\"))",
                canonical.display()
            )),
            "a file grant must name exactly that file:\n{profile}"
        );
        assert!(!profile.contains(&format!(
            "(allow process-exec (subpath \"{}\"))",
            canonical.display()
        )));
    }

    #[test]
    fn a_write_and_exec_grant_is_writable_and_executable() {
        // A build cache is written and then executed. One grant carries both,
        // so the path is never denied exec in the first place — there is no
        // deny for the profile's last-match resolution to have to beat.
        let cache = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .grant(resolved(&cache), Access::WRITE | Access::EXEC)
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();
        let canonical = resolved(&cache);

        for rule in [
            "allow file-read*",
            "allow file-write*",
            "allow file-write-create",
            "allow file-write-unlink",
            "allow process-exec",
        ] {
            let expected = format!("({rule} (subpath \"{}\"))", canonical.display());
            assert!(
                profile.contains(&expected),
                "missing {expected}:\n{profile}"
            );
        }

        assert!(
            !profile.contains(&format!(
                "(deny process-exec (subpath \"{}\"))",
                canonical.display()
            )),
            "a grant that allows exec must not also deny it:\n{profile}"
        );
    }

    #[test]
    fn an_exec_grant_still_beats_the_protections_above_it() {
        // The exec allow only wins because pass 3 comes after pass 2, and SBPL
        // resolves an operation with the last matching rule. A grant under the
        // shared temp directory, which pass 2 denies wholesale, is the case
        // where that ordering is the only thing doing the work.
        let tools = Path::new("/private/tmp").join(crate::workdir::generate_working_dir_name());
        std::fs::create_dir_all(&tools).expect("creates");

        let (data, _dir) = prepared_config(SandboxConfig::builder().executable(&tools).build());
        let profile = generate_profile(&data, None).unwrap();
        let canonical = std::fs::canonicalize(&tools).expect("canonical");
        std::fs::remove_dir_all(&tools).ok();

        let blanket = profile
            .find("(deny process-exec (subpath \"/private/tmp\"))")
            .expect("shared temp is denied exec");
        let grant = profile
            .find(&format!(
                "(allow process-exec (subpath \"{}\"))",
                canonical.display()
            ))
            .expect("the grant allows exec");

        assert!(
            blanket < grant,
            "an explicit grant must be emitted after the protection it overrides:\n{profile}"
        );
    }

    #[test]
    fn a_writable_grant_alone_is_still_denied_exec() {
        let cache = tempfile::tempdir().expect("tempdir");
        let (data, _dir) =
            prepared_config(SandboxConfig::builder().writable(resolved(&cache)).build());
        let profile = generate_profile(&data, None).unwrap();
        let canonical = std::fs::canonicalize(cache.path()).expect("canonical");

        assert!(profile.contains(&format!(
            "(deny process-exec (subpath \"{}\"))",
            canonical.display()
        )));
        assert!(!profile.contains(&format!(
            "(allow process-exec (subpath \"{}\"))",
            canonical.display()
        )));
    }

    #[test]
    fn a_grant_is_emitted_as_the_caller_resolved_it() {
        let scratch = Path::new("/private/tmp").join(crate::workdir::generate_working_dir_name());
        std::fs::create_dir_all(&scratch).expect("creates");

        let (data, _dir) = prepared_config(SandboxConfig::builder().readable(&scratch).build());
        let profile = generate_profile(&data, None).unwrap();

        assert!(
            profile.contains(&format!(
                "(allow file-read* (subpath \"{}\"))",
                scratch.display()
            )),
            "expected the granted path verbatim in:\n{profile}"
        );
        std::fs::remove_dir_all(&scratch).ok();
    }

    #[test]
    fn an_unresolved_grant_is_refused_and_nothing_is_emitted() {
        // /tmp is a symlink to /private/tmp on macOS. Resolving it here would
        // let a swapped link redirect a grant, so the caller resolves it.
        let (data, _dir) = prepared_config(SandboxConfig::builder().readable("/tmp").build());

        let error = generate_profile(&data, None).unwrap_err();
        assert!(
            matches!(&error, Error::GrantRedirected { path } if path == Path::new("/tmp")),
            "expected the redirected grant to be named, got {error:?}"
        );
    }

    #[test]
    fn a_grant_replaced_by_a_link_fails_the_next_build() {
        let root = tempfile::tempdir().expect("tempdir");
        let root = resolved(&root);
        let granted = root.join("granted");
        let nested = granted.join("nested");
        let target = root.join("target");
        std::fs::create_dir_all(&nested).expect("creates");
        std::fs::create_dir_all(&target).expect("creates");

        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(&granted)
                .writable(&nested)
                .build(),
        );
        generate_profile(&data, None).expect("an unchanged grant still builds");

        // The inner grant, then its parent, which is a grant too and is
        // checked first: each refusal names the first grant that reaches a link.
        for replaced in [&nested, &granted] {
            std::fs::remove_dir_all(replaced).expect("removes");
            std::os::unix::fs::symlink(&target, replaced).expect("links");

            let error = generate_profile(&data, None).unwrap_err();
            assert!(
                matches!(&error, Error::GrantRedirected { path } if path == replaced),
                "expected {} to be named, got {error:?}",
                replaced.display()
            );
        }
    }

    #[test]
    fn missing_configured_paths_are_rejected() {
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable("/definitely/not/a/real/path")
                .build(),
        );

        let error = generate_profile(&data, None).unwrap_err();
        assert!(
            matches!(error, Error::Path { .. }),
            "expected a path error, got {error:?}"
        );
    }

    #[test]
    fn persistent_identity_grants_are_adopted_into_the_profile() {
        let directory = tempfile::tempdir().expect("tempdir");
        let directory_path = resolved(&directory);
        let (mut data, _dir) = prepared_config(
            SandboxConfig::builder()
                .identity(
                    crate::identity::Identity::named("macos-test")
                        .expect("the identity name is valid")
                        .persistent_grant(crate::grant::Grant::new(&directory_path, Access::READ)),
                )
                .build(),
        );
        data.adopt_persistent_grants();

        let profile = generate_profile(&data, None).expect("the profile is generated");
        let path = escape_path(&directory_path).expect("the grant path escapes");
        assert!(
            profile.contains(&format!("(allow file-read* (subpath \"{path}\"))")),
            "the persistent grant is present in the profile:\n{profile}"
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
    fn host_protection_follows_every_grant_so_nothing_granted_reopens_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(resolved(&dir))
                .read_denylist(crate::ReadDenylist::credentials().home(home.path()))
                .write_denylist(crate::WriteDenylist::persistence().home(home.path()))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();

        let grant = profile
            .rfind("(allow file-write* (subpath")
            .expect("the grant is written");
        let ssh = profile
            .find(&format!(
                "(deny file-read* (subpath \"{}/.ssh\")",
                std::fs::canonicalize(home.path()).unwrap().display()
            ))
            .expect("the credential store is denied");
        let zshrc = profile
            .find(&format!(
                "(deny file-write* (subpath \"{}/.zshrc\")",
                std::fs::canonicalize(home.path()).unwrap().display()
            ))
            .expect("the shell startup file is denied");
        assert!(
            grant < ssh,
            "the read denial must follow the grants:\n{profile}"
        );
        assert!(
            grant < zshrc,
            "the write denial must follow the grants:\n{profile}"
        );
    }

    #[test]
    fn every_denial_is_tagged_so_it_can_be_attributed_to_the_sandbox() {
        let (data, dir) = prepared_config(SandboxConfig::new());
        let profile = generate_profile(&data, None).unwrap();
        let tag = crate::denial::denial_tag(dir.path());

        assert!(profile.contains(&format!("(deny default (with message \"{tag}\"))")));
        assert!(
            !profile.contains("no-log"),
            "a denial that is not logged cannot be recorded"
        );
    }

    #[test]
    fn the_security_services_are_closed_exactly_when_the_keychain_is_protected() {
        let (strict, _dir) = prepared_config(SandboxConfig::new());
        assert!(
            !generate_profile(&strict, None)
                .unwrap()
                .contains("(allow mach-lookup (global-name \"com.apple.SecurityServer\"))")
        );

        let (open, _dir) = prepared_config(
            SandboxConfig::builder()
                .security(crate::SecurityConfigBuilder::from_permissive().build())
                .build(),
        );
        assert!(
            generate_profile(&open, None)
                .unwrap()
                .contains("(allow mach-lookup (global-name \"com.apple.SecurityServer\"))")
        );

        // Certificate trust evaluation keeps its own service in both.
        assert!(
            generate_profile(&strict, None)
                .unwrap()
                .contains("(allow mach-lookup (global-name \"com.apple.trustd\"))")
        );
    }

    #[test]
    fn the_hooks_rule_is_narrowed_by_an_exemption_and_nothing_else_is() {
        let home = tempfile::tempdir().expect("tempdir");
        let clones = tempfile::tempdir().expect("tempdir");
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .write_denylist(
                    crate::WriteDenylist::persistence()
                        .home(home.path())
                        .except(clones.path()),
                )
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();
        let clones = std::fs::canonicalize(clones.path()).unwrap();

        assert!(profile.contains(&format!(
            "(deny file-write* (require-all (regex #\"/\\.git/hooks(/|$)\") (require-not (subpath \"{}\")))",
            clones.display()
        )));
        assert!(
            !profile.contains(&format!("(subpath \"{}\") (with message", clones.display())),
            "an exemption must not turn into a rule of its own"
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
