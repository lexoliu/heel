//! SBPL profile generation using compile-time templates.

use std::path::{Path, PathBuf};

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
    /// The path as the caller resolved it, verified and never followed.
    resolved: PathBuf,
    filter: PathFilter,
    writable: bool,
    executable: bool,
}

/// A path the profile allows, as the protections have to see it.
struct Opening {
    filter: PathFilter,
    /// The path as the caller resolved it.
    path: PathBuf,
    /// The path escaped for an SBPL string.
    escaped: String,
    /// Whether the opening also permits writing; a read-only grant does not
    /// reopen a protected location to changes.
    writable: bool,
}

/// Every path the profile allows, which is what the protections may not
/// swallow when a path names the thing they protect.
struct Openings {
    granted: Vec<Opening>,
    /// The directories above the granted paths, allowed as literals so that
    /// resolving into a granted path works.
    ancestors: Vec<Opening>,
}

impl Openings {
    fn new(granted: Vec<Opening>) -> Result<Self> {
        let mut paths: Vec<PathBuf> = granted
            .iter()
            .flat_map(|opening| {
                opening
                    .path
                    .ancestors()
                    .skip(1)
                    .filter(|ancestor| !ancestor.as_os_str().is_empty())
                    .map(Path::to_path_buf)
                    .collect::<Vec<_>>()
            })
            .collect();
        paths.sort_unstable();
        paths.dedup();
        let ancestors = paths
            .into_iter()
            .map(|path| {
                Ok(Opening {
                    filter: PathFilter::Literal,
                    escaped: escape_path(&path)?,
                    path,
                    writable: false,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self { granted, ancestors })
    }

    /// The `require-not` clauses that leave a protection of `names` open where
    /// a granted path is, or lies inside, a protected location, and the
    /// directories on the way to it.
    ///
    /// A grant of a directory that only contains a protected location is not
    /// among them.
    fn opened_by_name(&self, names: impl Fn(&Path) -> bool) -> Vec<String> {
        self.granted
            .iter()
            .chain(&self.ancestors)
            .filter(|opening| names(&opening.path))
            .map(Opening::exemption)
            .collect()
    }

    /// The same clauses for the writable granted paths alone, which is what
    /// leaves a protected location open to being changed: a grant that only
    /// reads the location does not reopen it, and the directories on the way to
    /// a grant are only walked through.
    fn opened_by_grant(&self, names: impl Fn(&Path) -> bool) -> Vec<String> {
        self.granted
            .iter()
            .filter(|opening| opening.writable && names(&opening.path))
            .map(Opening::exemption)
            .collect()
    }

    /// The directories on the way to a grant inside a protected location. They
    /// can be walked through and not listed, so a grant of `.ssh/keys` does not
    /// show the other names in `.ssh`.
    fn walked_through(&self, names: impl Fn(&Path) -> bool) -> Vec<String> {
        self.ancestors
            .iter()
            .filter(|ancestor| {
                names(&ancestor.path)
                    && !self
                        .granted
                        .iter()
                        .any(|opening| ancestor.path.starts_with(&opening.path))
            })
            .map(|ancestor| ancestor.escaped.clone())
            .collect()
    }
}

impl Opening {
    /// The clause that leaves this path out of a rule.
    fn exemption(&self) -> String {
        format!("(require-not ({} \"{}\"))", self.filter, self.escaped)
    }
}

/// `filter` without the places `exemptions` name.
fn excluding(filter: String, exemptions: &[String]) -> String {
    if exemptions.is_empty() {
        filter
    } else {
        format!("(require-all {filter} {})", exemptions.join(" "))
    }
}

/// The denials of one protected location, as the template sees them.
struct ProtectedRule {
    /// What is not readable: the location and everything in it, less the
    /// granted paths that name it or lie inside it, and the ways to them.
    reads: String,
    /// What is not created, changed, replaced, linked or removed: the location
    /// under the configured home, less the granted paths alone. A name planted
    /// in the location, or the location moved out of its name, would be
    /// readable under another one.
    changes: String,
    /// The directories on the way to a grant inside the location, whose entries
    /// are not listed.
    listings: Vec<String>,
}

impl ProtectedRule {
    /// The rule for one protected location: a real path and everything beneath
    /// it, less the openings that name it or lie inside it.
    ///
    /// A security toggle protects only the location under the configured home —
    /// `~/.ssh`, not every `.ssh` the sandbox meets — and an embedder's deny
    /// list protects the trees it names, so the same denial serves both. Reads
    /// are denied less the granted paths that name the location or lie inside
    /// it and the ways to them; changes are denied less the writable granted
    /// paths alone, since a name planted in the location, or the location moved
    /// out of its name, would be readable under another one.
    fn for_tree(tree: &Path, escaped: &str, openings: &Openings) -> Self {
        let names = |path: &Path| path.starts_with(tree);
        let location = format!("(subpath \"{escaped}\")");
        Self {
            reads: excluding(location.clone(), &openings.opened_by_name(names)),
            changes: excluding(location, &openings.opened_by_grant(names)),
            listings: openings.walked_through(names),
        }
    }
}

/// Every directory above `paths` up to the root, escaped for an SBPL literal.
///
/// A protected path's rule names the path itself, so it is only as strong as
/// the names above it: renaming any ancestor puts the denied location under a
/// name the rules do not cover. Each is therefore refused as a rename or delete
/// source and as a create destination — a prepared tree moved into a guarded
/// name is a create SBPL cannot tell from a plain `mkdir`.
fn ancestors(paths: &[PathBuf]) -> Result<Vec<String>> {
    let mut all: Vec<PathBuf> = paths
        .iter()
        .flat_map(|path| {
            path.ancestors()
                .skip(1)
                .take_while(|ancestor| ancestor.parent().is_some())
                .map(Path::to_path_buf)
                .collect::<Vec<_>>()
        })
        .collect();
    all.sort_unstable();
    all.dedup();
    all.iter().map(|path| escape_path(path)).collect()
}

/// A host protection policy as the template sees it: every path already
/// resolved and escaped, every filter already written.
struct HostRules {
    /// The escaped path of each tree, which is a path and everything beneath it.
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
            .collect::<Result<Vec<_>>>()?;
        let guard = |pattern: &Pattern, filter: String| {
            if pattern.is_anywhere() {
                excluding(filter, &exemptions)
            } else {
                filter
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
            guarded_parents: ancestors(&resolved.trees)?,
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
    protected: Vec<ProtectedRule>,
    /// The ancestors of the protected locations, guarded against renames and
    /// prepared trees moved into their names.
    guarded: Vec<String>,
    read_rules: Option<HostRules>,
    write_rules: Option<HostRules>,
}

/// Generate an SBPL profile from a sandbox configuration.
///
/// `proxy_port` is `Some` only when the network policy permits traffic; when it
/// is `None` the profile denies all outbound connections in the kernel.
pub fn generate_profile(config: &SandboxConfigData, proxy_port: Option<u16>) -> Result<String> {
    let security = config.security();
    let grants = grant_rules(config.grants())?;
    let openings = openings(config, &grants)?;

    let read_resolved = config
        .read_denylist()
        .map(|denylist| denylist.resolve())
        .transpose()?;
    let write_resolved = config
        .write_denylist()
        .map(|denylist| denylist.resolve())
        .transpose()?;

    // The planting and move rules anchor at the configured home: the read
    // denylist's when it names one, the write denylist's otherwise, and the
    // invoking user's home when neither says. It is resolved only when a
    // toggle protects a location, so a home-less environment fails only the
    // configurations that needed it.
    let mut anchored = Vec::new();
    let mut protected = Vec::new();
    if security.protected_locations().next().is_some() {
        let home = crate::policy::resolved_home(
            config
                .read_denylist()
                .and_then(|denylist| denylist.configured_home())
                .or_else(|| {
                    config
                        .write_denylist()
                        .and_then(|denylist| denylist.configured_home())
                }),
        )?;
        for location in security.protected_locations() {
            let path = crate::policy::resolve_lenient(&home.join(location))?;
            protected.push(ProtectedRule::for_tree(
                &path,
                &escape_path(&path)?,
                &openings,
            ));
            anchored.push(path);
        }
    }
    if let Some(resolved) = &read_resolved {
        for tree in &resolved.trees {
            protected.push(ProtectedRule::for_tree(
                tree,
                &escape_path(tree)?,
                &openings,
            ));
        }
        anchored.extend(resolved.trees.iter().cloned());
    }
    let guarded = ancestors(&anchored)?;

    let read_rules = read_resolved.as_ref().map(HostRules::new).transpose()?;

    let template = SandboxProfile {
        grants,
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
        protected,
        guarded,
        read_rules,
        write_rules: write_resolved.as_ref().map(HostRules::new).transpose()?,
        traversal_paths: openings
            .ancestors
            .iter()
            .map(|ancestor| ancestor.escaped.clone())
            .collect(),
    };

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

/// Every path the profile allows: the configured grants, and the directories
/// the sandbox itself needs.
///
/// A protection rule that covers an ancestor of a granted path makes that path
/// unreachable even though the path itself is allowed: the kernel refuses to
/// resolve through the denied component, so `chdir` into an allowed directory
/// fails. [`Openings`] therefore also carries the ancestors, which the profile
/// re-allows as literals, leaving their other children denied.
fn openings(config: &SandboxConfigData, grants: &[GrantRules]) -> Result<Openings> {
    let subpath = |path: &Path, writable: bool| -> Result<Opening> {
        unresolved::verify(path)?;
        Ok(Opening {
            filter: PathFilter::Subpath,
            escaped: escape_path(path)?,
            path: path.to_path_buf(),
            writable,
        })
    };

    let mut granted: Vec<Opening> = grants
        .iter()
        .map(|grant| Opening {
            filter: grant.filter,
            path: grant.resolved.clone(),
            escaped: grant.path.clone(),
            writable: grant.writable,
        })
        .collect();
    granted.push(subpath(config.working_dir(), true)?);
    for path in config
        .ipc_bin_dir()
        .into_iter()
        .chain(config.ipc_socket().and_then(Path::parent))
    {
        granted.push(subpath(path, true)?);
    }
    if let Some(python) = config.python() {
        granted.push(subpath(python.venv().path(), python.allow_pip_install())?);
    }
    Openings::new(granted)
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
                resolved: grant.path().to_path_buf(),
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

    use crate::platform::unresolved::resolved as grant_path;

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
                .writable(grant_path(resolved(&scratch)))
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
                .executable(grant_path(resolved(&tools)))
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

        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .executable(grant_path(&binary))
                .build(),
        );
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
                .grant(grant_path(resolved(&cache)), Access::WRITE | Access::EXEC)
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

        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .executable(grant_path(&tools))
                .build(),
        );
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
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(grant_path(resolved(&cache)))
                .build(),
        );
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

        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable(grant_path(&scratch))
                .build(),
        );
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
    fn an_unresolved_grant_is_refused_before_it_can_be_configured() {
        // /tmp is a symlink to /private/tmp on macOS. Resolving it here would
        // let a swapped link redirect a grant, so the caller resolves it.
        let error = crate::resolve::ResolvedPath::new("/tmp").unwrap_err();
        assert!(
            matches!(&error, Error::GrantRedirected { path, .. } if path == Path::new("/tmp")),
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
                .writable(grant_path(&granted))
                .writable(grant_path(&nested))
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
                matches!(&error, Error::GrantRedirected { path, .. } if path == replaced),
                "expected {} to be named, got {error:?}",
                replaced.display()
            );
        }
    }

    #[test]
    fn a_missing_path_cannot_be_a_grant() {
        let error = crate::resolve::ResolvedPath::new("/definitely/not/a/real/path").unwrap_err();
        assert!(
            matches!(error, Error::Path { .. }),
            "expected a path error, got {error:?}"
        );
    }

    #[test]
    fn a_grant_removed_since_it_was_configured_is_rejected() {
        let root = tempfile::tempdir().expect("tempdir");
        let granted = resolved(&root).join("granted");
        std::fs::create_dir(&granted).expect("creates");
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable(grant_path(&granted))
                .build(),
        );
        std::fs::remove_dir(&granted).expect("removes");

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
                        .persistent_grant(crate::grant::Grant::new(
                            grant_path(&directory_path),
                            Access::READ,
                        )),
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
                .writable(grant_path(resolved(&dir)))
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
    fn a_credential_rule_is_narrowed_only_by_a_grant_that_names_the_credential() {
        let home = tempfile::tempdir().expect("tempdir");
        let ssh = std::fs::canonicalize(home.path()).unwrap().join(".ssh");
        std::fs::create_dir(&ssh).expect("creates");
        let root = std::fs::canonicalize(home.path()).unwrap();

        let (enclosing, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable(grant_path(root.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&enclosing, None).unwrap();
        assert!(
            profile.contains(&format!(
                r#"(deny file-read* (subpath "{0}") (with message"#,
                ssh.display()
            )),
            "a grant of the enclosing directory must not narrow the rule:\n{profile}"
        );

        let (named, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable(grant_path(ssh.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&named, None).unwrap();
        assert!(
            profile.contains(&format!(
                r#"(deny file-read* (require-all (subpath "{0}") (require-not (subpath "{0}")))"#,
                ssh.display()
            )),
            "the grant naming the store must be left out of its rule:\n{profile}"
        );
    }

    #[test]
    fn a_protected_location_cannot_be_planted_linked_or_moved_unless_a_grant_names_it() {
        let home = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let ssh = root.join(".ssh");
        std::fs::create_dir(&ssh).expect("creates");

        // The denylist points the configured home at the stand-in, which is
        // where the planting and move rules apply.
        let (enclosing, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(grant_path(root.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&enclosing, None).unwrap();
        // Reads and changes are denied at the location under the configured
        // home; the enclosing grant narrows neither.
        assert!(
            profile.contains(&format!(
                r#"(deny file-read* (subpath "{}/.ssh") (with message"#,
                root.display()
            )),
            "a grant of the enclosing directory must not reopen reads:\n{profile}"
        );
        assert!(
            profile.contains(&format!(
                r#"(deny file-write* (subpath "{}/.ssh") (with message"#,
                root.display()
            )),
            "the location under the configured home is not writable:\n{profile}"
        );
        // The directories that lead to a multi-component location are not moved,
        // removed or created, and neither is home itself.
        for parent in [root.join(".cargo"), root.clone()] {
            for operation in ["file-write-unlink", "file-write-create"] {
                assert!(
                    profile.contains(&format!(
                        r#"(deny {operation} (literal "{}") (with message"#,
                        parent.display()
                    )),
                    "{operation} on {} is not refused:\n{profile}",
                    parent.display()
                );
            }
        }

        let (named, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(grant_path(root.clone()))
                .writable(grant_path(ssh.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&named, None).unwrap();
        assert!(
            profile.contains(&format!(
                r#"(deny file-write* (require-all (subpath "{0}") (require-not (subpath "{0}")))"#,
                ssh.display()
            )),
            "the grant naming the store must be left out of the write rule:\n{profile}"
        );
    }

    #[test]
    fn a_grant_inside_a_store_walks_through_the_store_without_listing_it() {
        let home = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let keys = root.join(".ssh/keys");
        std::fs::create_dir_all(&keys).expect("creates");

        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .readable(grant_path(keys.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();
        let listing = format!(
            "(deny file-read-data (literal \"{}\") (with message",
            root.join(".ssh").display()
        );
        assert!(profile.contains(&listing), "{profile}");
        assert!(
            !profile.contains(&format!(
                "(deny file-read-data (literal \"{}\")",
                root.display()
            )),
            "the directories above the store are listed as before"
        );
        // Neither the grant nor a path under it loses its listing.
        assert!(!profile.contains(&format!(
            "(deny file-read-data (literal \"{}\")",
            keys.display()
        )));
    }

    #[test]
    fn a_denylist_tree_is_protected_from_planting_like_a_toggle_location() {
        let home = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(grant_path(root.clone()))
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();
        assert!(
            profile.contains(&format!(
                "(deny file-write* (subpath \"{}/.netrc\") (with message",
                root.display()
            )),
            "file-write*:\n{profile}"
        );
        // Every directory above the tree, home included, is guarded against
        // renames and creates.
        for parent in [root.clone(), root.parent().unwrap().to_path_buf()] {
            assert!(
                profile.contains(&format!(
                    r#"(deny file-write-unlink (literal "{}") (with message"#,
                    parent.display()
                )),
                "an ancestor of the tree is not guarded:\n{profile}"
            );
        }
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
    fn a_read_only_venv_does_not_narrow_a_change_denial() {
        let home = tempfile::tempdir().expect("tempdir");
        let root = std::fs::canonicalize(home.path()).unwrap();
        let venv = root.join(".ssh/venv");
        std::fs::create_dir_all(&venv).unwrap();
        let (data, _dir) = prepared_config(
            SandboxConfig::builder()
                .writable(grant_path(root.clone()))
                .python(
                    crate::PythonConfig::builder()
                        .venv(crate::config::VenvConfig::builder().path(&venv).build())
                        .build(),
                )
                .read_denylist(crate::ReadDenylist::credentials().home(&root))
                .build(),
        );
        let profile = generate_profile(&data, None).unwrap();
        let changes = profile
            .lines()
            .find(|line| line.contains("file-write*") && line.contains(".ssh"))
            .expect("the .ssh change denial");
        assert!(
            !changes.contains("require-not"),
            "a read-only venv must not exempt the store: {changes}"
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
