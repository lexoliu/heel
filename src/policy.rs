//! Host protection policies: what a sandbox must never read or write.
//!
//! A grant list says what a sandbox *may* touch. These two policies say what it
//! *may not*, whatever else is granted, and they exist for sandboxes that leave
//! the rest of the machine open: a toolchain that has to read `~/.rustup`, a
//! Homebrew prefix or sources anywhere on disk cannot be given an allowlist, but
//! it must not be able to read the credentials the user keeps next to them, nor
//! plant something the user runs later.
//!
//! - [`ReadDenylist`]: credential stores and keys. Everything outside it keeps
//!   whatever readability the rest of the configuration gives.
//! - [`WriteDenylist`]: persistence locations, the places where a write turns
//!   into code that runs outside the sandbox later.
//!
//! Both tables are fixed in code. An embedder can add paths to a policy, never
//! remove one: a policy that could be narrowed from configuration would be a
//! setting rather than a boundary. Both are enforced after every grant, so a
//! grant of a directory that contains a denied location does not reopen it. On
//! macOS a grant that names a credential store, or a path inside one, opens
//! what it names, because the embedder that wrote it asked for exactly that —
//! and only a writable grant opens it to changes; Linux keeps every denied
//! location denied, grant or not. Persistence locations are never reopened on
//! either platform.
//!
//! The macOS and Linux backends enforce them. A sandbox configured with either
//! policy on a platform whose backend cannot (Windows) fails when it is
//! constructed, rather than running with a weaker boundary than the one that was
//! asked for.
use std::path::PathBuf;

#[cfg(any(target_os = "macos", target_os = "linux"))]
mod resolve;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub(crate) use resolve::{Pattern, Resolved};
#[cfg(target_os = "macos")]
pub(crate) use resolve::{resolve_lenient, resolved_home};

/// Paths a sandbox must not read: credential stores and keys.
///
/// Built with [`ReadDenylist::credentials`], which names the fixed table, and
/// extended with [`ReadDenylist::deny`] for the embedder's own secrets. Pass it
/// to [`SandboxConfigBuilder::read_denylist`](crate::SandboxConfigBuilder::read_denylist).
///
/// A grant of a directory that contains a denied path leaves it denied. A grant
/// naming the denied path itself, or a path inside it, opens that path and what
/// is beneath it, and nothing else of the store.
///
/// A denied read fails with `EPERM` (macOS) or `EACCES` (Linux) against the path
/// it was made on, which every ordinary tool reports by name. On macOS the keychain is also closed at the
/// security services, so a sandboxed process cannot read keychain items through
/// the system API, while certificate trust evaluation, which goes through
/// `trustd`, keeps working and HTTPS from sandboxed tools is unaffected.
///
/// The table, relative to the user's home unless absolute: `.ssh`, `.gnupg`,
/// `.config/gh`, `.cargo/credentials{,.toml}`, `.npmrc`, `.pypirc`, `.netrc`,
/// `.git-credentials`, `.docker/config.json`, `.aws`, `.azure`, `.config/gcloud`,
/// `.kube`, the browser profiles, `Library/Keychains` and `/Library/Keychains`,
/// and the sockets named by `SSH_AUTH_SOCK`, `GNUPGHOME` and launchd's agent
/// listener. The complete list is in `src/policy.rs`.
#[derive(Debug, Clone)]
pub struct ReadDenylist {
    extra: Vec<PathBuf>,
    sockets: Vec<PathBuf>,
    home: Option<PathBuf>,
}

impl ReadDenylist {
    /// The fixed credential table, with nothing added.
    pub fn credentials() -> Self {
        Self {
            extra: Vec::new(),
            sockets: Vec::new(),
            home: None,
        }
    }

    /// Resolve the table's home-relative entries against `home` instead of the
    /// invoking user's home directory.
    ///
    /// For a sandbox that runs as a different home than the process building it,
    /// and for tests, which must not point a policy at the real credentials.
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Also deny connecting to the unix socket at `path`, and reading it.
    ///
    /// The sockets of the running ssh-agent and gpg-agent are already denied
    /// where the environment names them; this is for an agent the embedder
    /// knows about and the environment does not.
    pub fn socket(mut self, path: impl Into<PathBuf>) -> Self {
        self.sockets.push(path.into());
        self
    }

    /// Also deny reads of `path` and everything beneath it.
    ///
    /// The path must be absolute; a relative one is refused when the sandbox is
    /// created, because it would name a different place in every process.
    pub fn deny(mut self, path: impl Into<PathBuf>) -> Self {
        self.extra.push(path.into());
        self
    }

    /// The paths added beyond the fixed table.
    pub fn extra(&self) -> &[PathBuf] {
        &self.extra
    }

    /// The home the table resolves against, when the embedder set one.
    #[cfg(target_os = "macos")]
    pub(crate) fn configured_home(&self) -> Option<&std::path::Path> {
        self.home.as_deref()
    }
}

/// Paths a sandbox must not write: places where a write persists as code that
/// runs outside the sandbox later.
///
/// Built with [`WriteDenylist::persistence`] and extended with
/// [`WriteDenylist::deny`]. Pass it to
/// [`SandboxConfigBuilder::write_denylist`](crate::SandboxConfigBuilder::write_denylist).
///
/// The denial covers creating, changing, renaming and removing, and every
/// directory above a denied location, home and above included, cannot be
/// renamed away and replaced with a lookalike either. Everything else keeps the
/// writability the
/// grants and [`SandboxConfigBuilder::writable_file_system`](crate::SandboxConfigBuilder::writable_file_system)
/// give it.
///
/// The table, relative to the user's home unless absolute: the shell startup
/// files of zsh, bash, csh, ksh, fish and nushell, `.ssh`, the global git
/// configuration, `.cargo/bin`, `.local/bin`, cargo's `config.toml`,
/// `Library/LaunchAgents`, `Library/LaunchDaemons`,
/// `Library/StartupItems`, `/Library/Launch{Agents,Daemons}`, the systemd and
/// autostart directories, `.git/hooks` and `.git/config` of any repository and
/// the `hooks` and `config` of its submodules, the credential stores of the read
/// table, the editor, debugger and REPL startup files, the user-writable
/// directories on `PATH`, `RUSTUP_HOME`, and the user's Python `site-packages`.
/// The complete list is in `src/policy.rs`.
#[derive(Debug, Clone)]
pub struct WriteDenylist {
    extra: Vec<PathBuf>,
    exempt: Vec<PathBuf>,
    home: Option<PathBuf>,
    rustup_home: Option<PathBuf>,
}

impl WriteDenylist {
    /// The fixed persistence table, with nothing added.
    pub fn persistence() -> Self {
        Self {
            extra: Vec::new(),
            exempt: Vec::new(),
            home: None,
            rustup_home: None,
        }
    }

    /// Resolve the table's home-relative entries against `home` instead of the
    /// invoking user's home directory.
    pub fn home(mut self, home: impl Into<PathBuf>) -> Self {
        self.home = Some(home.into());
        self
    }

    /// Protect `path` as the rustup home, instead of `RUSTUP_HOME` or
    /// `<home>/.rustup`.
    ///
    /// The path must be absolute.
    pub fn rustup_home(mut self, path: impl Into<PathBuf>) -> Self {
        self.rustup_home = Some(path.into());
        self
    }

    /// Also deny writes to `path` and everything beneath it.
    ///
    /// The path must be absolute.
    pub fn deny(mut self, path: impl Into<PathBuf>) -> Self {
        self.extra.push(path.into());
        self
    }

    /// Leave the `.git/hooks` rule off for repositories beneath `path`.
    ///
    /// This is for a tool's private clones, such as cargo's git cache, whose
    /// hooks no user ever runs and which the tool creates and removes itself.
    /// It narrows only the any-repository `.git/hooks` entry of the table, never
    /// a location named by home or by absolute path, and it is not itself a
    /// grant.
    pub fn except(mut self, path: impl Into<PathBuf>) -> Self {
        self.exempt.push(path.into());
        self
    }

    /// The paths added beyond the fixed table.
    pub fn extra(&self) -> &[PathBuf] {
        &self.extra
    }

    /// The directories the `.git/hooks` rule leaves alone.
    pub fn exempt(&self) -> &[PathBuf] {
        &self.exempt
    }

    /// The home the table resolves against, when the embedder set one.
    #[cfg(target_os = "macos")]
    pub(crate) fn configured_home(&self) -> Option<&std::path::Path> {
        self.home.as_deref()
    }
}
