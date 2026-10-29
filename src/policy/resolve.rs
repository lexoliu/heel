//! Resolution of the host protection tables against the host: the fixed
//! tables, the patterns they use and the resolved form the macOS and Linux
//! backends enforce.

use std::path::{Path, PathBuf};

use super::{ReadDenylist, WriteDenylist};
use crate::error::{Error, Result};

/// Where a table entry lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Location {
    /// Relative to the user's home directory.
    Home(&'static str),
    /// An absolute path.
    Absolute(&'static str),
    /// A relative path found beneath any directory, such as a repository's
    /// `.git/hooks`. A `*` inside a name matches any run of characters within
    /// that name and a name of `**` matches any number of directories.
    Anywhere(&'static str),
    /// A pattern anchored at the home directory, with the same wildcards as
    /// [`Location::Anywhere`], for entries whose name varies and may not exist
    /// yet, such as `.local/lib/python*/site-packages`.
    HomePattern(&'static str),
}

/// Credential stores and keys, relative to the user's home directory.
///
/// Registry and forge tokens, SSH and GPG keys with their agents' sockets, cloud
/// provider configuration, package-manager and git credential files, the GitHub
/// CLI configuration, browser profiles and the keychains.
pub(crate) const CREDENTIALS: &[Location] = &[
    // Keys and agents.
    Location::Home(".ssh"),
    Location::Home(".gnupg"),
    // Forge and registry tokens.
    Location::Home(".config/gh"),
    Location::Home(".config/glab-cli"),
    Location::Home(".config/hub"),
    Location::Home(".cargo/credentials.toml"),
    Location::Home(".cargo/credentials"),
    Location::Home(".npmrc"),
    Location::Home(".yarnrc.yml"),
    Location::Home(".pypirc"),
    Location::Home(".gem/credentials"),
    Location::Home(".m2/settings.xml"),
    Location::Home(".netrc"),
    Location::Home("_netrc"),
    Location::Home(".git-credentials"),
    Location::Home(".config/git/credentials"),
    Location::Home(".docker/config.json"),
    Location::Home(".terraform.d/credentials.tfrc.json"),
    Location::Home(".vault-token"),
    Location::Home(".password-store"),
    Location::Home(".config/op"),
    // Cloud providers.
    Location::Home(".aws"),
    Location::Home(".azure"),
    Location::Home(".config/gcloud"),
    Location::Home(".gcloud"),
    Location::Home(".kube"),
    Location::Home(".oci"),
    Location::Home(".config/doctl"),
    Location::Home(".config/heroku"),
    Location::Home(".fly"),
    Location::Home(".config/.wrangler"),
    // Browser profiles: cookies, sessions and saved passwords.
    Location::Home("Library/Application Support/Google/Chrome"),
    Location::Home("Library/Application Support/Chromium"),
    Location::Home("Library/Application Support/Firefox"),
    Location::Home("Library/Application Support/Microsoft Edge"),
    Location::Home("Library/Application Support/BraveSoftware"),
    Location::Home("Library/Application Support/Arc"),
    Location::Home("Library/Safari"),
    Location::Home("Library/Cookies"),
    Location::Home(".mozilla"),
    Location::Home(".config/google-chrome"),
    Location::Home(".config/chromium"),
    Location::Home(".config/BraveSoftware"),
    Location::Home(".config/microsoft-edge"),
    Location::Home(".var/app/org.mozilla.firefox"),
    Location::Home(".var/app/com.google.Chrome"),
    Location::Home(".var/app/org.chromium.Chromium"),
    Location::Home(".var/app/com.brave.Browser"),
    Location::Home("snap/firefox/common/.mozilla"),
    Location::Home("snap/chromium/common/chromium"),
    // Keychains.
    Location::Home("Library/Keychains"),
    Location::Home(".local/share/keyrings"),
    Location::Home(".local/share/kwalletd"),
    Location::Absolute("/Library/Keychains"),
    // Agent sockets that live at a fixed place rather than in an environment
    // variable: 1Password's SSH agent.
    Location::Home("Library/Group Containers/2BUA8C4S2C.com.1password"),
];

/// Persistence locations: writing here changes what runs outside the sandbox.
///
/// Shell startup files run at the next login shell, `~/.cargo/bin` and
/// `~/.local/bin` sit on `PATH`, a repository's `.git/hooks` run at its next
/// commit, and user service and agent directories start programs by themselves.
/// Cargo's own configuration can name a `rustc` wrapper that runs at the next
/// build.
pub(crate) const PERSISTENCE: &[Location] = &[
    // Shell startup files.
    Location::Home(".zshenv"),
    Location::Home(".zprofile"),
    Location::Home(".zshrc"),
    Location::Home(".zlogin"),
    Location::Home(".zlogout"),
    Location::Home(".bash_profile"),
    Location::Home(".bash_login"),
    Location::Home(".bashrc"),
    Location::Home(".bash_logout"),
    Location::Home(".profile"),
    Location::Home(".cshrc"),
    Location::Home(".tcshrc"),
    Location::Home(".kshrc"),
    Location::Home(".bash_aliases"),
    Location::Home(".xprofile"),
    Location::Home(".xsessionrc"),
    Location::Home(".xinitrc"),
    Location::Home(".pam_environment"),
    Location::Home(".config/fish"),
    Location::Home(".config/nushell"),
    // Editor, multiplexer, debugger and REPL startup files, which run whatever
    // they name the next time the program starts.
    Location::Home(".vimrc"),
    Location::Home(".config/nvim"),
    Location::Home(".tmux.conf"),
    Location::Home(".config/tmux"),
    Location::Home(".gdbinit"),
    Location::Home(".config/gdb"),
    Location::Home(".lldbinit"),
    Location::Home(".irbrc"),
    Location::Home(".pryrc"),
    Location::Home(".psqlrc"),
    Location::Home(".Rprofile"),
    Location::Home(".pythonrc"),
    Location::Home(".inputrc"),
    Location::Home(".emacs"),
    Location::Home(".emacs.d/init.el"),
    // Keys that authorize a login, and the client configuration that can name a
    // command to run for every connection.
    Location::Home(".ssh"),
    // Global git configuration can name a hook directory, a filesystem monitor
    // and aliases, all of which run at the next git command.
    Location::Home(".gitconfig"),
    Location::Home(".config/git"),
    // Directories on PATH.
    Location::Home(".cargo/bin"),
    Location::Home(".local/bin"),
    // Python runs `usercustomize` and every `.pth` file in the user site
    // directory at the start of every interpreter.
    Location::HomePattern(".local/lib/python*/site-packages"),
    // Cargo configuration, whose `build.rustc-wrapper` runs at the next build.
    Location::Home(".cargo/config.toml"),
    Location::Home(".cargo/config"),
    // User service and agent directories.
    Location::Home("Library/LaunchAgents"),
    Location::Home("Library/LaunchDaemons"),
    Location::Home("Library/StartupItems"),
    Location::Home(".config/systemd"),
    Location::Home(".config/autostart"),
    Location::Home(".config/environment.d"),
    Location::Home(".local/share/systemd"),
    Location::Home(".local/share/dbus-1/services"),
    Location::Home(".local/share/applications"),
    Location::Home(".config/mimeapps.list"),
    Location::Home(".config/plasma-workspace/env"),
    Location::Home(".config/autostart-scripts"),
    Location::Home(".kde/env"),
    Location::Home(".kde/Autostart"),
    Location::Absolute("/Library/LaunchAgents"),
    Location::Absolute("/Library/LaunchDaemons"),
    Location::Absolute("/Library/StartupItems"),
    // Any repository's hooks, and the configuration that can name a hook
    // directory, a filesystem monitor or an alias, including those of
    // submodules.
    Location::Anywhere(".git/hooks"),
    Location::Anywhere(".git/config"),
    Location::Anywhere(".git/modules/**/hooks"),
    Location::Anywhere(".git/modules/**/config"),
];

/// Unix sockets that give their client control of the user's session or of
/// containers, relative to the home directory unless absolute.
pub(crate) const SOCKETS: &[Location] = &[
    Location::Home(".docker/run/docker.sock"),
    Location::Home(".local/share/containers/podman/machine/podman.sock"),
    Location::Absolute("/var/run/docker.sock"),
    Location::Absolute("/run/docker.sock"),
    Location::Absolute("/run/podman/podman.sock"),
];

/// Environment variables whose value is the path of a socket to deny.
pub(crate) const SOCKET_ENV: &[&str] = &["SSH_AUTH_SOCK", "DOCKER_HOST", "CONTAINER_HOST"];

/// The environment variable naming the per-user runtime directory, which holds
/// the session bus, the pipewire and wayland sockets and the container runtimes'
/// sockets.
pub(crate) const RUNTIME_DIR_ENV: &str = "XDG_RUNTIME_DIR";

/// The environment variable naming where Rust toolchains are installed.
pub(crate) const RUSTUP_HOME_ENV: &str = "RUSTUP_HOME";

/// One name of a [`Pattern`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Exactly this name.
    Name(String),
    /// A name with `*` wildcards inside it.
    Glob(String),
    /// Any number of directories, including none.
    Any,
}

impl Segment {
    fn parse(text: &str) -> Self {
        if text == "**" {
            Self::Any
        } else if text.contains('*') {
            Self::Glob(text.to_owned())
        } else {
            Self::Name(text.to_owned())
        }
    }

    #[cfg(target_os = "linux")]
    fn accepts(&self, name: &[u8]) -> bool {
        match self {
            Self::Name(expected) => expected.as_bytes() == name,
            Self::Glob(glob) => glob_matches(glob.as_bytes(), name),
            Self::Any => true,
        }
    }
}

/// Whether `text` matches `glob`, in which `*` stands for any run of bytes.
#[cfg(target_os = "linux")]
fn glob_matches(glob: &[u8], text: &[u8]) -> bool {
    let (mut g, mut t) = (0, 0);
    let mut resume: Option<(usize, usize)> = None;
    while t < text.len() {
        if g < glob.len() && glob[g] == b'*' {
            resume = Some((g, t));
            g += 1;
        } else if g < glob.len() && glob[g] == text[t] {
            g += 1;
            t += 1;
        } else if let Some((star, matched)) = resume {
            g = star + 1;
            t = matched + 1;
            resume = Some((star, matched + 1));
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|&byte| byte == b'*')
}

/// A relative path with wildcards, either found beneath any directory or
/// anchored at one: the form of a table entry whose place or name varies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Pattern {
    anchor: Option<PathBuf>,
    segments: Vec<Segment>,
}

impl Pattern {
    /// A pattern that may start in any directory.
    pub(crate) fn anywhere(spec: &str) -> Self {
        Self {
            anchor: None,
            segments: spec.split('/').map(Segment::parse).collect(),
        }
    }

    /// A pattern that starts at `anchor`.
    pub(crate) fn at(anchor: PathBuf, spec: &str) -> Self {
        Self {
            anchor: Some(anchor),
            segments: spec.split('/').map(Segment::parse).collect(),
        }
    }

    /// Whether the pattern may start in any directory, which is also what an
    /// exemption can narrow.
    pub(crate) fn is_anywhere(&self) -> bool {
        self.anchor.is_none()
    }

    /// The patterns naming the directories that hold a match: the ones that must
    /// not be moved away or removed, or the match could be swapped for a copy.
    ///
    /// A directory of any depth stands for the one directly beneath the last
    /// fixed name, so a submodule's git directory is held but the objects inside
    /// it are not.
    pub(crate) fn guarded_parents(&self) -> Vec<Self> {
        let mut parents: Vec<Self> = Vec::new();
        for length in 1..self.segments.len() {
            let mut segments = self.segments[..length].to_vec();
            if segments.last() == Some(&Segment::Any) {
                segments.pop();
                segments.push(Segment::Glob("*".into()));
            }
            let parent = Self {
                anchor: self.anchor.clone(),
                segments,
            };
            if !parents.contains(&parent) {
                parents.push(parent);
            }
        }
        parents
    }

    /// The pattern as an SBPL regex over absolute paths.
    ///
    /// With `tree` it also matches everything beneath a match; without, only the
    /// match itself.
    #[cfg(target_os = "macos")]
    pub(crate) fn regex(&self, tree: bool) -> String {
        fn escape(text: &str, regex: &mut String) {
            for c in text.chars() {
                if matches!(
                    c,
                    '.' | '+' | '?' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '^' | '$' | '\\'
                ) {
                    regex.push('\\');
                }
                regex.push(c);
            }
        }
        let mut regex = String::new();
        if let Some(anchor) = &self.anchor {
            regex.push('^');
            escape(&anchor.to_string_lossy(), &mut regex);
        }
        for segment in &self.segments {
            match segment {
                Segment::Name(name) => {
                    regex.push('/');
                    escape(name, &mut regex);
                }
                Segment::Glob(glob) => {
                    regex.push('/');
                    for (index, part) in glob.split('*').enumerate() {
                        if index > 0 {
                            regex.push_str("[^/]*");
                        }
                        escape(part, &mut regex);
                    }
                }
                Segment::Any => regex.push_str("(/[^/]+)*"),
            }
        }
        regex.push_str(if tree { "(/|$)" } else { "$" });
        regex
    }

    /// Whether `path` is a match or lies beneath one.
    #[cfg(target_os = "linux")]
    pub(crate) fn matches(&self, path: &Path) -> bool {
        self.matches_with(path, true)
    }

    /// Whether `path` is exactly a match.
    #[cfg(target_os = "linux")]
    pub(crate) fn matches_exactly(&self, path: &Path) -> bool {
        self.matches_with(path, false)
    }

    #[cfg(target_os = "linux")]
    fn matches_with(&self, path: &Path, tree: bool) -> bool {
        let relative = match &self.anchor {
            Some(anchor) => match path.strip_prefix(anchor) {
                Ok(relative) => relative,
                Err(_) => return false,
            },
            None => path,
        };
        let names: Vec<&[u8]> = relative
            .components()
            .filter_map(|component| match component {
                std::path::Component::Normal(name) => Some(name.as_encoded_bytes()),
                _ => None,
            })
            .collect();
        if self.anchor.is_some() {
            return Self::match_names(&self.segments, &names, tree);
        }
        (0..=names.len()).any(|start| Self::match_names(&self.segments, &names[start..], tree))
    }

    #[cfg(target_os = "linux")]
    fn match_names(segments: &[Segment], names: &[&[u8]], tree: bool) -> bool {
        match segments.split_first() {
            None => tree || names.is_empty(),
            Some((Segment::Any, rest)) => {
                (0..=names.len()).any(|skipped| Self::match_names(rest, &names[skipped..], tree))
            }
            Some((segment, rest)) => match names.split_first() {
                Some((name, remaining)) if segment.accepts(name) => {
                    Self::match_names(rest, remaining, tree)
                }
                _ => false,
            },
        }
    }
}

/// A policy's table with the host's home directory and environment resolved.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Resolved {
    /// A path and everything beneath it.
    pub trees: Vec<PathBuf>,
    /// Entries found beneath any directory, or anchored at the home directory,
    /// whose names may contain wildcards.
    pub patterns: Vec<Pattern>,
    /// Directories the any-directory patterns leave alone.
    pub exempt: Vec<PathBuf>,
    /// Agent and container sockets, which are denied as connect targets as well
    /// as read. Each is also in `trees`.
    pub sockets: Vec<PathBuf>,
    /// Directories that contain a denied location and so must not be removed or
    /// renamed away.
    pub guarded_parents: Vec<PathBuf>,
    /// The per-user runtime directory, whose sockets are denied as connect
    /// targets except for the ones the embedder names.
    pub runtime_dir: Option<PathBuf>,
}

/// The user's home directory, as a process under this user finds it.
fn home_directory(configured: Option<&Path>) -> Result<PathBuf> {
    configured
        .map(Path::to_path_buf)
        .or_else(std::env::home_dir)
        .filter(|home| home.is_absolute())
        .ok_or_else(|| {
            Error::InitFailed(
                "cannot find the home directory the host protection tables are relative to".into(),
            )
        })
}

/// Resolve `path` to the form the kernel matches rules against.
///
/// A denied location usually does not exist yet (that is the point of denying
/// it), so the deepest ancestor that does is canonicalized and the rest appended:
/// `/tmp/x/.zshrc` becomes `/private/tmp/x/.zshrc` whether or not the file is
/// there.
pub(crate) fn resolve_lenient(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        return Err(Error::InvalidProfile(format!(
            "a denylist path must be absolute: {}",
            path.display()
        )));
    }
    let mut missing = Vec::new();
    let mut existing = path;
    loop {
        match std::fs::canonicalize(existing) {
            Ok(mut resolved) => {
                resolved.extend(missing.iter().rev());
                return Ok(resolved);
            }
            Err(source) => match (existing.parent(), existing.file_name()) {
                (Some(parent), Some(name)) => {
                    missing.push(name);
                    existing = parent;
                }
                _ => return Err(Error::path(path, source)),
            },
        }
    }
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) {
    if !list.contains(&item) {
        list.push(item);
    }
}

fn resolve_table(
    table: &[&[Location]],
    extra: &[PathBuf],
    home: Option<&Path>,
) -> Result<Resolved> {
    let home = home_directory(home)?;
    let home_resolved = resolve_lenient(&home)?;
    let mut resolved = Resolved::default();
    for location in table.iter().flat_map(|part| part.iter()) {
        match location {
            Location::Home(relative) => {
                let path = resolve_lenient(&home.join(relative))?;
                // Every directory between the home directory and the entry is a
                // place the entry could be swapped out from: moving the parent
                // aside and a prepared copy into its name defeats a rule that
                // only names the entry.
                for ancestor in path.ancestors().skip(1) {
                    if ancestor == home_resolved || !ancestor.starts_with(&home_resolved) {
                        break;
                    }
                    push_unique(&mut resolved.guarded_parents, ancestor.to_path_buf());
                }
                push_unique(&mut resolved.trees, path);
            }
            Location::Absolute(path) => {
                push_unique(&mut resolved.trees, resolve_lenient(Path::new(path))?);
            }
            Location::Anywhere(spec) => {
                push_unique(&mut resolved.patterns, Pattern::anywhere(spec));
            }
            Location::HomePattern(spec) => {
                push_unique(
                    &mut resolved.patterns,
                    Pattern::at(home_resolved.clone(), spec),
                );
            }
        }
    }
    for path in extra {
        push_unique(&mut resolved.trees, resolve_lenient(path)?);
    }
    Ok(resolved)
}

/// The sockets the environment names, as absolute paths.
///
/// `DOCKER_HOST` and `CONTAINER_HOST` name a socket as `unix:///path`; a value
/// that is a plain absolute path, as `SSH_AUTH_SOCK` is, is taken as it stands.
fn environment_sockets() -> Vec<PathBuf> {
    SOCKET_ENV
        .iter()
        .filter_map(std::env::var_os)
        .filter_map(|value| {
            let text = value.to_string_lossy();
            let path = text.strip_prefix("unix://").unwrap_or(&text);
            let path = PathBuf::from(path);
            path.is_absolute().then_some(path)
        })
        .collect()
}

impl ReadDenylist {
    /// The table resolved against this host: the home directory, and the agent
    /// sockets and key directories the environment names.
    pub(crate) fn resolve(&self) -> Result<Resolved> {
        let mut resolved = resolve_table(&[CREDENTIALS], &self.extra, self.home.as_deref())?;
        let home = home_directory(self.home.as_deref())?;
        let sockets = SOCKETS
            .iter()
            .filter_map(|location| match location {
                Location::Home(relative) => Some(home.join(relative)),
                Location::Absolute(path) => Some(PathBuf::from(path)),
                Location::Anywhere(_) | Location::HomePattern(_) => None,
            })
            .chain(self.sockets.iter().cloned())
            .chain(environment_sockets());
        for socket in sockets {
            let socket = resolve_lenient(&socket)?;
            push_unique(&mut resolved.sockets, socket.clone());
            push_unique(&mut resolved.trees, socket);
        }
        if let Some(value) = std::env::var_os("GNUPGHOME") {
            let path = PathBuf::from(value);
            if path.is_absolute() {
                push_unique(&mut resolved.trees, resolve_lenient(&path)?);
            }
        }
        resolved.runtime_dir = std::env::var_os(RUNTIME_DIR_ENV)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .map(|path| resolve_lenient(&path))
            .transpose()?;
        Ok(resolved)
    }
}

/// Whether the current user can write to the directory `path`.
#[cfg(unix)]
fn user_can_write(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `path` is a valid NUL-terminated string for the whole call.
    unsafe { libc::access(path.as_ptr(), libc::W_OK) == 0 }
}

#[cfg(not(unix))]
fn user_can_write(_path: &Path) -> bool {
    false
}

impl WriteDenylist {
    /// The table resolved against this host: the persistence locations, the
    /// credential stores (several name programs that run later), the user's
    /// writable `PATH` directories and the Rust toolchain directory.
    pub(crate) fn resolve(&self) -> Result<Resolved> {
        let mut resolved = resolve_table(
            &[PERSISTENCE, CREDENTIALS],
            &self.extra,
            self.home.as_deref(),
        )?;
        let home = resolve_lenient(&home_directory(self.home.as_deref())?)?;

        // A program found on `PATH` in a directory the user can write runs at
        // the next command that names it. The home directory itself, and
        // anything above it, is a root of the user's files rather than a
        // directory of programs.
        if let Some(path) = std::env::var_os("PATH") {
            for directory in std::env::split_paths(&path) {
                if !directory.is_absolute() || !directory.is_dir() || !user_can_write(&directory) {
                    continue;
                }
                let directory = resolve_lenient(&directory)?;
                if home.starts_with(&directory) {
                    continue;
                }
                push_unique(&mut resolved.trees, directory);
            }
        }

        let rustup = match self
            .rustup_home
            .clone()
            .or_else(|| std::env::var_os(RUSTUP_HOME_ENV).map(PathBuf::from))
        {
            Some(path) if path.is_absolute() => path,
            _ => home.join(".rustup"),
        };
        push_unique(&mut resolved.trees, resolve_lenient(&rustup)?);

        for path in &self.exempt {
            push_unique(&mut resolved.exempt, resolve_lenient(path)?);
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_credential_table_names_the_stores_the_issue_requires() {
        let paths = ReadDenylist::credentials().resolve().unwrap().trees;
        let home = resolve_lenient(&home_directory(None).unwrap()).unwrap();
        for relative in [
            ".ssh",
            ".config/gh",
            ".cargo/credentials.toml",
            ".cargo/credentials",
            ".netrc",
            ".docker/config.json",
            ".aws",
            ".config/gcloud",
            ".kube",
            "Library/Keychains",
        ] {
            assert!(
                paths.contains(&home.join(relative)),
                "{relative} is missing from the credential table"
            );
        }
        assert!(paths.contains(&PathBuf::from("/Library/Keychains")));
    }

    #[test]
    fn an_embedder_path_is_added_to_the_table() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = ReadDenylist::credentials()
            .deny(dir.path().join("secrets"))
            .resolve()
            .unwrap();
        let expected = std::fs::canonicalize(dir.path()).unwrap().join("secrets");
        assert!(resolved.trees.contains(&expected));
    }

    #[test]
    fn a_relative_embedder_path_is_refused() {
        let error = ReadDenylist::credentials()
            .deny("secrets")
            .resolve()
            .unwrap_err();
        assert!(matches!(error, Error::InvalidProfile(_)), "{error:?}");
    }

    #[test]
    fn a_denied_location_that_does_not_exist_resolves_beneath_its_real_parent() {
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_lenient(&dir.path().join("a/b/.zshrc")).unwrap();
        let expected = std::fs::canonicalize(dir.path())
            .unwrap()
            .join("a/b/.zshrc");
        assert_eq!(resolved, expected);
    }

    #[test]
    fn the_persistence_table_guards_the_directories_above_an_entry() {
        let resolved = WriteDenylist::persistence().resolve().unwrap();
        let home = resolve_lenient(&home_directory(None).unwrap()).unwrap();
        assert!(resolved.guarded_parents.contains(&home.join(".cargo")));
        assert!(resolved.guarded_parents.contains(&home.join(".config")));
        assert!(resolved.guarded_parents.contains(&home.join("Library")));
        assert!(
            !resolved.guarded_parents.contains(&home),
            "the home directory itself is never guarded"
        );
        assert!(resolved.patterns.contains(&Pattern::anywhere(".git/hooks")));
    }
}
