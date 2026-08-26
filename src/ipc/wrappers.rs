//! Generation of the command shims a sandboxed process sees on its `PATH`.
//!
//! Each registered IPC command gets a small script in `.heel/bin` that execs
//! `heel ipc <command>`. The scripts carry no argument-parsing logic of their
//! own: they forward the declared argument names to `heel ipc`, which does the
//! parsing in Rust where it can be tested.

use std::borrow::Cow;
use std::path::{Path, PathBuf};

use askama::Template;

use crate::error::{Error, Result};
use crate::ipc::router::{CommandMeta, IpcRouter};

/// Directory inside the working directory holding sandbox-private files.
pub const HEEL_DIR_NAME: &str = ".heel";
/// Directory inside [`HEEL_DIR_NAME`] holding the generated command shims.
pub const WRAPPER_DIR_NAME: &str = "bin";
/// File name of the IPC socket inside its private directory.
pub const SOCKET_NAME: &str = "s";

/// Wrapper script for one IPC command.
#[derive(Template)]
#[template(path = "ipc/wrapper.sh", escape = "none")]
struct WrapperTemplate<'a> {
    command: &'a str,
    positional_args: &'a [Cow<'static, str>],
    stdin_arg: Option<&'a str>,
}

/// The `heel` launcher placed alongside the wrappers.
#[derive(Template)]
#[template(path = "ipc/heel_launcher.sh", escape = "none")]
struct LauncherTemplate<'a> {
    binary: &'a str,
}

/// Where a sandbox's IPC files live.
///
/// The command shims sit inside the working directory so they land on `PATH`,
/// but the socket does not. Two reasons: `sockaddr_un` has room for barely a
/// hundred bytes, which a working directory under a per-user temp root can
/// exhaust on its own; and the working directory is writable by the sandboxed
/// process, which could otherwise unlink the socket it depends on.
#[derive(Debug, Clone)]
pub(crate) struct IpcLayout {
    heel_dir: PathBuf,
    bin_dir: PathBuf,
}

impl IpcLayout {
    /// Derive the layout for a working directory.
    pub(crate) fn new(working_dir: &Path) -> Self {
        let heel_dir = working_dir.join(HEEL_DIR_NAME);
        Self {
            bin_dir: heel_dir.join(WRAPPER_DIR_NAME),
            heel_dir,
        }
    }

    /// Directory holding the generated shims, which is added to `PATH`.
    pub(crate) fn bin_dir(&self) -> &Path {
        &self.bin_dir
    }

    /// Create the directories and write the launcher and command shims.
    ///
    /// This is blocking work; callers run it off the async executor.
    pub(crate) fn write(&self, router: &IpcRouter, heel_binary: &Path) -> Result<()> {
        create_private_dir(&self.heel_dir)?;
        create_private_dir(&self.bin_dir)?;

        let escaped = shell_escape::unix::escape(heel_binary.to_string_lossy());
        write_script(
            &self.bin_dir.join("heel"),
            &LauncherTemplate { binary: &escaped }.render()?,
        )?;

        for (command, meta) in router.methods() {
            write_script(&self.bin_dir.join(command), &render_wrapper(command, meta)?)?;
        }

        tracing::debug!(bin_dir = %self.bin_dir.display(), "wrote IPC command shims");
        Ok(())
    }
}

/// The directory to create the IPC socket in.
///
/// Unix socket paths are limited to about a hundred bytes, so the shortest
/// available temporary root is chosen rather than the conventional one: on
/// macOS the per-user temp directory alone is two thirds of the budget.
pub(crate) fn socket_root() -> PathBuf {
    let user_temp = std::env::temp_dir();
    let shared_temp = PathBuf::from("/tmp");

    if shared_temp.is_dir() && shared_temp.as_os_str().len() < user_temp.as_os_str().len() {
        shared_temp
    } else {
        user_temp
    }
}

/// Render the shim for one command.
fn render_wrapper(command: &str, meta: &CommandMeta) -> Result<String> {
    Ok(WrapperTemplate {
        command,
        positional_args: &meta.positional_args,
        stdin_arg: meta.stdin_arg.as_deref(),
    }
    .render()?)
}

/// Create a directory only its owner can enter.
fn create_private_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).map_err(|source| Error::path(path, source))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::path(path, source))?;
    }

    Ok(())
}

/// Write an executable script.
fn write_script(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents).map_err(|source| Error::path(path, source))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| Error::path(path, source))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{IpcCommand, NoArgs};
    use serde::Deserialize;

    struct Search;

    #[derive(Deserialize)]
    struct SearchArgs {
        #[allow(dead_code)]
        query: String,
    }

    impl IpcCommand for Search {
        fn name(&self) -> Cow<'static, str> {
            "search".into()
        }
        fn positional_args(&self) -> Cow<'static, [Cow<'static, str>]> {
            Cow::Borrowed(&[Cow::Borrowed("query")])
        }
        fn stdin_arg(&self) -> Option<Cow<'static, str>> {
            Some("input".into())
        }

        type Args = SearchArgs;
        type Response = ();

        async fn handle(&self, _args: SearchArgs) {}
    }

    struct Plain;

    impl IpcCommand for Plain {
        fn name(&self) -> Cow<'static, str> {
            "plain".into()
        }

        type Args = NoArgs;
        type Response = ();

        async fn handle(&self, _args: NoArgs) {}
    }

    #[test]
    fn wrapper_forwards_declared_argument_names() {
        let script = render_wrapper(
            "search",
            &CommandMeta {
                positional_args: Cow::Borrowed(&[Cow::Borrowed("query"), Cow::Borrowed("scope")]),
                stdin_arg: Some(Cow::Borrowed("input")),
            },
        )
        .expect("renders");

        assert!(script.contains(
            "heel\" ipc search --positional query --positional scope --stdin-arg input -- \"$@\""
        ));
    }

    #[test]
    fn wrapper_without_metadata_is_a_bare_forward() {
        let script = render_wrapper(
            "plain",
            &CommandMeta {
                positional_args: Cow::Borrowed(&[]),
                stdin_arg: None,
            },
        )
        .expect("renders");

        assert!(script.contains("heel\" ipc plain -- \"$@\""));
        assert!(!script.contains("--positional"));
        assert!(!script.contains("--stdin-arg"));
    }

    #[test]
    fn layout_writes_executable_owner_only_scripts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = IpcLayout::new(dir.path());
        let router = IpcRouter::new().register(Search).register(Plain);

        layout
            .write(&router, Path::new("/usr/local/bin/heel"))
            .expect("writes");

        for name in ["heel", "search", "plain"] {
            let path = layout.bin_dir().join(name);
            assert!(path.is_file(), "{name} must be written");

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;

                let mode = std::fs::metadata(&path)
                    .unwrap_or_else(|_| panic!("{name} exists"))
                    .permissions()
                    .mode();
                assert_eq!(mode & 0o777, 0o700, "{name} must be owner-only");
            }
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = std::fs::metadata(layout.bin_dir())
                .expect("bin dir exists")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }

    #[test]
    fn launcher_escapes_the_binary_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let layout = IpcLayout::new(dir.path());

        layout
            .write(&IpcRouter::new(), Path::new("/opt/heel dir/heel"))
            .expect("writes");

        let launcher = std::fs::read_to_string(layout.bin_dir().join("heel")).expect("reads");
        assert!(
            launcher.contains("'/opt/heel dir/heel'"),
            "unescaped path in: {launcher}"
        );
    }

    #[test]
    fn shims_live_inside_the_working_directory() {
        let layout = IpcLayout::new(Path::new("/work"));
        assert_eq!(layout.bin_dir(), Path::new("/work/.heel/bin"));
    }

    #[test]
    fn socket_root_leaves_room_for_the_socket_name() {
        let root = socket_root();
        assert!(root.is_dir(), "{} must exist", root.display());
        // A per-sandbox directory and the socket name still have to fit inside
        // the platform's sockaddr_un limit.
        assert!(
            root.as_os_str().len() + "/heel-0123abcd/s".len() < 100,
            "{} leaves no room for a socket path",
            root.display()
        );
    }
}
