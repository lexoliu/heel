//! The host protection policies, enforced by the kernel.
//!
//! A sandbox that leaves the rest of the machine open must still keep the
//! credentials unreadable and the persistence locations unwritable. These tests
//! build a home directory of stand-ins in a temporary directory and aim the
//! policies at it, so no real credential is read or changed; the Homebrew and
//! system-bin checks only list directories.
//!
//! The policies are enforced on macOS and Linux; on Windows a sandbox that
//! carries one must fail at construction, which the last test checks.

#![allow(clippy::unwrap_used)]

mod fixtures;

#[cfg(unix)]
use std::path::Path;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(unix)]
use heel::DenyAll;
#[cfg(windows)]
use heel::Sandbox;
#[cfg(target_os = "macos")]
use heel::{AllowAll, SecurityConfig, SecurityConfigBuilder};
use heel::{ReadDenylist, SandboxConfigBuilder, WriteDenylist};

#[cfg(unix)]
mod enforced {
    use super::*;
    use fixtures::host::{home_with, open_security, reader, sh, start, stderr, stdout, writer};

    /// The credential stores #106 requires, one file in each.
    const CREDENTIAL_FILES: &[&str] = &[
        ".ssh/id_ed25519",
        ".gnupg/private-keys-v1.d/key.key",
        ".config/gh/hosts.yml",
        ".cargo/credentials.toml",
        ".cargo/credentials",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".git-credentials",
        ".docker/config.json",
        ".aws/credentials",
        ".config/gcloud/credentials.db",
        ".kube/config",
        "Library/Keychains/login.keychain-db",
        "Library/Application Support/Google/Chrome/Default/Cookies",
        "Library/Application Support/Firefox/Profiles/p/logins.json",
    ];

    #[tokio::test]
    async fn every_credential_store_is_unreadable_and_the_error_names_it() {
        let home = home_with(CREDENTIAL_FILES);
        let sandbox = start(reader(DenyAll, home.path())).await;

        for relative in CREDENTIAL_FILES {
            let path = std::fs::canonicalize(home.path()).unwrap().join(relative);
            let output = sh(&sandbox, &format!("cat '{}'", path.display())).await;
            assert!(
                !output.status.success(),
                "{relative} was readable: {}",
                stdout(&output)
            );
            assert!(
                stderr(&output).contains(&path.display().to_string()),
                "the failure for {relative} does not name the path: {}",
                stderr(&output)
            );
        }
    }

    #[tokio::test]
    async fn everything_that_is_not_a_credential_stays_readable() {
        let home = home_with(&[".config/other/settings.toml", ".rustup/settings.toml"]);
        let sandbox = start(reader(DenyAll, home.path())).await;
        let root = std::fs::canonicalize(home.path()).unwrap();

        for relative in [".config/other/settings.toml", ".rustup/settings.toml"] {
            let output = sh(
                &sandbox,
                &format!("cat '{}'", root.join(relative).display()),
            )
            .await;
            assert!(output.status.success(), "{relative}: {}", stderr(&output));
            assert_eq!(stdout(&output), "secret");
        }
    }

    #[tokio::test]
    async fn a_toolchain_on_the_host_is_readable_but_not_writable() {
        // The files a build reads next to the credentials it must not: a rustup
        // home and a Homebrew prefix. The rustup home is a stand-in the test
        // creates, so a failed protection damages nothing on the host. The refusal
        // is the write denylist's: with the home directory unprotected, Linux
        // grants it whole.
        let rustup = tempfile::tempdir().unwrap();
        let settings = std::fs::canonicalize(rustup.path())
            .unwrap()
            .join("settings.toml");
        std::fs::write(&settings, "version = \"12\"\n").unwrap();
        let unrelated_home = tempfile::tempdir().unwrap();
        let sandbox = start(
            reader(DenyAll, unrelated_home.path()).write_denylist(
                WriteDenylist::persistence()
                    .home(unrelated_home.path())
                    .rustup_home(rustup.path()),
            ),
        )
        .await;

        let read = sh(&sandbox, &format!("head -c 1 '{}'", settings.display())).await;
        assert!(read.status.success(), "{}", stderr(&read));

        let write = sh(&sandbox, &format!("echo x >> '{}'", settings.display())).await;
        assert!(!write.status.success(), "the toolchain was writable");
        assert_eq!(
            std::fs::read_to_string(&settings).unwrap(),
            "version = \"12\"\n"
        );

        for homebrew in ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"] {
            if Path::new(homebrew).is_dir() {
                let listed = sh(&sandbox, &format!("ls '{homebrew}' > /dev/null")).await;
                assert!(listed.status.success(), "{homebrew}: {}", stderr(&listed));
            }
        }
    }

    #[tokio::test]
    async fn a_path_the_embedder_adds_is_denied() {
        let home = home_with(&[]);
        let secrets = tempfile::tempdir().unwrap();
        std::fs::write(secrets.path().join("token"), "t").unwrap();
        let path = std::fs::canonicalize(secrets.path()).unwrap().join("token");
        let sandbox = start(
            SandboxConfigBuilder::default()
                .filesystem_strict(false)
                .security(open_security())
                .read_denylist(
                    ReadDenylist::credentials()
                        .home(home.path())
                        .deny(secrets.path()),
                ),
        )
        .await;

        let output = sh(&sandbox, &format!("cat '{}'", path.display())).await;
        assert!(!output.status.success());
        assert!(stderr(&output).contains(&path.display().to_string()));
    }

    #[tokio::test]
    async fn a_grant_does_not_reopen_a_credential_store() {
        let home = home_with(&[".ssh/id_ed25519"]);
        let ssh = home.path().join(".ssh");
        let path = std::fs::canonicalize(&ssh).unwrap().join("id_ed25519");
        let sandbox = start(reader(DenyAll, home.path()).readable(&ssh)).await;

        let output = sh(&sandbox, &format!("cat '{}'", path.display())).await;
        assert!(!output.status.success(), "a grant reopened the store");
    }

    #[tokio::test]
    async fn a_credential_directory_cannot_be_moved_to_a_name_that_is_readable() {
        let home = home_with(&[".ssh/id_ed25519", ".config/other/x"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(reader(DenyAll, home.path()).writable(&root)).await;

        let moved = sh(
            &sandbox,
            &format!(
                "mv '{0}/.ssh' '{0}/stolen' && cat '{0}/stolen/id_ed25519'",
                root.display()
            ),
        )
        .await;
        assert!(!moved.status.success(), "{}", stdout(&moved));
        assert!(root.join(".ssh/id_ed25519").exists());

        let parent = sh(
            &sandbox,
            &format!(
                "mv '{0}/.config' '{0}/c' && cat '{0}/c/gh/hosts.yml'",
                root.display()
            ),
        )
        .await;
        assert!(!parent.status.success());
    }

    /// A keychain holding one generic password, outside every denied location.
    #[cfg(target_os = "macos")]
    ///
    /// It is created and filled by the unsandboxed `security` tool under a
    /// throwaway home, so the real search list and the real keychains are untouched.
    struct TestKeychain {
        dir: tempfile::TempDir,
    }

    #[cfg(target_os = "macos")]
    impl TestKeychain {
        const SERVICE: &'static str = "heel-test-service";
        const SECRET: &'static str = "heel-test-secret";

        fn create() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let fake_home = dir.path().join("home");
            std::fs::create_dir(&fake_home).unwrap();
            let keychain = dir.path().join("test.keychain-db");
            for args in [
                vec!["create-keychain", "-p", "pw", keychain.to_str().unwrap()],
                vec!["unlock-keychain", "-p", "pw", keychain.to_str().unwrap()],
                vec![
                    "add-generic-password",
                    "-a",
                    "heel",
                    "-s",
                    Self::SERVICE,
                    "-w",
                    Self::SECRET,
                    keychain.to_str().unwrap(),
                ],
            ] {
                let status = std::process::Command::new("/usr/bin/security")
                    .args(&args)
                    .env("HOME", &fake_home)
                    .status()
                    .unwrap();
                assert!(status.success(), "security {args:?} failed");
            }
            Self { dir }
        }

        fn path(&self) -> PathBuf {
            std::fs::canonicalize(self.dir.path())
                .unwrap()
                .join("test.keychain-db")
        }

        fn command(&self) -> String {
            format!(
                "/usr/bin/security find-generic-password -s {} -w '{}'",
                Self::SERVICE,
                self.path().display()
            )
        }
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn a_keychain_item_cannot_be_read_through_the_security_services() {
        let keychain = TestKeychain::create();

        // The control: with the keychain unprotected the item is readable inside a
        // sandbox, so the failure below is the policy and not the fixture.
        let control = start(
            SandboxConfigBuilder::default()
                .filesystem_strict(false)
                .security(open_security()),
        )
        .await;
        let output = sh(&control, &keychain.command()).await;
        assert_eq!(stdout(&output), TestKeychain::SECRET, "{}", stderr(&output));

        // The keychain file is outside every denied path, so the file rules cannot
        // be what stops this.
        let home = home_with(&[]);
        let protected = start(reader(DenyAll, home.path())).await;
        let output = sh(&protected, &keychain.command()).await;
        assert!(
            !output.status.success() && stdout(&output).is_empty(),
            "the keychain item was read: {}",
            stdout(&output)
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn protecting_the_keychain_holds_under_strict_reads_even_with_a_grant() {
        // #23: under `filesystem_strict` the toggle looked inert, and a read grant
        // on the keychain directory opened it.
        let keychain = TestKeychain::create();
        let directory = keychain.path().parent().unwrap().to_path_buf();

        let protected = start(
            SandboxConfigBuilder::default()
                .filesystem_strict(true)
                .security(SecurityConfig::strict())
                .readable(&directory),
        )
        .await;
        let output = sh(&protected, &keychain.command()).await;
        assert!(
            !output.status.success() && stdout(&output).is_empty(),
            "a read grant reached the keychain: {}",
            stdout(&output)
        );

        let unprotected = start(
            SandboxConfigBuilder::default()
                .filesystem_strict(true)
                .security(
                    SecurityConfigBuilder::default()
                        .protect_keychain(false)
                        .build(),
                )
                .readable(&directory),
        )
        .await;
        let output = sh(&unprotected, &keychain.command()).await;
        assert_eq!(
            stdout(&output),
            TestKeychain::SECRET,
            "turning the protection off must be what opens the keychain: {}",
            stderr(&output)
        );
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn https_works_while_the_keychain_is_closed() {
        // Certificate trust evaluation goes through trustd, not the services that
        // open keychain items.
        let home = home_with(&[]);
        let sandbox = start(reader(AllowAll, home.path())).await;

        let output = sandbox
            .command("/usr/bin/curl")
            .args([
                "-sS",
                "--max-time",
                "30",
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
            ])
            .arg("https://example.com")
            .output()
            .await
            .unwrap();
        assert_eq!(stdout(&output), "200", "{}", stderr(&output));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_agent_socket_cannot_be_connected_to_whatever_the_network_policy() {
        let home = home_with(&[]);
        let socket = PathBuf::from(format!(
            "/private/tmp/heel-agent-{}.sock",
            std::process::id()
        ));
        std::fs::remove_file(&socket).ok();
        let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            // One connection from the unsandboxed control; the sandboxed attempt
            // never arrives.
            let _ = listener.accept();
        });

        let connect = format!(
            "/usr/bin/ruby -rsocket -e 'UNIXSocket.new(\"{}\").close; puts :connected'",
            socket.display()
        );
        let sandbox = start(
            SandboxConfigBuilder::default()
                .network(AllowAll)
                .filesystem_strict(false)
                .security(open_security())
                .read_denylist(
                    ReadDenylist::credentials()
                        .home(home.path())
                        .socket(&socket),
                ),
        )
        .await;
        let denied = sh(&sandbox, &connect).await;

        let control = std::process::Command::new("/bin/sh")
            .args(["-c", &connect])
            .output()
            .unwrap();
        server.join().unwrap();
        std::fs::remove_file(&socket).ok();

        assert_eq!(stdout(&control), "connected");
        assert!(
            !stderr(&denied).is_empty() && stdout(&denied).is_empty(),
            "the agent socket was reachable: {}",
            stdout(&denied)
        );
        assert!(
            stderr(&denied).contains("Operation not permitted"),
            "{}",
            stderr(&denied)
        );
    }

    /// The persistence locations a default build must not be able to write.
    const PERSISTENCE_FILES: &[&str] = &[
        ".zshrc",
        ".zshenv",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".config/fish/config.fish",
        ".cargo/bin/cargo",
        ".local/bin/tool",
        ".cargo/config.toml",
        ".ssh/authorized_keys",
        ".gitconfig",
        "Library/LaunchAgents/com.example.plist",
        ".config/systemd/user/unit.service",
        ".config/autostart/app.desktop",
        "work/repo/.git/hooks/pre-commit",
    ];

    #[tokio::test]
    async fn persistence_locations_cannot_be_changed_created_removed_or_renamed() {
        let home = home_with(PERSISTENCE_FILES);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(writer(home.path())).await;

        for relative in PERSISTENCE_FILES {
            let path = root.join(relative);
            let existing = path.display().to_string();
            for (what, script) in [
                ("modify", format!("echo x >> '{existing}'")),
                ("replace", format!("echo x > '{existing}'")),
                ("remove", format!("rm '{existing}'")),
                ("rename", format!("mv '{existing}' '{existing}.old'")),
            ] {
                let output = sh(&sandbox, &script).await;
                assert!(
                    !output.status.success(),
                    "could {what} {relative}: {}",
                    stderr(&output)
                );
            }
            assert_eq!(
                std::fs::read_to_string(&path).unwrap(),
                "secret",
                "{relative}"
            );
        }
    }

    #[tokio::test]
    async fn a_new_shell_startup_file_cannot_be_created() {
        let home = home_with(&[]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(writer(home.path())).await;

        for name in [
            ".zshrc",
            ".bash_profile",
            ".config/fish/config.fish",
            ".cargo/bin/evil",
        ] {
            let output = sh(
                &sandbox,
                &format!(
                    "mkdir -p \"$(dirname '{0}/{1}')\"; echo x > '{0}/{1}'",
                    root.display(),
                    name
                ),
            )
            .await;
            assert!(!output.status.success(), "created {name}");
            assert!(!root.join(name).exists(), "{name} exists");
        }
    }

    #[tokio::test]
    async fn the_directory_above_a_persistence_location_cannot_be_swapped_for_a_copy() {
        let home = home_with(&[".cargo/bin/cargo", "prepared/.cargo/bin/evil"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(writer(home.path())).await;

        let output = sh(
            &sandbox,
            &format!(
                "mv '{0}/.cargo' '{0}/.cargo.old' && mv '{0}/prepared/.cargo' '{0}/.cargo'",
                root.display()
            ),
        )
        .await;
        assert!(!output.status.success());
        assert!(root.join(".cargo/bin/cargo").exists());
        assert!(!root.join(".cargo/bin/evil").exists());
    }

    #[tokio::test]
    async fn everything_else_is_writable_as_usual() {
        let home = home_with(&[".cargo/bin/cargo", "work/repo/.git/index"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(writer(home.path())).await;

        for relative in [
            "notes.txt",
            "work/repo/src/lib.rs",
            "work/repo/.git/index",
            ".cargo/registry/index/entry",
            ".cache/stow/entry",
            "Library/Caches/tool/entry",
        ] {
            let path = root.join(relative);
            let output = sh(
                &sandbox,
                &format!(
                    "mkdir -p \"$(dirname '{0}')\" && echo x >> '{0}' && mv '{0}' '{0}.moved' && rm '{0}.moved'",
                    path.display()
                ),
            )
            .await;
            assert!(output.status.success(), "{relative}: {}", stderr(&output));
        }
    }

    #[tokio::test]
    async fn a_grant_does_not_reopen_a_persistence_location() {
        let home = home_with(&[".cargo/bin/cargo"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(writer(home.path()).writable(root.join(".cargo/bin"))).await;

        let output = sh(
            &sandbox,
            &format!("echo x >> '{}/.cargo/bin/cargo'", root.display()),
        )
        .await;
        assert!(!output.status.success());
    }

    #[tokio::test]
    async fn a_private_clone_can_be_exempted_from_the_hooks_rule() {
        let home = home_with(&[
            "cache/git/checkout/.git/hooks/sample",
            "work/.git/hooks/pre-commit",
        ]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(
            SandboxConfigBuilder::default()
                .filesystem_strict(false)
                .security(open_security())
                .writable_file_system(true)
                .write_denylist(
                    WriteDenylist::persistence()
                        .home(home.path())
                        .except(root.join("cache/git")),
                ),
        )
        .await;

        let exempt = sh(
            &sandbox,
            &format!(
                "echo x >> '{0}/cache/git/checkout/.git/hooks/sample' && rm -r '{0}/cache/git/checkout/.git'",
                root.display()
            ),
        )
        .await;
        assert!(exempt.status.success(), "{}", stderr(&exempt));

        let guarded = sh(
            &sandbox,
            &format!("echo x >> '{}/work/.git/hooks/pre-commit'", root.display()),
        )
        .await;
        assert!(!guarded.status.success());
    }

    #[tokio::test]
    async fn denials_are_reported_with_the_path_they_refused() {
        let home = home_with(&[".ssh/id_ed25519"]);
        let path = std::fs::canonicalize(home.path())
            .unwrap()
            .join(".ssh/id_ed25519");
        let sandbox = start(reader(DenyAll, home.path())).await;

        let recorder = sandbox.record_denials().await.expect("recording starts");
        let output = sh(&sandbox, &format!("cat '{}'", path.display())).await;
        assert!(!output.status.success());
        let denials = recorder.finish().await.expect("recording finishes");

        assert!(
            denials
                .iter()
                .any(|denial| denial.operation.starts_with("file-read")
                    && denial.target == path.display().to_string()),
            "no denial names {}: {denials:#?}",
            path.display()
        );
    }
}

#[cfg(windows)]
#[tokio::test]
async fn a_denylist_on_a_platform_that_cannot_enforce_it_fails_at_construction() {
    let home = tempfile::tempdir().unwrap();
    for builder in [
        SandboxConfigBuilder::default()
            .read_denylist(ReadDenylist::credentials().home(home.path())),
        SandboxConfigBuilder::default()
            .write_denylist(WriteDenylist::persistence().home(home.path())),
    ] {
        let error =
            Sandbox::with_config_and_executor(builder.build(), executor_core::tokio::TokioGlobal)
                .await
                .err()
                .expect("the sandbox must not start");
        assert!(
            matches!(error, heel::Error::UnsupportedPolicy { .. }),
            "{error:?}"
        );
    }
}
