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
        let rustup = fixtures::tempdir();
        let settings = std::fs::canonicalize(rustup.path())
            .unwrap()
            .join("settings.toml");
        std::fs::write(&settings, "version = \"12\"\n").unwrap();
        let unrelated_home = fixtures::tempdir();
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
        let secrets = fixtures::tempdir();
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

    // On macOS a grant naming a store opens it; `macos_protections` covers that.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_grant_does_not_reopen_a_credential_store() {
        let home = home_with(&[".ssh/id_ed25519"]);
        let ssh = std::fs::canonicalize(home.path().join(".ssh")).unwrap();
        let path = std::fs::canonicalize(&ssh).unwrap().join("id_ed25519");
        let sandbox = start(reader(DenyAll, home.path()).readable(fixtures::resolved(&ssh))).await;

        let output = sh(&sandbox, &format!("cat '{}'", path.display())).await;
        assert!(!output.status.success(), "a grant reopened the store");
    }

    #[tokio::test]
    async fn a_credential_directory_cannot_be_moved_to_a_name_that_is_readable() {
        let home = home_with(&[".ssh/id_ed25519", ".config/other/x"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(reader(DenyAll, home.path()).writable(fixtures::resolved(&root))).await;

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
            let dir = fixtures::tempdir();
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
                .readable(fixtures::resolved(&directory)),
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
                .readable(fixtures::resolved(&directory)),
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
            ".cache/stow/entry",
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
        let sandbox =
            start(writer(home.path()).writable(fixtures::resolved(root.join(".cargo/bin")))).await;

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

/// What the macOS profile enforces beyond the denylists: the security toggles
/// beat an enclosing grant, nothing is planted at or moved out of a protected
/// location, and a grant naming a store opens exactly it. The Linux backend
/// enforces the denylists only.
#[cfg(target_os = "macos")]
mod macos_protections {
    use super::*;
    use fixtures::host::{home_with, open_security, sh, start, stderr, stdout};

    /// Every sandbox that reads outside its grants and one that reads only
    /// inside them, the two shapes a host that grants a directory runs in.
    const READ_POLICIES: [bool; 2] = [false, true];

    fn denylisted(strict: bool, home: &Path) -> SandboxConfigBuilder<DenyAll> {
        SandboxConfigBuilder::default()
            .filesystem_strict(strict)
            .security(open_security())
            .read_denylist(ReadDenylist::credentials().home(home))
    }

    /// Whether `cat` of `relative` under `root` succeeded and printed the
    /// stand-in's content, with the failure's message when it did not.
    async fn cat<N: heel::NetworkPolicy>(
        sandbox: &heel::Sandbox<N>,
        root: &Path,
        relative: &str,
    ) -> Result<(), String> {
        let path = root.join(relative);
        let output = sh(sandbox, &format!("cat '{}'", path.display())).await;
        if output.status.success() {
            assert_eq!(stdout(&output), "secret", "{relative}");
            Ok(())
        } else {
            Err(stderr(&output))
        }
    }

    #[tokio::test]
    async fn a_grant_of_a_directory_holding_a_credential_store_does_not_open_it() {
        // The directory a host starts a session in is granted whole, and may be
        // the home directory or one above it.
        for strict in READ_POLICIES {
            let home = home_with(&[".ssh/id_ed25519", ".aws/credentials", "notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox =
                start(denylisted(strict, &root).readable(fixtures::resolved(&root))).await;

            for store in [".ssh/id_ed25519", ".aws/credentials"] {
                let error = cat(&sandbox, &root, store)
                    .await
                    .expect_err("the grant reopened a credential store");
                assert!(
                    error.contains(&root.join(store).display().to_string()),
                    "strict={strict}: the failure does not name {store}: {error}"
                );
            }
            cat(&sandbox, &root, "notes.txt")
                .await
                .unwrap_or_else(|error| panic!("strict={strict}: {error}"));
        }
    }

    #[tokio::test]
    async fn a_grant_naming_a_credential_store_opens_it_and_only_it() {
        for strict in READ_POLICIES {
            let home = home_with(&[".ssh/id_ed25519", ".aws/credentials"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox =
                start(denylisted(strict, &root).readable(fixtures::resolved(root.join(".ssh"))))
                    .await;

            cat(&sandbox, &root, ".ssh/id_ed25519")
                .await
                .unwrap_or_else(|error| panic!("strict={strict}: {error}"));
            cat(&sandbox, &root, ".aws/credentials")
                .await
                .expect_err("a grant of one store opened another");
        }
    }

    #[tokio::test]
    async fn a_grant_inside_a_credential_store_opens_what_it_names() {
        for strict in READ_POLICIES {
            let home = home_with(&[".ssh/id_ed25519", ".ssh/keys/deploy"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(
                denylisted(strict, &root)
                    .readable(fixtures::resolved(&root))
                    .readable(fixtures::resolved(root.join(".ssh/keys"))),
            )
            .await;

            cat(&sandbox, &root, ".ssh/keys/deploy")
                .await
                .unwrap_or_else(|error| panic!("strict={strict}: {error}"));
            cat(&sandbox, &root, ".ssh/id_ed25519")
                .await
                .expect_err("a grant inside a store opened the rest of it");
        }
    }

    /// The files the security toggles protect, one in each group.
    const TOGGLED_FILES: &[&str] = &[
        ".ssh/id_ed25519",
        ".gnupg/private-keys-v1.d/key.key",
        ".aws/credentials",
        ".kube/config",
        ".npmrc",
        ".cargo/credentials.toml",
        ".zsh_history",
        "Library/Keychains/login.keychain-db",
        "Library/Application Support/Google/Chrome/Default/Cookies",
    ];

    /// A sandbox with the strict toggles and no denylist, in the three shapes of
    /// filesystem policy: reads only inside grants, reads everywhere, and
    /// writes everywhere.
    const TOGGLE_MODES: [(bool, bool); 3] = [(true, false), (false, false), (false, true)];

    fn toggled(strict: bool, writable: bool) -> SandboxConfigBuilder<DenyAll> {
        SandboxConfigBuilder::default()
            .filesystem_strict(strict)
            .writable_file_system(writable)
            .security(SecurityConfig::strict())
    }

    #[tokio::test]
    async fn a_grant_of_a_directory_does_not_open_what_the_security_toggles_protect() {
        for (strict, writable) in TOGGLE_MODES {
            let mut files = TOGGLED_FILES.to_vec();
            files.push("notes.txt");
            let home = home_with(&files);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(
                toggled(strict, writable)
                    .readable(fixtures::resolved(&root))
                    .read_denylist(ReadDenylist::credentials().home(&root)),
            )
            .await;

            for protected in TOGGLED_FILES {
                cat(&sandbox, &root, protected).await.expect_err(&format!(
                    "strict={strict} writable={writable}: a grant reopened {protected}"
                ));
            }
            cat(&sandbox, &root, "notes.txt")
                .await
                .unwrap_or_else(|error| panic!("strict={strict} writable={writable}: {error}"));
        }
    }

    #[tokio::test]
    async fn a_grant_naming_what_the_security_toggles_protect_opens_it() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(TOGGLED_FILES);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let named = [
                ".ssh",
                ".aws/credentials",
                "Library/Keychains",
                "Library/Application Support/Google/Chrome/Default",
            ];
            let mut builder =
                toggled(strict, writable).read_denylist(ReadDenylist::credentials().home(&root));
            for path in named {
                builder = builder.readable(fixtures::resolved(root.join(path)));
            }
            let sandbox = start(builder).await;

            for opened in [
                ".ssh/id_ed25519",
                ".aws/credentials",
                "Library/Keychains/login.keychain-db",
                "Library/Application Support/Google/Chrome/Default/Cookies",
            ] {
                cat(&sandbox, &root, opened).await.unwrap_or_else(|error| {
                    panic!("strict={strict} writable={writable}: {opened}: {error}")
                });
            }
            for still_protected in [".gnupg/private-keys-v1.d/key.key", ".kube/config", ".npmrc"] {
                cat(&sandbox, &root, still_protected)
                    .await
                    .expect_err("a grant opened a location it does not name");
            }
        }
    }

    /// A sandbox over a home directory stand-in that grants it writably, in each
    /// shape of filesystem policy. The denylist points the configured home at
    /// the stand-in, which is where the planting rules apply.
    fn home_granted(strict: bool, writable: bool, root: &Path) -> SandboxConfigBuilder<DenyAll> {
        toggled(strict, writable)
            .writable(fixtures::resolved(root))
            .read_denylist(ReadDenylist::credentials().home(root))
    }

    /// Run `script` in a shell and return its output, which must have succeeded.
    async fn succeeds<N: heel::NetworkPolicy>(sandbox: &heel::Sandbox<N>, script: &str) -> String {
        let output = sh(sandbox, script).await;
        assert!(output.status.success(), "{script}: {}", stderr(&output));
        stdout(&output)
    }

    /// Run `script` in a shell and require it to fail without printing a secret.
    async fn is_refused<N: heel::NetworkPolicy>(
        sandbox: &heel::Sandbox<N>,
        script: &str,
        what: &str,
    ) {
        let output = sh(sandbox, script).await;
        assert!(
            !output.status.success() && !stdout(&output).contains("secret"),
            "{what}: `{script}` succeeded: {}",
            stdout(&output)
        );
    }

    #[tokio::test]
    async fn a_link_to_a_store_does_not_read_it() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[".ssh/id_ed25519", "notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            // Links the host made before the sandbox started.
            std::os::unix::fs::symlink(root.join(".ssh/id_ed25519"), root.join("file-link"))
                .unwrap();
            std::os::unix::fs::symlink(root.join(".ssh"), root.join("directory-link")).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");

            is_refused(
                &sandbox,
                &format!("cat '{}/file-link'", root.display()),
                &what,
            )
            .await;
            is_refused(
                &sandbox,
                &format!("cat '{}/directory-link/id_ed25519'", root.display()),
                &what,
            )
            .await;

            // Links the sandbox makes itself.
            let made = sh(
                &sandbox,
                &format!(
                    "ln -s '{0}/.ssh/id_ed25519' '{0}/made-link'; ln '{0}/.ssh/id_ed25519' '{0}/made-hard'; \
                     cat '{0}/made-link'",
                    root.display()
                ),
            )
            .await;
            assert!(
                !stdout(&made).contains("secret"),
                "{what}: {}",
                stdout(&made)
            );
            assert!(
                !root.join("made-hard").exists(),
                "{what}: a hard link to a store was made"
            );
            cat(&sandbox, &root, "notes.txt")
                .await
                .unwrap_or_else(|error| panic!("{what}: {error}"));
        }
    }

    #[tokio::test]
    async fn a_store_created_after_the_sandbox_started_is_unreadable() {
        const LATER: &[&str] = &[
            ".ssh/id_ed25519",
            ".aws/credentials",
            ".netrc",
            ".cargo/credentials.toml",
            "Library/Keychains/login.keychain-db",
        ];
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&["notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(
                toggled(strict, writable)
                    .readable(fixtures::resolved(&root))
                    .read_denylist(ReadDenylist::credentials().home(&root)),
            )
            .await;
            let what = format!("strict={strict} writable={writable}");

            // What the host does while the sandbox runs: it makes the stores and
            // an ordinary file next to them.
            for relative in LATER.iter().chain(&["later.txt"]) {
                let path = root.join(relative);
                std::fs::create_dir_all(path.parent().unwrap()).unwrap();
                std::fs::write(path, "secret").unwrap();
            }

            for relative in LATER {
                cat(&sandbox, &root, relative)
                    .await
                    .expect_err(&format!("{what}: {relative} was readable"));
            }
            cat(&sandbox, &root, "later.txt")
                .await
                .unwrap_or_else(|error| panic!("{what}: a file the host made later: {error}"));
        }
    }

    /// A directory the sandbox can pass through and cannot list.
    struct Unlisted(std::path::PathBuf);

    impl Unlisted {
        fn new(path: std::path::PathBuf) -> Self {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o111)).unwrap();
            Self(path)
        }
    }

    impl Drop for Unlisted {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o755)).ok();
        }
    }

    #[tokio::test]
    async fn a_same_named_store_under_a_directory_the_sandbox_cannot_list_is_ordinary() {
        // `~/unlisted/.ssh` is not `~/.ssh`: a toggle protects the location
        // under the configured home, not every directory that shares its name.
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&["unlisted/.ssh/id_ed25519", "unlisted/open.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let _unlisted = Unlisted::new(root.join("unlisted"));
            let sandbox =
                start(toggled(strict, writable).readable(fixtures::resolved(&root))).await;
            let what = format!("strict={strict} writable={writable}");

            cat(&sandbox, &root, "unlisted/open.txt")
                .await
                .unwrap_or_else(|error| panic!("{what}: the directory is not reachable: {error}"));
            cat(&sandbox, &root, "unlisted/.ssh/id_ed25519")
                .await
                .unwrap_or_else(|error| panic!("{what}: a same-named store was denied: {error}"));
        }
    }

    #[tokio::test]
    async fn a_store_and_the_directory_leading_to_it_cannot_be_renamed_to_a_readable_name() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[
                ".ssh/id_ed25519",
                ".cargo/credentials.toml",
                ".netrc",
                "notes.txt",
            ]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for script in [
                format!("mv '{at}/.ssh' '{at}/x' && cat '{at}/x/id_ed25519'"),
                format!("mv '{at}/.cargo' '{at}/c' && cat '{at}/c/credentials.toml'"),
                format!("mv '{at}/.cargo/credentials.toml' '{at}/c.toml' && cat '{at}/c.toml'"),
                format!("mv '{at}/.netrc' '{at}/n' && cat '{at}/n'"),
                format!("rm -r '{at}/.ssh' && cat '{at}/.ssh/id_ed25519'"),
            ] {
                is_refused(&sandbox, &script, &what).await;
            }
            for kept in [".ssh/id_ed25519", ".cargo/credentials.toml", ".netrc"] {
                assert!(
                    root.join(kept).exists(),
                    "{what}: {kept} was moved or removed"
                );
            }
            assert!(
                !root.join("x").exists() && !root.join("c").exists(),
                "{what}"
            );
        }
    }

    #[tokio::test]
    async fn a_link_cannot_be_planted_at_a_protected_name() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&["notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for (plant, script) in [
                (".netrc", format!("ln -s notes.txt '{at}/.netrc'")),
                (".npmrc", format!("echo x > '{at}/.npmrc'")),
                (".pypirc", format!("ln '{at}/notes.txt' '{at}/.pypirc'")),
                (".aws", format!("mkdir '{at}/.aws'")),
                (".ssh", format!("ln -s '{at}' '{at}/.ssh'")),
                (".gem", format!("ln -s '{at}' '{at}/.gem'")),
                (".gem", format!("echo x > '{at}/.gem'")),
                (
                    ".netrc",
                    format!("cp '{at}/notes.txt' '{at}/n' && mv '{at}/n' '{at}/.netrc'"),
                ),
            ] {
                let output = sh(&sandbox, &script).await;
                assert!(
                    !output.status.success(),
                    "{what}: `{script}` planted {plant}"
                );
                assert!(
                    std::fs::symlink_metadata(root.join(plant)).is_err(),
                    "{what}: `{script}` left {plant} behind"
                );
                std::fs::remove_file(root.join("n")).ok();
            }

            // A directory above a store cannot be made at all: SBPL cannot tell
            // a `mkdir` from a prepared tree moved into the name, so the name
            // itself is closed under the configured home.
            is_refused(&sandbox, &format!("mkdir '{at}/.cargo'"), &what).await;
            is_refused(
                &sandbox,
                &format!("echo x > '{at}/.cargo/credentials.toml'"),
                &what,
            )
            .await;
            assert!(!root.join(".cargo/credentials.toml").exists(), "{what}");

            // What the host then writes at those names is not readable.
            std::fs::write(root.join(".netrc"), "secret").unwrap();
            cat(&sandbox, &root, ".netrc")
                .await
                .expect_err(&format!("{what}: the host's .netrc was readable"));
        }
    }

    #[tokio::test]
    async fn a_prepared_directory_cannot_be_moved_into_a_guarded_name() {
        // The directory was populated under an ordinary name; renaming it into
        // the guarded name plants its entries at the protected name without a
        // single create the rules could refuse.
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&["seed.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for plant in [
                format!(
                    "mkdir '{at}/z' && ln '{at}/seed.txt' '{at}/z/credentials.toml' \
                     && mv '{at}/z' '{at}/.cargo'"
                ),
                format!(
                    "mkdir '{at}/z' && ln -s '{at}/seed.txt' '{at}/z/credentials.toml' \
                     && mv '{at}/z' '{at}/.cargo'"
                ),
            ] {
                is_refused(&sandbox, &plant, &what).await;
            }
            assert!(!root.join(".cargo").exists(), "{what}");
            assert!(root.join("z").exists(), "{what}");

            // And the store the host then makes itself is still not readable.
            std::fs::create_dir(root.join(".cargo")).unwrap();
            std::fs::write(root.join(".cargo/credentials.toml"), "secret").unwrap();
            cat(&sandbox, &root, ".cargo/credentials.toml")
                .await
                .expect_err(&format!("{what}: the host's store was readable"));
        }
    }

    #[tokio::test]
    async fn a_protected_location_cannot_escape_by_renaming_an_ancestor() {
        // Home and every directory above a denied path are guarded, so none of
        // them can be moved out from under a rule that names a descendant.
        for (strict, writable) in TOGGLE_MODES {
            // `.config/gh` and the embedder's `secrets` are denied trees only:
            // unlike a toggle name, their rule matches by absolute path, so a
            // renamed ancestor is the whole bypass.
            let home = home_with(&[".config/gh/hosts.yml", "work/config/secrets/token"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(
                home_granted(strict, writable, &root).read_denylist(
                    ReadDenylist::credentials()
                        .home(&root)
                        .deny(root.join("work/config/secrets")),
                ),
            )
            .await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for script in [
                // The home directory stand-in itself, an ancestor of every
                // denied path.
                format!("mv '{at}' '{at}2' && cat '{at}2/.config/gh/hosts.yml'"),
                // The directories above the embedder's denied path: the granted
                // tree's root, then the denied path's own parent.
                format!("mv '{at}/work' '{at}/w' && cat '{at}/w/config/secrets/token'"),
                format!("mv '{at}/work/config' '{at}/work/c' && cat '{at}/work/c/secrets/token'"),
            ] {
                is_refused(&sandbox, &script, &what).await;
            }

            // An ancestor above the configured home is guarded too: moving the
            // stand-in's parent would put the whole table under a new name. Only
            // the fully-writable shape can even attempt it.
            if writable {
                let parent = root.parent().unwrap().display();
                let name = root.file_name().unwrap().to_string_lossy();
                is_refused(
                    &sandbox,
                    &format!(
                        "mv '{parent}' '{parent}2' && cat '{parent}2/{name}/.config/gh/hosts.yml'"
                    ),
                    &what,
                )
                .await;
            }

            assert!(
                root.join(".config/gh/hosts.yml").exists()
                    && root.join("work/config/secrets/token").exists(),
                "{what}: an ancestor was moved"
            );
            assert!(!root.join("work/c").exists(), "{what}");
        }
    }

    #[tokio::test]
    async fn an_existing_protected_file_cannot_be_overwritten() {
        // Planting is not the only change: writing into a file the store already
        // holds replaces its contents just as surely.
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[".ssh/id_ed25519", ".netrc", ".docker/config.json"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for script in [
                format!("echo evil >> '{at}/.ssh/id_ed25519'"),
                format!("echo x > '{at}/.netrc'"),
                format!("echo x > '{at}/.docker/config.json'"),
            ] {
                is_refused(&sandbox, &script, &what).await;
            }
            for kept in [".ssh/id_ed25519", ".netrc", ".docker/config.json"] {
                assert_eq!(
                    std::fs::read_to_string(root.join(kept)).unwrap(),
                    "secret",
                    "{what}: {kept} was changed"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_prepared_git_directory_cannot_be_moved_into_a_repo() {
        // `.git` and the directories above the user-site packages are guarded
        // names too: a prepared tree moved into one is a create at the name.
        let home = home_with(&["repo/src/lib.rs"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        std::fs::create_dir(root.join(".local")).unwrap();
        let sandbox = start(
            SandboxConfigBuilder::default()
                .writable(fixtures::resolved(&root))
                .write_denylist(WriteDenylist::persistence().home(&root)),
        )
        .await;
        let at = root.display();

        for script in [
            format!("mkdir '{at}/z' && mkdir '{at}/z/hooks' && mv '{at}/z' '{at}/repo/.git'"),
            format!("mkdir '{at}/prepared' && mv '{at}/prepared' '{at}/.local/lib'"),
        ] {
            let output = sh(&sandbox, &script).await;
            assert!(!output.status.success(), "{script}");
        }
        assert!(!root.join("repo/.git").exists());
        assert!(!root.join(".local/lib").exists());
    }

    #[tokio::test]
    async fn a_read_only_grant_inside_a_store_does_not_open_it_for_writing() {
        // A grant that reads a credential store opens exactly that: writes,
        // renames and new entries under it stay denied.
        let home = home_with(&[".ssh/id_ed25519"]);
        let root = std::fs::canonicalize(home.path()).unwrap();
        let sandbox = start(
            toggled(false, true)
                .readable(fixtures::resolved(root.join(".ssh")))
                .read_denylist(ReadDenylist::credentials().home(&root)),
        )
        .await;
        let at = root.display();

        cat(&sandbox, &root, ".ssh/id_ed25519")
            .await
            .expect("the readable grant opens the file");

        for script in [
            format!("echo x > '{at}/.ssh/new_key'"),
            format!("echo x >> '{at}/.ssh/id_ed25519'"),
            format!("mv '{at}/.ssh' '{at}/x'"),
        ] {
            is_refused(&sandbox, &script, "read-only grant").await;
        }
        assert_eq!(
            std::fs::read_to_string(root.join(".ssh/id_ed25519")).unwrap(),
            "secret"
        );
    }

    #[tokio::test]
    async fn a_guarded_directory_cannot_have_its_attributes_changed() {
        // Renames and creates are not the whole of a change: flags and modes
        // on a guarded directory are refused as well.
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[".ssh/id_ed25519"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            for script in [
                format!("chmod 777 '{at}'"),
                format!("chflags uchg '{at}/.ssh'"),
                format!("xattr -w k v '{at}/.ssh'"),
            ] {
                is_refused(&sandbox, &script, &what).await;
            }
        }
    }

    #[tokio::test]
    async fn the_same_name_outside_the_configured_home_stays_ordinary() {
        // Reads stay protected wherever a name matches, but a project's `.cargo`
        // or `.npmrc` is the sandbox's to create, change, remove and rename.
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&["project/src/lib.rs"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            succeeds(
                &sandbox,
                &format!(
                    "mkdir '{at}/project/.cargo' && echo x > '{at}/project/.npmrc' \
                     && mkdir '{at}/project/.docker' && mv '{at}/project/.docker' '{at}/project/d' \
                     && echo x > '{at}/project/.cargo/config.toml' \
                     && rm '{at}/project/.npmrc' && rmdir '{at}/project/.cargo' 2>/dev/null; \
                     rm -r '{at}/project/.cargo' '{at}/project/d'"
                ),
            )
            .await;
            assert!(
                !root.join("project/.cargo").exists() && !root.join("project/d").exists(),
                "{what}"
            );

            // A same-named file inside the home but off the protected path is
            // ordinary too: `~/project/.netrc` is not `~/.netrc`.
            std::fs::write(root.join("project/.netrc"), "secret").unwrap();
            cat(&sandbox, &root, "project/.netrc")
                .await
                .unwrap_or_else(|error| panic!("{what}: a same-named file was denied: {error}"));
        }
    }

    #[tokio::test]
    async fn a_grant_naming_a_store_opens_exactly_it_for_reading_and_writing() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[".ssh/id_ed25519", ".aws/credentials", "notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(
                toggled(strict, writable)
                    .readable(fixtures::resolved(&root))
                    .writable(fixtures::resolved(root.join(".ssh")))
                    .read_denylist(ReadDenylist::credentials().home(&root)),
            )
            .await;
            let what = format!("strict={strict} writable={writable}");
            let at = root.display();

            let printed = succeeds(
                &sandbox,
                &format!(
                    "cat '{at}/.ssh/id_ed25519' && echo made > '{at}/.ssh/known_hosts' \
                     && cat '{at}/.ssh/known_hosts' && mv '{at}/.ssh/known_hosts' '{at}/.ssh/kept' \
                     && cat '{at}/.ssh/kept'"
                ),
            )
            .await;
            assert_eq!(printed, "secretmade\nmade", "{what}");
            cat(&sandbox, &root, ".aws/credentials")
                .await
                .expect_err(&format!("{what}: the grant opened another store"));
            is_refused(
                &sandbox,
                &format!("mv '{at}/.aws' '{at}/x' && cat '{at}/x/credentials'"),
                &what,
            )
            .await;
        }
    }

    #[tokio::test]
    async fn files_the_sandbox_creates_under_a_granted_directory_stay_readable_and_writable() {
        for (strict, writable) in TOGGLE_MODES {
            let home = home_with(&[".ssh/id_ed25519", "notes.txt"]);
            let root = std::fs::canonicalize(home.path()).unwrap();
            let sandbox = start(home_granted(strict, writable, &root)).await;
            let at = root.display();

            let printed = succeeds(
                &sandbox,
                &format!(
                    "mkdir '{at}/made' && echo a > '{at}/made/f' && echo b >> '{at}/made/f' \
                     && cat '{at}/made/f' && echo c > '{at}/top.txt' && cat '{at}/top.txt' \
                     && mv '{at}/top.txt' '{at}/moved.txt' && cat '{at}/moved.txt' \
                     && ln -s moved.txt '{at}/alias' && cat '{at}/alias' && ls '{at}' > /dev/null \
                     && rm '{at}/alias' '{at}/moved.txt'"
                ),
            )
            .await;
            assert_eq!(
                printed, "a\nb\nc\nc\nc",
                "strict={strict} writable={writable}"
            );
        }
    }
}

#[cfg(windows)]
#[tokio::test]
async fn a_denylist_on_a_platform_that_cannot_enforce_it_fails_at_construction() {
    let home = fixtures::tempdir();
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
            matches!(error, heel::Error::UnsupportedSetting { .. }),
            "{error:?}"
        );
    }
}
