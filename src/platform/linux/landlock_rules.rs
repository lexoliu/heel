//! Landlock ruleset generation for Linux sandbox
//!
//! Landlock provides kernel-level filesystem and network access control.
//! We use Landlock ABI v4 which supports:
//! - Filesystem access control (read, write, execute, etc.)
//! - Network TCP connection restrictions

use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd};
use std::path::{Path, PathBuf};

use landlock::{
    ABI, Access, AccessFs, AccessNet, BitFlags, NetPort, PathBeneath, PathFd, RestrictSelfError,
    Ruleset, RulesetAttr, RulesetCreated, RulesetCreatedAttr, RulesetError, RulesetStatus,
    make_bitflags,
};

use crate::config::SandboxConfigData;
use crate::error::{Error, Result};
use crate::security::SecurityConfig;

/// Minimal config snapshot for building Landlock rulesets
#[derive(Clone)]
pub struct LandlockConfig {
    security: SecurityConfig,
    writable_paths: Vec<PathBuf>,
    readable_paths: Vec<PathBuf>,
    executable_paths: Vec<PathBuf>,
    network_deny_all: bool,
    ipc_port: Option<u16>,
    python_venv_path: Option<PathBuf>,
    working_dir: PathBuf,
    filesystem_strict: bool,
    writable_file_system: bool,
}

impl LandlockConfig {
    pub fn from_config(config: &SandboxConfigData) -> Self {
        Self {
            security: config.security().clone(),
            writable_paths: config.writable_paths().to_vec(),
            readable_paths: config.readable_paths().to_vec(),
            executable_paths: config.executable_paths().to_vec(),
            network_deny_all: config.network_deny_all(),
            ipc_port: config.ipc_port(),
            python_venv_path: config.python().map(|p| p.venv().path().to_path_buf()),
            working_dir: config.working_dir().to_path_buf(),
            filesystem_strict: config.filesystem_strict(),
            writable_file_system: config.writable_file_system(),
        }
    }

    pub fn security(&self) -> &SecurityConfig {
        &self.security
    }

    pub fn writable_paths(&self) -> &[PathBuf] {
        &self.writable_paths
    }

    pub fn readable_paths(&self) -> &[PathBuf] {
        &self.readable_paths
    }

    pub fn executable_paths(&self) -> &[PathBuf] {
        &self.executable_paths
    }

    pub fn network_deny_all(&self) -> bool {
        self.network_deny_all
    }

    pub fn ipc_port(&self) -> Option<u16> {
        self.ipc_port
    }

    pub fn python_venv_path(&self) -> Option<&Path> {
        self.python_venv_path.as_deref()
    }

    pub fn working_dir(&self) -> &Path {
        &self.working_dir
    }

    pub fn filesystem_strict(&self) -> bool {
        self.filesystem_strict
    }

    pub fn writable_file_system(&self) -> bool {
        self.writable_file_system
    }
}

/// A prepared Landlock ruleset ready to be applied in pre_exec
pub struct PreparedRuleset {
    inner: RulesetCreated,
}

impl PreparedRuleset {
    /// Apply the ruleset to the current process (call in pre_exec)
    ///
    /// Fails fast if the ruleset is not fully enforced.
    pub fn restrict_self(self) -> std::io::Result<()> {
        let status = self.inner.restrict_self().map_err(landlock_error_to_io)?;

        // Fast-fail if not fully enforced
        match status.ruleset {
            RulesetStatus::FullyEnforced => Ok(()),
            RulesetStatus::PartiallyEnforced => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
            RulesetStatus::NotEnforced => Err(std::io::Error::from_raw_os_error(libc::EPERM)),
        }
    }
}

fn landlock_error_to_io(error: RulesetError) -> std::io::Error {
    match error {
        RulesetError::RestrictSelf(RestrictSelfError::SetNoNewPrivsCall { source, .. })
        | RulesetError::RestrictSelf(RestrictSelfError::RestrictSelfCall { source, .. }) => source,
        other => std::io::Error::other(format!("Landlock restrict_self failed: {other}")),
    }
}

/// Build a Landlock ruleset from sandbox configuration
pub fn build_ruleset(config: &LandlockConfig, proxy_port: u16) -> Result<PreparedRuleset> {
    // We require ABI v4 for network restrictions
    let abi = ABI::V4;

    // Start with all filesystem access rights handled (deny by default)
    let fs_access = AccessFs::from_all(abi);
    let net_access = AccessNet::ConnectTcp;

    let mut ruleset = Ruleset::default()
        .handle_access(fs_access)
        .map_err(|e| Error::InvalidProfile(format!("Landlock fs access error: {}", e)))?;

    if !config.network_deny_all() || config.ipc_port().is_some() {
        ruleset = ruleset
            .handle_access(net_access)
            .map_err(|e| Error::InvalidProfile(format!("Landlock net access error: {}", e)))?;
    }

    let mut ruleset = ruleset
        .create()
        .map_err(|e| Error::InvalidProfile(format!("Landlock ruleset create error: {}", e)))?;

    // --- System paths (read + execute for binaries/libraries) ---
    // These paths need both read and execute for running programs
    let system_exec_paths: &[&str] = if config.filesystem_strict() {
        &[
            "/bin",
            "/sbin",
            "/usr/bin",
            "/usr/sbin",
            "/usr/lib",
            "/usr/lib64",
            "/usr/lib32",
            "/lib",
            "/lib64",
            "/lib32",
            "/usr/libexec",
            "/usr/local",
        ]
    } else {
        &["/usr", "/lib", "/lib64", "/lib32", "/bin", "/sbin"]
    };
    let system_exec_access = make_bitflags!(AccessFs::{
        ReadFile | ReadDir | Execute
    });

    for path in system_exec_paths {
        add_path_rule(&mut ruleset, path, system_exec_access, abi)?;
    }

    // System config and pseudo-filesystems (read-only, no execute needed)
    //
    // These are required even in strict mode:
    // - dynamic loaders and libc consult files under /etc
    // - procfs/sysfs expose kernel and process metadata many tools rely on
    // - /run holds runtime resolver and system state
    //
    // They remain read-only, so strict mode still blocks writes and user-owned secrets.
    let system_read_paths = ["/etc", "/proc", "/sys", "/run"];

    for path in &system_read_paths {
        add_path_rule(&mut ruleset, path, AccessFs::from_read(abi), abi)?;
    }

    // --- Temp directories (read + write) ---
    let temp_paths = ["/tmp", "/var/tmp"];
    for path in &temp_paths {
        add_path_rule(&mut ruleset, path, AccessFs::from_all(abi), abi)?;
    }

    // --- Device access ---
    add_device_rules(&mut ruleset, config.security(), abi)?;

    // --- Working directory (full access) ---
    add_path_rule(
        &mut ruleset,
        config.working_dir(),
        AccessFs::from_all(abi),
        abi,
    )?;

    // --- User-configured paths ---

    // Readable paths
    for path in config.readable_paths() {
        add_path_rule(&mut ruleset, path, AccessFs::from_read(abi), abi)?;
    }

    // Writable paths
    for path in config.writable_paths() {
        add_path_rule(&mut ruleset, path, AccessFs::from_all(abi), abi)?;
    }

    // Executable paths (read + execute)
    for path in config.executable_paths() {
        let exec_access = make_bitflags!(AccessFs::{ReadFile | Execute});
        add_path_rule(&mut ruleset, path, exec_access, abi)?;
    }

    // --- Python venv if configured ---
    if let Some(venv_path) = config.python_venv_path() {
        add_path_rule(&mut ruleset, venv_path, AccessFs::from_all(abi), abi)?;
    }

    // --- Global Write Access (Permissive Mode) ---
    if config.writable_file_system() {
        add_path_rule(&mut ruleset, "/", AccessFs::from_all(abi), abi)?;
    }

    // --- Apply security restrictions ---
    // Note: Landlock is additive-only, so we implement restrictions by
    // NOT adding rules for protected paths. Since we only add specific
    // allowed paths above, sensitive paths are denied by default.
    //
    // However, if protect_user_home is false, we need to add home access
    apply_security_config(&mut ruleset, config.security(), abi)?;

    // --- Network: Only allow TCP connections to proxy port ---
    if !config.network_deny_all() {
        ruleset = ruleset
            .add_rule(NetPort::new(proxy_port, AccessNet::ConnectTcp))
            .map_err(|e| Error::InvalidProfile(format!("Landlock network rule error: {}", e)))?;
    }
    if let Some(ipc_port) = config.ipc_port() {
        ruleset = ruleset
            .add_rule(NetPort::new(ipc_port, AccessNet::ConnectTcp))
            .map_err(|e| Error::InvalidProfile(format!("Landlock IPC rule error: {}", e)))?;
    }

    tracing::debug!(
        proxy_port = proxy_port,
        ipc_port = config.ipc_port(),
        working_dir = %config.working_dir().display(),
        "landlock: ruleset built"
    );

    Ok(PreparedRuleset { inner: ruleset })
}

/// Add a path rule to the ruleset, handling non-existent paths gracefully
fn add_path_rule(
    ruleset: &mut RulesetCreated,
    path: impl AsRef<Path>,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<()> {
    let path = path.as_ref();

    match PathFd::new(path) {
        Ok(path_fd) => {
            let effective_access = effective_path_access(&path_fd, path, access, abi)?;

            if let Err(e) = ruleset.add_rule(PathBeneath::new(path_fd, effective_access)) {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "landlock: failed to add path rule"
                );
            } else {
                tracing::trace!(path = %path.display(), "landlock: added path rule");
            }
        }
        Err(e) => {
            // Path doesn't exist - this is not an error, just skip
            tracing::trace!(
                path = %path.display(),
                error = %e,
                "landlock: skipping non-existent path"
            );
        }
    }
    Ok(())
}

fn effective_path_access(
    path_fd: &PathFd,
    path: &Path,
    access: BitFlags<AccessFs>,
    abi: ABI,
) -> Result<BitFlags<AccessFs>> {
    if path_is_directory(path_fd)? {
        return Ok(access);
    }

    let file_access = access & AccessFs::from_file(abi);
    if file_access.is_empty() {
        return Err(Error::InvalidProfile(format!(
            "Landlock path {} is not a directory, but requested access {:?} requires directory semantics",
            path.display(),
            access,
        )));
    }

    if file_access != access {
        tracing::trace!(
            path = %path.display(),
            requested_access = ?access,
            effective_access = ?file_access,
            "landlock: narrowed non-directory path access"
        );
    }

    Ok(file_access)
}

fn path_is_directory(path_fd: &PathFd) -> Result<bool> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let rc = unsafe { libc::fstat(path_fd.as_fd().as_raw_fd(), stat.as_mut_ptr()) };
    if rc != 0 {
        return Err(Error::InvalidProfile(format!(
            "Landlock failed to inspect rule path: {}",
            std::io::Error::last_os_error(),
        )));
    }

    let stat = unsafe { stat.assume_init() };
    Ok((stat.st_mode & libc::S_IFMT) == libc::S_IFDIR)
}

/// Add device access rules
fn add_device_rules(
    ruleset: &mut RulesetCreated,
    security: &SecurityConfig,
    abi: ABI,
) -> Result<()> {
    // Basic device access for stdio and randomness
    // Note: /dev/stdin, /dev/stdout, /dev/stderr are symlinks to /proc/self/fd/*
    // and can't be added as Landlock rules. They work via inherited file descriptors.
    let basic_devices = [
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/random",
        "/dev/urandom",
        "/dev/fd",
        "/dev/tty",
        "/dev/ptmx",
        "/dev/pts",
    ];

    for device in &basic_devices {
        add_path_rule(ruleset, device, AccessFs::from_all(abi), abi)?;
    }

    // GPU access (/dev/dri for DRM)
    if security.allow_gpu {
        add_path_rule(ruleset, "/dev/dri", AccessFs::from_all(abi), abi)?;
        // NVIDIA devices
        add_path_rule(ruleset, "/dev/nvidia0", AccessFs::from_all(abi), abi)?;
        add_path_rule(ruleset, "/dev/nvidiactl", AccessFs::from_all(abi), abi)?;
        add_path_rule(ruleset, "/dev/nvidia-modeset", AccessFs::from_all(abi), abi)?;
        add_path_rule(ruleset, "/dev/nvidia-uvm", AccessFs::from_all(abi), abi)?;
        tracing::debug!("landlock: GPU access enabled");
    }

    // NPU access (/dev/accel for Intel/AMD accelerators)
    if security.allow_npu {
        add_path_rule(ruleset, "/dev/accel", AccessFs::from_all(abi), abi)?;
        // Intel NPU
        add_path_rule(ruleset, "/dev/accel0", AccessFs::from_all(abi), abi)?;
        tracing::debug!("landlock: NPU access enabled");
    }

    // General hardware access
    if security.allow_hardware {
        // USB devices
        add_path_rule(ruleset, "/dev/bus/usb", AccessFs::from_all(abi), abi)?;
        // Input devices
        add_path_rule(ruleset, "/dev/input", AccessFs::from_all(abi), abi)?;
        // Video devices (webcams)
        add_path_rule(ruleset, "/dev/video0", AccessFs::from_all(abi), abi)?;
        add_path_rule(ruleset, "/dev/video1", AccessFs::from_all(abi), abi)?;
        // Audio devices
        add_path_rule(ruleset, "/dev/snd", AccessFs::from_all(abi), abi)?;
        tracing::debug!("landlock: general hardware access enabled");
    }

    Ok(())
}

/// Apply SecurityConfig by adding access to home if not protected
fn apply_security_config(
    ruleset: &mut RulesetCreated,
    security: &SecurityConfig,
    abi: ABI,
) -> Result<()> {
    // Landlock is default-deny. We only need to ADD paths when protection is disabled.

    if !security.protect_user_home {
        // Allow access to home directory
        if let Ok(home) = std::env::var("HOME") {
            add_path_rule(ruleset, &home, AccessFs::from_all(abi), abi)?;
            tracing::debug!(home = %home, "landlock: home access enabled");
        }
        // Also try /home for other users
        add_path_rule(ruleset, "/home", AccessFs::from_all(abi), abi)?;
    }

    // Note: For the other protection flags (protect_credentials, protect_cloud_config, etc.),
    // since Landlock is default-deny and we're not adding those paths above,
    // they are automatically protected.
    //
    // The macOS SBPL uses explicit deny rules because SBPL has broader allow rules.
    // With Landlock, we only whitelist specific paths, so sensitive paths are denied by default.

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File};

    use rand::random;

    use super::*;

    struct TestPath {
        path: PathBuf,
    }

    impl TestPath {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "heel-landlock-rules-{}-{}",
                std::process::id(),
                random::<u64>()
            ));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestPath {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn non_directory_rules_are_narrowed_to_file_access() {
        let test_path = TestPath::new();
        fs::create_dir_all(test_path.path()).unwrap();
        let file_path = test_path.path().join("device");
        File::create(&file_path).unwrap();

        let path_fd = PathFd::new(&file_path).unwrap();
        let access =
            effective_path_access(&path_fd, &file_path, AccessFs::from_all(ABI::V4), ABI::V4)
                .unwrap();

        assert_eq!(access, AccessFs::from_file(ABI::V4));
    }

    #[test]
    fn directory_rules_keep_directory_access() {
        let test_path = TestPath::new();
        fs::create_dir_all(test_path.path()).unwrap();

        let path_fd = PathFd::new(test_path.path()).unwrap();
        let access = effective_path_access(
            &path_fd,
            test_path.path(),
            AccessFs::from_all(ABI::V4),
            ABI::V4,
        )
        .unwrap();

        assert_eq!(access, AccessFs::from_all(ABI::V4));
    }

    #[test]
    fn file_rules_reject_directory_only_access() {
        let test_path = TestPath::new();
        fs::create_dir_all(test_path.path()).unwrap();
        let file_path = test_path.path().join("file");
        File::create(&file_path).unwrap();

        let path_fd = PathFd::new(&file_path).unwrap();
        let error = effective_path_access(&path_fd, &file_path, AccessFs::ReadDir.into(), ABI::V4)
            .unwrap_err();

        assert!(matches!(error, Error::InvalidProfile(_)));
    }
}
