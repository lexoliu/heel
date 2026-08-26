//! Seccomp BPF filter generation for the Linux sandbox.
//!
//! Landlock governs files and TCP connections; seccomp covers what is left:
//! socket families Landlock does not see, and syscalls that could be used to
//! escape or to attack the host.

use std::collections::BTreeMap;

use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};

use crate::error::{Error, Result};

/// Compiled filters, ready to be applied after fork.
///
/// Two programs rather than one, because a `SeccompFilter` carries a single
/// action for everything it matches and `clone3` needs a different one. Their
/// rule sets are disjoint, so each returns `Allow` wherever the other decides
/// and the kernel's "most restrictive result wins" leaves no ambiguity.
pub(crate) struct PreparedFilter {
    programs: Vec<seccompiler::BpfProgram>,
}

impl PreparedFilter {
    /// Install the filters on the current process. Called from `pre_exec`.
    ///
    /// Safe to call there: the programs are compiled before forking, so this
    /// only issues `prctl` and `seccomp` syscalls.
    pub(crate) fn apply(self) -> std::io::Result<()> {
        for program in &self.programs {
            seccompiler::apply_filter(program).map_err(seccomp_error_to_io)?;
        }
        Ok(())
    }
}

fn seccomp_error_to_io(error: seccompiler::Error) -> std::io::Error {
    match error {
        seccompiler::Error::Prctl(source) | seccompiler::Error::Seccomp(source) => source,
        seccompiler::Error::EmptyFilter => std::io::Error::from_raw_os_error(libc::EINVAL),
        seccompiler::Error::ThreadSync(_) => std::io::Error::from_raw_os_error(libc::EIO),
        other => std::io::Error::other(format!("seccomp apply_filter failed: {other}")),
    }
}

/// Build the filter for a sandbox configuration.
///
/// `allow_tcp` is true when the sandbox has a proxy or an IPC endpoint to reach;
/// when false, TCP sockets cannot be created at all.
pub(crate) fn build_filter(allow_tcp: bool) -> Result<PreparedFilter> {
    let arch = detect_arch()?;

    // Default-allow with explicit blocks. A default-deny filter would need a
    // complete allow list for every runtime a sandbox might host, which is not
    // maintainable; the kernel-level isolation comes from Landlock instead.
    let denied = compile(
        build_rules(allow_tcp)?,
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )?;

    // `clone3` cannot be filtered by flags: its arguments live behind a struct
    // pointer that seccomp cannot dereference, so it has to be refused outright
    // or it would be a way around the flag checks on `clone`.
    //
    // It must be refused with ENOSYS, not EPERM. glibc issues `clone3` first for
    // every thread it creates and falls back to `clone` only on ENOSYS; any
    // other error is fatal, so EPERM here stops a sandboxed process from
    // creating threads at all. Refusing it this way keeps the namespace path
    // closed, since the fallback lands on `clone`, which is filtered.
    let unsupported = compile(
        BTreeMap::from([(libc::SYS_clone3, Vec::new())]),
        SeccompAction::Errno(libc::ENOSYS as u32),
        arch,
    )?;

    tracing::debug!(allow_tcp, "seccomp: filters built");

    Ok(PreparedFilter {
        programs: vec![denied, unsupported],
    })
}

/// Compile one rule set into a BPF program.
///
/// Syscalls with no rule are allowed: a default-deny filter would need a
/// complete allow list for every runtime a sandbox might host, which is not
/// maintainable. The kernel-level isolation comes from Landlock instead.
fn compile(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    matched: SeccompAction,
    arch: TargetArch,
) -> Result<seccompiler::BpfProgram> {
    SeccompFilter::new(rules, SeccompAction::Allow, matched, arch)
        .map_err(|e| Error::InvalidProfile(format!("seccomp filter error: {e:?}")))?
        .try_into()
        .map_err(|e| Error::InvalidProfile(format!("seccomp BPF compilation error: {e:?}")))
}

fn detect_arch() -> Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    return Ok(TargetArch::x86_64);

    #[cfg(target_arch = "aarch64")]
    return Ok(TargetArch::aarch64);

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    Err(Error::UnsupportedPlatform)
}

fn build_rules(allow_tcp: bool) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    rules.insert(libc::SYS_socket, socket_rules(allow_tcp)?);
    rules.insert(libc::SYS_clone, namespace_clone_rules()?);
    // `clone3` is refused by its own filter, with a different error; see
    // `build_filter`.

    add_dangerous_syscall_blocks(&mut rules);

    Ok(rules)
}

/// Socket families and types the sandbox refuses to create.
///
/// Landlock only governs TCP connections, so datagram and raw sockets have to
/// be stopped here or they would bypass the network policy entirely. Unix
/// sockets stay available for IPC.
fn socket_rules(allow_tcp: bool) -> Result<Vec<SeccompRule>> {
    /// Flags that may be OR-ed into the socket type argument.
    ///
    /// Seccomp cannot mask an argument before comparing it, so every
    /// combination is enumerated; missing one would leave a way to create the
    /// socket this filter is meant to block.
    const TYPE_FLAGS: [i32; 4] = [
        0,
        libc::SOCK_NONBLOCK,
        libc::SOCK_CLOEXEC,
        libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
    ];

    const INET_DOMAINS: [i32; 2] = [libc::AF_INET, libc::AF_INET6];

    let mut blocked_types = vec![libc::SOCK_DGRAM, libc::SOCK_RAW];
    if !allow_tcp {
        blocked_types.push(libc::SOCK_STREAM);
    }

    // Packet sockets can read and forge raw frames; no configuration needs them.
    let mut rules = vec![rule(&[(0, libc::AF_PACKET as u64)])?];

    for domain in INET_DOMAINS {
        for socket_type in &blocked_types {
            for flags in TYPE_FLAGS {
                rules.push(rule(&[
                    (0, domain as u64),
                    (1, (socket_type | flags) as u64),
                ])?);
            }
        }
    }

    Ok(rules)
}

/// Block `clone` calls that would create a new user namespace.
///
/// `unshare` is blocked outright below, but `clone(CLONE_NEWUSER)` reaches the
/// same capability-granting namespace by another path.
fn namespace_clone_rules() -> Result<Vec<SeccompRule>> {
    let flags = libc::CLONE_NEWUSER as u64;
    let condition = SeccompCondition::new(
        0,
        SeccompCmpArgLen::Qword,
        SeccompCmpOp::MaskedEq(flags),
        flags,
    )
    .map_err(|e| Error::InvalidProfile(format!("seccomp condition error: {e:?}")))?;

    Ok(vec![SeccompRule::new(vec![condition]).map_err(|e| {
        Error::InvalidProfile(format!("seccomp rule error: {e:?}"))
    })?])
}

/// Build a rule matching on the given `(argument index, value)` equalities.
fn rule(conditions: &[(u8, u64)]) -> Result<SeccompRule> {
    let conditions = conditions
        .iter()
        .map(|&(index, value)| {
            SeccompCondition::new(index, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, value)
                .map_err(|e| Error::InvalidProfile(format!("seccomp condition error: {e:?}")))
        })
        .collect::<Result<Vec<_>>>()?;

    SeccompRule::new(conditions)
        .map_err(|e| Error::InvalidProfile(format!("seccomp rule error: {e:?}")))
}

/// Syscalls a sandboxed process has no legitimate use for.
fn add_dangerous_syscall_blocks(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) {
    // An empty rule list matches on the syscall number alone.
    const BLOCKED: &[i64] = &[
        // Debugging and cross-process memory access.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Kernel modules.
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        // Execution domain changes, which can disable ASLR.
        libc::SYS_personality,
        // Mounts.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        // Namespaces.
        libc::SYS_unshare,
        libc::SYS_setns,
        // Power management.
        libc::SYS_reboot,
        libc::SYS_kexec_load,
        libc::SYS_kexec_file_load,
        // Privilege changes.
        libc::SYS_setuid,
        libc::SYS_setgid,
        libc::SYS_setreuid,
        libc::SYS_setregid,
        libc::SYS_setresuid,
        libc::SYS_setresgid,
        libc::SYS_setgroups,
        // Kernel keyring.
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_keyctl,
        // BPF, which could install filters of its own.
        libc::SYS_bpf,
        // Common exploit primitives.
        libc::SYS_userfaultfd,
        libc::SYS_perf_event_open,
        // io_uring submits file and socket operations through a ring buffer
        // that seccomp does not inspect, so leaving it available would let a
        // sandboxed process reach every syscall blocked above.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Clock and accounting.
        libc::SYS_settimeofday,
        libc::SYS_clock_settime,
        libc::SYS_adjtimex,
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_quotactl,
        libc::SYS_acct,
    ];

    for syscall in BLOCKED {
        rules.insert(*syscall, Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_is_supported() {
        assert!(detect_arch().is_ok());
    }

    #[test]
    fn filters_compile_in_both_network_modes() {
        for allow_tcp in [false, true] {
            let filter = build_filter(allow_tcp).expect("builds");
            assert!(filter.programs.iter().all(|program| !program.is_empty()));
        }
    }

    #[test]
    fn datagram_and_raw_sockets_are_always_blocked() {
        let rules = socket_rules(true).expect("builds");
        // One AF_PACKET rule, plus every flag combination of the two blocked
        // types across both inet domains.
        assert_eq!(rules.len(), 1 + 2 * 2 * 4);
    }

    #[test]
    fn tcp_is_blocked_only_when_nothing_needs_it() {
        let permissive = socket_rules(true).expect("builds").len();
        let restrictive = socket_rules(false).expect("builds").len();
        assert_eq!(
            restrictive - permissive,
            2 * 4,
            "TCP rules for both domains"
        );
    }

    #[test]
    fn io_uring_is_blocked_regardless_of_configuration() {
        // io_uring bypasses seccomp entirely, so it must never depend on a
        // hardware or convenience toggle.
        let rules = build_rules(true).expect("builds");
        for syscall in [
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(rules.contains_key(&syscall), "io_uring must be blocked");
        }
    }

    #[test]
    fn namespace_creation_is_blocked_through_both_paths() {
        let rules = build_rules(true).expect("builds");
        assert!(rules.contains_key(&libc::SYS_unshare));
        assert!(rules.contains_key(&libc::SYS_clone));
        assert!(
            !rules[&libc::SYS_clone].is_empty(),
            "clone must be filtered by flags, not blocked outright"
        );
    }

    #[test]
    fn clone3_is_refused_separately_from_everything_else() {
        // It must not share the general EPERM filter: glibc issues `clone3` for
        // every thread it creates and falls back to `clone` only on ENOSYS, so
        // refusing it with EPERM stops a sandboxed process from threading.
        assert!(
            !build_rules(true)
                .expect("builds")
                .contains_key(&libc::SYS_clone3),
            "clone3 belongs to its own ENOSYS filter"
        );
        assert_eq!(
            build_filter(true).expect("builds").programs.len(),
            2,
            "the general filter and the clone3 filter are installed separately"
        );
    }
}
