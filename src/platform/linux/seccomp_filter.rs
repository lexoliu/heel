//! Seccomp BPF filter generation for Linux sandbox
//!
//! Seccomp provides syscall-level filtering. We use it to:
//! 1. Block non-TCP socket creation (UDP, raw sockets) - critical for network isolation
//! 2. Block dangerous syscalls (ptrace, module loading, etc.)
//! 3. Optionally restrict hardware-related syscalls

use std::collections::BTreeMap;

use seccompiler::{
    SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule,
    TargetArch,
};

use crate::error::{Error, Result};
use crate::security::SecurityConfig;

/// A prepared Seccomp filter ready to be applied in pre_exec
pub struct PreparedFilter {
    program: seccompiler::BpfProgram,
}

impl PreparedFilter {
    /// Apply the filter to the current process (call in pre_exec)
    pub fn apply(self) -> std::io::Result<()> {
        seccompiler::apply_filter(&self.program).map_err(seccomp_error_to_io)
    }
}

fn seccomp_error_to_io(error: seccompiler::Error) -> std::io::Error {
    match error {
        seccompiler::Error::Prctl(source) | seccompiler::Error::Seccomp(source) => source,
        seccompiler::Error::EmptyFilter => std::io::Error::from_raw_os_error(libc::EINVAL),
        seccompiler::Error::ThreadSync(_) => std::io::Error::from_raw_os_error(libc::EIO),
        other => std::io::Error::other(format!("Seccomp apply_filter failed: {other}")),
    }
}

/// Build a Seccomp BPF filter from SecurityConfig
pub fn build_filter(
    security: &SecurityConfig,
    network_deny_all: bool,
    ipc_enabled: bool,
) -> Result<PreparedFilter> {
    let arch = detect_arch()?;

    // We use a default-allow policy with explicit blocks for dangerous syscalls
    // This is more practical than default-deny for a general-purpose sandbox
    let rules = build_rules(security, arch, network_deny_all, ipc_enabled)?;

    let filter = SeccompFilter::new(
        rules,
        // Default action when syscall is NOT in rules map (allow most syscalls)
        SeccompAction::Allow,
        // Action when a rule matches (block the dangerous syscall)
        SeccompAction::Errno(libc::EPERM as u32),
        arch,
    )
    .map_err(|e| Error::InvalidProfile(format!("Seccomp filter error: {:?}", e)))?;

    // Compile to BPF bytecode
    let program: seccompiler::BpfProgram = filter
        .try_into()
        .map_err(|e| Error::InvalidProfile(format!("Seccomp BPF compilation error: {:?}", e)))?;

    tracing::debug!(
        allow_hardware = security.allow_hardware,
        "seccomp: filter built"
    );

    Ok(PreparedFilter { program })
}

fn detect_arch() -> Result<TargetArch> {
    #[cfg(target_arch = "x86_64")]
    return Ok(TargetArch::x86_64);

    #[cfg(target_arch = "aarch64")]
    return Ok(TargetArch::aarch64);

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(Error::UnsupportedPlatform);
}

fn build_rules(
    security: &SecurityConfig,
    arch: TargetArch,
    network_deny_all: bool,
    ipc_enabled: bool,
) -> Result<BTreeMap<i64, Vec<SeccompRule>>> {
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();

    // --- CRITICAL: Network socket filtering ---
    // Block non-TCP socket creation to enforce complete network isolation
    add_socket_restrictions(&mut rules, arch, network_deny_all, ipc_enabled)?;

    // --- Block dangerous syscalls ---
    add_dangerous_syscall_blocks(&mut rules)?;

    // --- Hardware restrictions ---
    if !security.allow_hardware {
        add_hardware_restrictions(&mut rules)?;
    }

    Ok(rules)
}

/// Block socket creation for non-TCP protocols
///
/// This is CRITICAL for network isolation:
/// - Allow: TCP (SOCK_STREAM) over IPv4/IPv6
/// - Allow: Unix domain sockets (AF_UNIX) for local IPC
/// - Block: UDP (SOCK_DGRAM)
/// - Block: Raw sockets (SOCK_RAW)
fn add_socket_restrictions(
    rules: &mut BTreeMap<i64, Vec<SeccompRule>>,
    _arch: TargetArch,
    network_deny_all: bool,
    ipc_enabled: bool,
) -> Result<()> {
    // socket() syscall: int socket(int domain, int type, int protocol)
    // arg0 = domain (AF_INET, AF_INET6, AF_UNIX, etc.)
    // arg1 = type (SOCK_STREAM, SOCK_DGRAM, SOCK_RAW, etc.)
    // arg2 = protocol

    // We want to ALLOW:
    // - socket(AF_UNIX, *, *) - Unix domain sockets for IPC
    // - socket(AF_INET, SOCK_STREAM, *) - TCP over IPv4
    // - socket(AF_INET6, SOCK_STREAM, *) - TCP over IPv6
    //
    // We want to BLOCK (return EPERM):
    // - socket(AF_INET/AF_INET6, SOCK_DGRAM, *) - UDP
    // - socket(AF_INET/AF_INET6, SOCK_RAW, *) - Raw sockets
    // - socket(AF_PACKET, *, *) - Packet sockets

    // Strategy: Block specific dangerous combinations
    // Note: SOCK_DGRAM = 2, SOCK_RAW = 3, SOCK_STREAM = 1
    // AF_INET = 2, AF_INET6 = 10, AF_UNIX = 1, AF_PACKET = 17

    // The type field can have flags OR'd in (SOCK_NONBLOCK=0x800, SOCK_CLOEXEC=0x80000)
    // We need to mask these out: type & 0xF gives the base socket type
    // However, seccompiler doesn't support masking, so we block the common cases

    // Socket types (without flags)
    const SOCK_STREAM: u64 = libc::SOCK_STREAM as u64;
    const SOCK_DGRAM: u64 = libc::SOCK_DGRAM as u64;
    const SOCK_RAW: u64 = libc::SOCK_RAW as u64;

    // Socket types with SOCK_NONBLOCK
    const SOCK_STREAM_NONBLOCK: u64 = (libc::SOCK_STREAM | libc::SOCK_NONBLOCK) as u64;
    const SOCK_DGRAM_NONBLOCK: u64 = (libc::SOCK_DGRAM | libc::SOCK_NONBLOCK) as u64;
    const SOCK_RAW_NONBLOCK: u64 = (libc::SOCK_RAW | libc::SOCK_NONBLOCK) as u64;

    // Socket types with SOCK_CLOEXEC
    const SOCK_STREAM_CLOEXEC: u64 = (libc::SOCK_STREAM | libc::SOCK_CLOEXEC) as u64;
    const SOCK_DGRAM_CLOEXEC: u64 = (libc::SOCK_DGRAM | libc::SOCK_CLOEXEC) as u64;
    const SOCK_RAW_CLOEXEC: u64 = (libc::SOCK_RAW | libc::SOCK_CLOEXEC) as u64;

    // Socket types with both flags
    const SOCK_STREAM_BOTH: u64 =
        (libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;
    const SOCK_DGRAM_BOTH: u64 =
        (libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;
    const SOCK_RAW_BOTH: u64 = (libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC) as u64;

    // Domains
    const AF_INET: u64 = libc::AF_INET as u64;
    const AF_INET6: u64 = libc::AF_INET6 as u64;
    const AF_PACKET: u64 = libc::AF_PACKET as u64;

    // Block UDP and RAW sockets for IPv4 and IPv6
    let dgram_types = [
        SOCK_DGRAM,
        SOCK_DGRAM_NONBLOCK,
        SOCK_DGRAM_CLOEXEC,
        SOCK_DGRAM_BOTH,
    ];
    let raw_types = [SOCK_RAW, SOCK_RAW_NONBLOCK, SOCK_RAW_CLOEXEC, SOCK_RAW_BOTH];
    let stream_types = [
        SOCK_STREAM,
        SOCK_STREAM_NONBLOCK,
        SOCK_STREAM_CLOEXEC,
        SOCK_STREAM_BOTH,
    ];

    let mut socket_rules = Vec::new();

    // Block AF_PACKET entirely (raw packet sockets)
    socket_rules.push(
        SeccompRule::new(vec![
            SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_PACKET)
                .map_err(|e| Error::InvalidProfile(format!("Seccomp condition error: {:?}", e)))?,
        ])
        .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
    );

    // Block UDP sockets (AF_INET/AF_INET6 + SOCK_DGRAM variants)
    for &sock_type in &dgram_types {
        // AF_INET + SOCK_DGRAM
        socket_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
            ])
            .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
        );

        // AF_INET6 + SOCK_DGRAM
        socket_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET6)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
            ])
            .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
        );
    }

    // Block RAW sockets (AF_INET/AF_INET6 + SOCK_RAW variants)
    for &sock_type in &raw_types {
        // AF_INET + SOCK_RAW
        socket_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
            ])
            .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
        );

        // AF_INET6 + SOCK_RAW
        socket_rules.push(
            SeccompRule::new(vec![
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET6)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
                SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                    .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
            ])
            .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
        );
    }

    if network_deny_all && !ipc_enabled {
        // Block TCP sockets (AF_INET/AF_INET6 + SOCK_STREAM variants)
        for &sock_type in &stream_types {
            // AF_INET + SOCK_STREAM
            socket_rules.push(
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET)
                        .map_err(|e| {
                            Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                        })?,
                    SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                        .map_err(|e| {
                            Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                        })?,
                ])
                .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
            );

            // AF_INET6 + SOCK_STREAM
            socket_rules.push(
                SeccompRule::new(vec![
                    SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, AF_INET6)
                        .map_err(|e| {
                        Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                    })?,
                    SeccompCondition::new(1, SeccompCmpArgLen::Dword, SeccompCmpOp::Eq, sock_type)
                        .map_err(|e| {
                            Error::InvalidProfile(format!("Seccomp condition error: {:?}", e))
                        })?,
                ])
                .map_err(|e| Error::InvalidProfile(format!("Seccomp rule error: {:?}", e)))?,
            );
        }
    }

    rules.insert(libc::SYS_socket, socket_rules);

    tracing::debug!("seccomp: socket restrictions added (UDP and RAW blocked)");

    Ok(())
}

/// Block syscalls that are dangerous for sandboxed processes
fn add_dangerous_syscall_blocks(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) -> Result<()> {
    // Empty rule chains match on syscall number only.
    let block_always = || Vec::new();

    // Process debugging and manipulation
    rules.insert(libc::SYS_ptrace, block_always());
    rules.insert(libc::SYS_process_vm_readv, block_always());
    rules.insert(libc::SYS_process_vm_writev, block_always());

    // Kernel module operations
    rules.insert(libc::SYS_init_module, block_always());
    rules.insert(libc::SYS_finit_module, block_always());
    rules.insert(libc::SYS_delete_module, block_always());

    // Personality changes (can disable ASLR, etc.)
    rules.insert(libc::SYS_personality, block_always());

    // Mount operations
    rules.insert(libc::SYS_mount, block_always());
    rules.insert(libc::SYS_umount2, block_always());
    rules.insert(libc::SYS_pivot_root, block_always());

    // Namespace operations (could escape sandbox)
    rules.insert(libc::SYS_unshare, block_always());
    rules.insert(libc::SYS_setns, block_always());

    // Reboot and power management
    rules.insert(libc::SYS_reboot, block_always());
    rules.insert(libc::SYS_kexec_load, block_always());
    rules.insert(libc::SYS_kexec_file_load, block_always());

    // UID/GID manipulation (privilege escalation)
    rules.insert(libc::SYS_setuid, block_always());
    rules.insert(libc::SYS_setgid, block_always());
    rules.insert(libc::SYS_setreuid, block_always());
    rules.insert(libc::SYS_setregid, block_always());
    rules.insert(libc::SYS_setresuid, block_always());
    rules.insert(libc::SYS_setresgid, block_always());
    rules.insert(libc::SYS_setgroups, block_always());

    // Keyring operations (credential access)
    rules.insert(libc::SYS_add_key, block_always());
    rules.insert(libc::SYS_request_key, block_always());
    rules.insert(libc::SYS_keyctl, block_always());

    // BPF (could install malicious filters or bypass restrictions)
    rules.insert(libc::SYS_bpf, block_always());

    // Userfaultfd (commonly used in exploits)
    rules.insert(libc::SYS_userfaultfd, block_always());

    // perf_event_open (information disclosure, timing attacks)
    rules.insert(libc::SYS_perf_event_open, block_always());

    // Clock manipulation
    rules.insert(libc::SYS_settimeofday, block_always());
    rules.insert(libc::SYS_clock_settime, block_always());
    rules.insert(libc::SYS_adjtimex, block_always());

    // Swap manipulation
    rules.insert(libc::SYS_swapon, block_always());
    rules.insert(libc::SYS_swapoff, block_always());

    // Quota manipulation
    rules.insert(libc::SYS_quotactl, block_always());

    // Accounting
    rules.insert(libc::SYS_acct, block_always());

    tracing::debug!("seccomp: dangerous syscall blocks added");
    Ok(())
}

/// Restrict hardware-related syscalls when allow_hardware is false
fn add_hardware_restrictions(rules: &mut BTreeMap<i64, Vec<SeccompRule>>) -> Result<()> {
    // Empty rule chains match on syscall number only.
    let block_always = || Vec::new();

    // io_uring (powerful async I/O, can be used in exploits)
    rules.insert(libc::SYS_io_uring_setup, block_always());
    rules.insert(libc::SYS_io_uring_enter, block_always());
    rules.insert(libc::SYS_io_uring_register, block_always());

    tracing::debug!("seccomp: hardware restrictions added");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityConfig;

    #[test]
    fn test_arch_detection() {
        // This test will only pass on supported architectures
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            assert!(detect_arch().is_ok());
        }
    }

    #[test]
    fn test_filter_program_is_not_empty() {
        let filter = build_filter(&SecurityConfig::strict(), false, false).unwrap();
        assert!(!filter.program.is_empty());
    }
}
