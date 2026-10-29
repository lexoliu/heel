//! The seccomp program that sends the calls the broker serves to its listener.
//!
//! Hand-built, because no seccomp crate offers the user-notify action: it is a
//! classic BPF program over `seccomp_data`, a binary search over the sorted
//! syscall numbers so that the calls it does not care about, which are almost
//! all of them, cost a handful of instructions rather than one comparison per
//! brokered call.
//!
//! Syscall numbers with the x32 bit set are refused with `ENOSYS` before
//! anything else: x32 shares the x86-64 audit architecture, so a filter that
//! only matches numbers would let every one of its calls through.

use std::collections::BTreeMap;

use libc::sock_filter;

use crate::error::{Error, Result};

/// `AUDIT_ARCH_X86_64`, from `<linux/audit.h>`.
#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xC000_003E;
/// `AUDIT_ARCH_AARCH64`, from `<linux/audit.h>`.
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xC000_00B7;

/// The bit x32 sets in every syscall number.
#[cfg(target_arch = "x86_64")]
pub(crate) const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// `fchmodat2`, shared by every architecture from 6.6 on and absent from libc.
const SYS_FCHMODAT2: i64 = 452;
/// `setxattrat`, 6.13.
const SYS_SETXATTRAT: i64 = 463;
/// `removexattrat`, 6.13.
const SYS_REMOVEXATTRAT: i64 = 466;
/// `file_setattr`, 6.17: changes a path's inode flags, which no brokered call
/// covers, so it is refused outright and callers fall back to the ioctl.
const SYS_FILE_SETATTR: i64 = 469;

const OFFSET_NR: u32 = 0;
const OFFSET_ARCH: u32 = 4;
const OFFSET_ARGS: u32 = 16;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_JMP_JGE_K: u16 = 0x35;
const BPF_JMP_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

/// A call the broker serves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(missing_docs)]
// aarch64 has only the `at` forms of the legacy calls.
#[cfg_attr(target_arch = "aarch64", allow(dead_code))]
pub(crate) enum Syscall {
    Open,
    Openat,
    Openat2,
    Creat,
    Mkdir,
    Mkdirat,
    Mknod,
    Mknodat,
    Symlink,
    Symlinkat,
    Link,
    Linkat,
    Rename,
    Renameat,
    Renameat2,
    Unlink,
    Unlinkat,
    Rmdir,
    Truncate,
    Chmod,
    Fchmod,
    Fchmodat,
    Fchmodat2,
    Chown,
    Fchown,
    Lchown,
    Fchownat,
    Setxattr,
    Lsetxattr,
    Fsetxattr,
    Removexattr,
    Lremovexattr,
    Fremovexattr,
    Setxattrat,
    Removexattrat,
    Utime,
    Utimes,
    Futimesat,
    Utimensat,
    Connect,
    Bind,
}

/// Every brokered call with the number it has on this architecture.
fn table() -> Vec<(i64, Syscall)> {
    use Syscall as S;
    #[allow(unused_mut)]
    let mut table = vec![
        (libc::SYS_openat, S::Openat),
        (libc::SYS_openat2, S::Openat2),
        (libc::SYS_mkdirat, S::Mkdirat),
        (libc::SYS_mknodat, S::Mknodat),
        (libc::SYS_symlinkat, S::Symlinkat),
        (libc::SYS_linkat, S::Linkat),
        (libc::SYS_renameat, S::Renameat),
        (libc::SYS_renameat2, S::Renameat2),
        (libc::SYS_unlinkat, S::Unlinkat),
        (libc::SYS_truncate, S::Truncate),
        (libc::SYS_fchmod, S::Fchmod),
        (libc::SYS_fchmodat, S::Fchmodat),
        (SYS_FCHMODAT2, S::Fchmodat2),
        (libc::SYS_fchown, S::Fchown),
        (libc::SYS_fchownat, S::Fchownat),
        (libc::SYS_setxattr, S::Setxattr),
        (libc::SYS_lsetxattr, S::Lsetxattr),
        (libc::SYS_fsetxattr, S::Fsetxattr),
        (libc::SYS_removexattr, S::Removexattr),
        (libc::SYS_lremovexattr, S::Lremovexattr),
        (libc::SYS_fremovexattr, S::Fremovexattr),
        (SYS_SETXATTRAT, S::Setxattrat),
        (SYS_REMOVEXATTRAT, S::Removexattrat),
        (libc::SYS_utimensat, S::Utimensat),
        (libc::SYS_connect, S::Connect),
        (libc::SYS_bind, S::Bind),
    ];
    // Only x86-64 has the calls that predate the `*at` family.
    #[cfg(target_arch = "x86_64")]
    table.extend([
        (libc::SYS_open, S::Open),
        (libc::SYS_creat, S::Creat),
        (libc::SYS_mkdir, S::Mkdir),
        (libc::SYS_mknod, S::Mknod),
        (libc::SYS_symlink, S::Symlink),
        (libc::SYS_link, S::Link),
        (libc::SYS_rename, S::Rename),
        (libc::SYS_unlink, S::Unlink),
        (libc::SYS_rmdir, S::Rmdir),
        (libc::SYS_chmod, S::Chmod),
        (libc::SYS_chown, S::Chown),
        (libc::SYS_lchown, S::Lchown),
        (libc::SYS_utime, S::Utime),
        (libc::SYS_utimes, S::Utimes),
        (libc::SYS_futimesat, S::Futimesat),
    ]);
    table
}

/// The brokered call with syscall number `nr`.
pub(crate) fn classify(nr: i32) -> Option<Syscall> {
    table()
        .into_iter()
        .find(|&(number, _)| number == i64::from(nr))
        .map(|(_, syscall)| syscall)
}

/// What the program does with one syscall number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Action {
    /// Always notify.
    Notify,
    /// Notify when the argument at this index has a bit of the mask set.
    NotifyIfFlags { argument: u32, mask: u32 },
    /// Refuse with `ENOSYS`.
    Unsupported,
}

impl Action {
    /// Instructions of this action, run once the number has matched.
    fn code(self) -> Vec<sock_filter> {
        match self {
            Self::Notify => vec![ret(libc::SECCOMP_RET_USER_NOTIF)],
            Self::Unsupported => vec![ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32)],
            Self::NotifyIfFlags { argument, mask } => vec![
                stmt(BPF_LD_W_ABS, OFFSET_ARGS + 8 * argument),
                jump(BPF_JMP_JSET_K, mask, 0, 1),
                ret(libc::SECCOMP_RET_USER_NOTIF),
                ret(libc::SECCOMP_RET_ALLOW),
            ],
        }
    }
}

fn stmt(code: u16, k: u32) -> sock_filter {
    sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> sock_filter {
    sock_filter { code, jt, jf, k }
}

fn ret(value: u32) -> sock_filter {
    stmt(BPF_RET_K, value)
}

/// The open flags a write can come from: `O_WRONLY`, `O_RDWR`, `O_CREAT`,
/// `O_TRUNC` and the `__O_TMPFILE` bit.
pub(crate) const WRITE_OPEN_FLAGS: u32 = (libc::O_WRONLY
    | libc::O_RDWR
    | libc::O_CREAT
    | libc::O_TRUNC
    | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32;

/// Which calls the program sends to the broker.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Coverage {
    /// Serve file creation, removal and metadata calls, and `bind`.
    pub files: bool,
    /// Also serve opens that only read, so that every denial of a read is seen
    /// and the directories above a denied path can be listed.
    pub reads: bool,
}

/// Build the program. `connect` is served in every mode.
pub(crate) fn build(coverage: Coverage) -> Result<Vec<sock_filter>> {
    let mut entries: BTreeMap<u32, Action> = BTreeMap::new();
    for (number, syscall) in table() {
        use Syscall as S;
        let action = match syscall {
            S::Connect => Action::Notify,
            S::Bind if coverage.files => Action::Notify,
            S::Bind => continue,
            _ if !coverage.files => continue,
            S::Open if !coverage.reads => Action::NotifyIfFlags {
                argument: 1,
                mask: WRITE_OPEN_FLAGS,
            },
            S::Openat if !coverage.reads => Action::NotifyIfFlags {
                argument: 2,
                mask: WRITE_OPEN_FLAGS,
            },
            _ => Action::Notify,
        };
        let number = u32::try_from(number)
            .map_err(|_| Error::InvalidProfile(format!("syscall number {number} out of range")))?;
        entries.insert(number, action);
    }
    if coverage.files {
        entries.insert(SYS_FILE_SETATTR as u32, Action::Unsupported);
    }
    let entries: Vec<(u32, Action)> = entries.into_iter().collect();

    #[allow(unused_mut)]
    let mut program = vec![
        stmt(BPF_LD_W_ABS, OFFSET_ARCH),
        jump(BPF_JMP_JEQ_K, AUDIT_ARCH, 1, 0),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
        stmt(BPF_LD_W_ABS, OFFSET_NR),
    ];
    #[cfg(target_arch = "x86_64")]
    program.extend([
        jump(BPF_JMP_JSET_K, X32_SYSCALL_BIT, 0, 1),
        ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        // The test above clobbers nothing, but the search below expects the
        // number in the accumulator, which `jset` leaves untouched.
    ]);
    program.extend(search(&entries)?);
    Ok(program)
}

/// A binary search over `entries`, sorted by syscall number, that returns a
/// verdict on every path. The accumulator holds the syscall number on entry.
fn search(entries: &[(u32, Action)]) -> Result<Vec<sock_filter>> {
    /// A run this short is compared one by one.
    const LEAF: usize = 3;

    if entries.len() <= LEAF {
        let mut code = Vec::new();
        for &(number, action) in entries {
            let body = action.code();
            let skip = u8::try_from(body.len()).map_err(|_| too_long())?;
            code.push(jump(BPF_JMP_JEQ_K, number, 0, skip));
            code.extend(body);
        }
        code.push(ret(libc::SECCOMP_RET_ALLOW));
        return Ok(code);
    }

    let middle = entries.len() / 2;
    let left = search(&entries[..middle])?;
    let right = search(&entries[middle..])?;
    let skip = u8::try_from(left.len()).map_err(|_| too_long())?;
    let mut code = vec![jump(BPF_JMP_JGE_K, entries[middle].0, skip, 0)];
    code.extend(left);
    code.extend(right);
    Ok(code)
}

fn too_long() -> Error {
    Error::InvalidProfile("the broker's seccomp program exceeds a BPF jump".into())
}

/// A program that refuses every syscall number with the x32 bit set, for the
/// filters that otherwise match numbers only.
///
/// Every program heel installs refuses them: the numbers are not the ones the
/// rules name, so without this each rule would be bypassed by the same call
/// made through its x32 number.
#[cfg(target_arch = "x86_64")]
pub(crate) fn x32_refusal() -> Vec<sock_filter> {
    vec![
        stmt(BPF_LD_W_ABS, OFFSET_NR),
        jump(BPF_JMP_JSET_K, X32_SYSCALL_BIT, 0, 1),
        ret(libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32),
        ret(libc::SECCOMP_RET_ALLOW),
    ]
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Run a classic BPF program over a syscall, as the kernel would.
    fn run(program: &[sock_filter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        let (mut accumulator, mut counter) = (0u32, 0usize);
        loop {
            let instruction = program[counter];
            counter += 1;
            match instruction.code {
                BPF_LD_W_ABS => {
                    accumulator = match instruction.k {
                        OFFSET_NR => nr,
                        OFFSET_ARCH => arch,
                        offset => {
                            (args[((offset - OFFSET_ARGS) / 8) as usize] & 0xffff_ffff) as u32
                        }
                    };
                }
                BPF_JMP_JEQ_K | BPF_JMP_JGE_K | BPF_JMP_JSET_K => {
                    let taken = match instruction.code {
                        BPF_JMP_JEQ_K => accumulator == instruction.k,
                        BPF_JMP_JGE_K => accumulator >= instruction.k,
                        _ => accumulator & instruction.k != 0,
                    };
                    counter += usize::from(if taken {
                        instruction.jt
                    } else {
                        instruction.jf
                    });
                }
                BPF_RET_K => return instruction.k,
                other => panic!("unexpected instruction {other:#x}"),
            }
        }
    }

    fn verdict(program: &[sock_filter], nr: i64, args: [u64; 6]) -> u32 {
        run(program, nr as u32, AUDIT_ARCH, args)
    }

    const EVERYTHING: Coverage = Coverage {
        files: true,
        reads: true,
    };

    #[test]
    fn every_brokered_call_is_notified_and_nothing_else_is() {
        let program = build(EVERYTHING).unwrap();
        for (number, _) in table() {
            assert_eq!(
                verdict(&program, number, [0; 6]),
                libc::SECCOMP_RET_USER_NOTIF,
                "syscall {number}"
            );
        }
        for number in [
            libc::SYS_read,
            libc::SYS_write,
            libc::SYS_close,
            libc::SYS_execve,
        ] {
            assert_eq!(verdict(&program, number, [0; 6]), libc::SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn a_wrong_architecture_is_killed() {
        let program = build(EVERYTHING).unwrap();
        assert_eq!(
            run(&program, 0, 0x4000_0003, [0; 6]),
            libc::SECCOMP_RET_KILL_PROCESS
        );
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn x32_numbers_are_refused_before_any_rule() {
        let program = build(EVERYTHING).unwrap();
        let open = (libc::SYS_openat as u32) | X32_SYSCALL_BIT;
        assert_eq!(
            run(&program, open, AUDIT_ARCH, [0; 6]),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
        assert_eq!(
            run(
                &x32_refusal(),
                libc::SYS_ptrace as u32 | X32_SYSCALL_BIT,
                AUDIT_ARCH,
                [0; 6]
            ),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
    }

    #[test]
    fn without_a_read_denylist_only_opens_that_write_are_notified() {
        let program = build(Coverage {
            files: true,
            reads: false,
        })
        .unwrap();
        let mut read_only = [0u64; 6];
        read_only[2] = (libc::O_RDONLY | libc::O_CLOEXEC) as u64;
        assert_eq!(
            verdict(&program, libc::SYS_openat, read_only),
            libc::SECCOMP_RET_ALLOW
        );
        for flags in [
            libc::O_WRONLY,
            libc::O_RDWR,
            libc::O_CREAT,
            libc::O_TRUNC,
            libc::O_TMPFILE,
        ] {
            let mut args = [0u64; 6];
            args[2] = flags as u64;
            assert_eq!(
                verdict(&program, libc::SYS_openat, args),
                libc::SECCOMP_RET_USER_NOTIF,
                "flags {flags:#x}"
            );
        }
        assert_eq!(
            verdict(&program, libc::SYS_openat2, [0; 6]),
            libc::SECCOMP_RET_USER_NOTIF,
            "openat2 keeps its flags in memory"
        );
    }

    #[test]
    fn a_connect_only_program_leaves_the_filesystem_alone() {
        let program = build(Coverage {
            files: false,
            reads: false,
        })
        .unwrap();
        assert_eq!(
            verdict(&program, libc::SYS_connect, [0; 6]),
            libc::SECCOMP_RET_USER_NOTIF
        );
        for number in [libc::SYS_openat, libc::SYS_bind, libc::SYS_unlinkat] {
            assert_eq!(verdict(&program, number, [0; 6]), libc::SECCOMP_RET_ALLOW);
        }
    }

    #[test]
    fn file_setattr_is_refused() {
        let program = build(Coverage {
            files: true,
            reads: false,
        })
        .unwrap();
        assert_eq!(
            verdict(&program, SYS_FILE_SETATTR, [0; 6]),
            libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32
        );
    }
}
