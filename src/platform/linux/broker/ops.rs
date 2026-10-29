//! The calls the broker serves, one function each.
//!
//! Every call follows the same shape. The arguments are copied out of the
//! stopped process, the path is resolved against directories this process holds,
//! the denylist is checked against the name and the inode that resolved to, and
//! the call is then performed here, in the held directory, by this process. The
//! result goes back as the return value, or for an open as a descriptor
//! installed in the caller. Nothing is checked and then used by path.
//!
//! Errors are the exact errno of the call that failed, as the sandboxed
//! process would have seen it. A refusal by the policy is `EACCES`, which is what
//! Landlock reports for the same access.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{
    AtFlags, CWD, FileType, Gid, Mode, OFlags, RenameFlags, ResolveFlags, Stat, Timestamps, Uid,
    XattrFlags,
};

use super::Context;
use super::check::InodeId;
use super::filter::{Syscall, WRITE_OPEN_FLAGS};
use super::net;
use super::notify::Reply;
use super::pool::Kind;
use super::resolve::{self, AT_FDCWD, Base, Caller, Place};
use super::sink::Operation;

/// A failed call, as the errno the caller sees.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Errno(pub i32);

impl From<io::Error> for Errno {
    fn from(error: io::Error) -> Self {
        Self(error.raw_os_error().unwrap_or(libc::EIO))
    }
}

impl From<rustix::io::Errno> for Errno {
    fn from(errno: rustix::io::Errno) -> Self {
        Self(errno.raw_os_error())
    }
}

pub(crate) type Out = Result<Reply, Errno>;

const EACCES: Errno = Errno(libc::EACCES);

/// `AT_SYMLINK_FOLLOW`.
const AT_SYMLINK_FOLLOW: u32 = 0x400;
/// `AT_SYMLINK_NOFOLLOW`.
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
/// `AT_EMPTY_PATH`.
const AT_EMPTY_PATH: u32 = 0x1000;
/// `AT_REMOVEDIR`.
const AT_REMOVEDIR: u32 = 0x200;
/// The longest extended attribute value the kernel accepts.
const XATTR_SIZE_MAX: usize = 65536;
/// The longest extended attribute name, with its terminator.
const XATTR_NAME_MAX: usize = 256;
/// `MAJOR(5)`/`MINOR(0)` of `/dev/tty`.
const DEV_TTY: (u32, u32) = (5, 0);

/// One call, with its arguments as the registers hold them.
pub(crate) struct Call<'a> {
    pub syscall: Syscall,
    pub args: [u64; 6],
    pub caller: &'a Caller<'a>,
}

impl Call<'_> {
    fn fd(&self, index: usize) -> i32 {
        self.args[index] as i32
    }

    fn word(&self, index: usize) -> u32 {
        self.args[index] as u32
    }

    fn address(&self, index: usize) -> u64 {
        self.args[index]
    }
}

/// Serve one call.
pub(crate) fn serve(ctx: &Context, call: &Call<'_>) -> Out {
    use Syscall as S;
    let _held = ctx.shared().hold_for(call.syscall);
    if makes_files(call) {
        apply_umask(call.caller)?;
    }
    match call.syscall {
        S::Open => open(ctx, call, AT_FDCWD, 0, 1, 2, ResolveFlags::empty()),
        S::Openat => open(ctx, call, call.fd(0), 1, 2, 3, ResolveFlags::empty()),
        S::Creat => {
            let flags = (libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC) as u32;
            open_with(
                ctx,
                call,
                AT_FDCWD,
                0,
                flags,
                call.word(1),
                ResolveFlags::empty(),
            )
        }
        S::Openat2 => open_how(ctx, call),
        S::Mkdir => mkdir(ctx, call, AT_FDCWD, 0, 1),
        S::Mkdirat => mkdir(ctx, call, call.fd(0), 1, 2),
        S::Mknod => mknod(ctx, call, AT_FDCWD, 0, 1, 2),
        S::Mknodat => mknod(ctx, call, call.fd(0), 1, 2, 3),
        S::Symlink => symlink(ctx, call, 0, AT_FDCWD, 1),
        S::Symlinkat => symlink(ctx, call, 0, call.fd(1), 2),
        S::Link => link(ctx, call, (AT_FDCWD, 0), (AT_FDCWD, 1), 0),
        S::Linkat => link(ctx, call, (call.fd(0), 1), (call.fd(2), 3), call.word(4)),
        S::Rename => rename(ctx, call, (AT_FDCWD, 0), (AT_FDCWD, 1), 0),
        S::Renameat => rename(ctx, call, (call.fd(0), 1), (call.fd(2), 3), 0),
        S::Renameat2 => rename(ctx, call, (call.fd(0), 1), (call.fd(2), 3), call.word(4)),
        S::Unlink => unlink(ctx, call, AT_FDCWD, 0, 0),
        S::Unlinkat => unlink(ctx, call, call.fd(0), 1, call.word(2)),
        S::Rmdir => unlink(ctx, call, AT_FDCWD, 0, AT_REMOVEDIR),
        S::Truncate => truncate(ctx, call),
        S::Chmod => chmod(ctx, call, path_subject(AT_FDCWD, 0, true), call.word(1)),
        S::Fchmod => chmod(ctx, call, Subject::Fd(call.fd(0)), call.word(1)),
        S::Fchmodat => chmod(ctx, call, path_subject(call.fd(0), 1, true), call.word(2)),
        S::Fchmodat2 => {
            let flags = call.word(3);
            chmod(
                ctx,
                call,
                flagged_subject(call.fd(0), 1, flags),
                call.word(2),
            )
        }
        S::Chown => chown(ctx, call, path_subject(AT_FDCWD, 0, true), 1),
        S::Lchown => chown(ctx, call, path_subject(AT_FDCWD, 0, false), 1),
        S::Fchown => chown(ctx, call, Subject::Fd(call.fd(0)), 1),
        S::Fchownat => {
            let flags = call.word(4);
            chown(ctx, call, flagged_subject(call.fd(0), 1, flags), 2)
        }
        S::Setxattr | S::Lsetxattr => {
            let follow = call.syscall == S::Setxattr;
            set_xattr(
                ctx,
                call,
                path_subject(AT_FDCWD, 0, follow),
                XattrArgs::Registers,
            )
        }
        S::Fsetxattr => set_xattr(ctx, call, Subject::Fd(call.fd(0)), XattrArgs::Registers),
        S::Removexattr | S::Lremovexattr => {
            let follow = call.syscall == S::Removexattr;
            remove_xattr(ctx, call, path_subject(AT_FDCWD, 0, follow), 1)
        }
        S::Fremovexattr => remove_xattr(ctx, call, Subject::Fd(call.fd(0)), 1),
        S::Setxattrat => {
            let flags = call.word(2);
            set_xattr(
                ctx,
                call,
                flagged_subject(call.fd(0), 1, flags),
                XattrArgs::Struct,
            )
        }
        S::Removexattrat => {
            let flags = call.word(2);
            remove_xattr(ctx, call, flagged_subject(call.fd(0), 1, flags), 3)
        }
        S::Utime => utime(ctx, call, Times::Utime, path_subject(AT_FDCWD, 0, true), 1),
        S::Utimes => utime(
            ctx,
            call,
            Times::Timevals,
            path_subject(AT_FDCWD, 0, true),
            1,
        ),
        S::Futimesat => utime(
            ctx,
            call,
            Times::Timevals,
            path_subject(call.fd(0), 1, true),
            2,
        ),
        S::Utimensat => {
            let flags = call.word(3);
            let subject = if call.address(1) == 0 {
                Subject::Fd(call.fd(0))
            } else {
                flagged_subject(call.fd(0), 1, flags)
            };
            utime(ctx, call, Times::Timespecs, subject, 2)
        }
        S::Connect => net::connect(ctx, call),
        S::Bind => net::bind(ctx, call),
    }
}

/// Whether the call can create a file, and so is subject to the file creation
/// mask. Reading the mask costs a read of `/proc`, so the calls that cannot
/// create anything do not pay for it.
fn makes_files(call: &Call<'_>) -> bool {
    use Syscall as S;
    let creating = |flags: u64| flags & (libc::O_CREAT | libc::O_TMPFILE) as u64 != 0;
    match call.syscall {
        S::Creat | S::Mkdir | S::Mkdirat | S::Mknod | S::Mknodat | S::Bind | S::Openat2 => true,
        S::Open => creating(call.args[1]),
        S::Openat => creating(call.args[2]),
        _ => false,
    }
}

/// Make this thread's file creation mask the caller's.
fn apply_umask(caller: &Caller<'_>) -> Result<(), Errno> {
    let umask = caller.status()?.umask;
    rustix::process::umask(Mode::from_bits_truncate(umask));
    Ok(())
}

/// Record a refusal and answer with it.
pub(crate) fn refuse(ctx: &Context, call: &Call<'_>, operation: Operation, target: &Path) -> Errno {
    let tgid = call
        .caller
        .status()
        .map_or(call.caller.tid, |status| status.tgid);
    ctx.shared()
        .sink
        .record(operation, target, tgid, call.caller.tid);
    EACCES
}

/// Read the path in argument `index`.
fn path_argument(call: &Call<'_>, index: usize) -> Result<Vec<u8>, Errno> {
    Ok(call.caller.read_path(call.address(index))?)
}

fn place_of(
    call: &Call<'_>,
    dirfd: i32,
    index: usize,
    extra: ResolveFlags,
) -> Result<Place, Errno> {
    let path = path_argument(call, index)?;
    Ok(resolve::resolve(
        call.caller,
        Base::Dirfd(dirfd),
        &path,
        extra,
    )?)
}

fn mode_of(bits: u32) -> Mode {
    Mode::from_bits_truncate(bits & 0o7777)
}

fn is(stat: &Stat, kind: FileType) -> bool {
    FileType::from_raw_mode(stat.st_mode) == kind
}

fn identity(stat: &Stat) -> InodeId {
    (stat.st_dev, stat.st_ino)
}

// -- Opens ------------------------------------------------------------------

fn open(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    flags: usize,
    mode: usize,
    resolve: ResolveFlags,
) -> Out {
    let dirfd = if dirfd == AT_FDCWD && call.syscall == Syscall::Open {
        AT_FDCWD
    } else {
        dirfd
    };
    open_with(
        ctx,
        call,
        dirfd,
        path,
        call.word(flags),
        call.word(mode),
        resolve,
    )
}

/// `openat2`, whose flags, mode and resolution flags are in a structure.
fn open_how(ctx: &Context, call: &Call<'_>) -> Out {
    let size = usize::try_from(call.args[3]).map_err(|_| Errno(libc::EINVAL))?;
    if !(24..=4096).contains(&size) {
        return Err(Errno(libc::EINVAL));
    }
    let how = call.caller.read_bytes(call.address(2), size)?;
    if how[24.min(size)..].iter().any(|&byte| byte != 0) {
        return Err(Errno(libc::E2BIG));
    }
    let word = |at: usize| u64::from_ne_bytes(how[at..at + 8].try_into().unwrap_or_default());
    let resolve = ResolveFlags::from_bits_retain(word(16));
    open_with(
        ctx,
        call,
        call.fd(0),
        1,
        word(0) as u32,
        word(8) as u32,
        resolve,
    )
}

fn open_with(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    flags: u32,
    mode: u32,
    resolve: ResolveFlags,
) -> Out {
    let by_path = flags & libc::O_PATH as u32 != 0;
    let tmpfile = flags & libc::O_TMPFILE as u32 == libc::O_TMPFILE as u32;
    if by_path || (flags & WRITE_OPEN_FLAGS == 0 && !tmpfile) {
        return open_read(ctx, call, dirfd, path, flags, resolve);
    }
    if tmpfile {
        return open_tmpfile(ctx, call, dirfd, path, flags, mode, resolve);
    }
    open_write(ctx, call, dirfd, path, flags, mode, resolve)
}

/// An open that only reads. The kernel and Landlock decide it, except that a
/// read of a credential store is refused here so it is recorded, and a directory
/// above one is opened here, because Landlock grants it nothing to list.
fn open_read(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    flags: u32,
    resolve_flags: ResolveFlags,
) -> Out {
    let shared = ctx.shared();
    if !shared.guard.watches_reads() {
        return Ok(Reply::Continue);
    }
    let Ok(bytes) = path_argument(call, path) else {
        return Ok(Reply::Continue);
    };
    // Anything this cannot resolve is the kernel's to answer.
    let Ok(mut place) = resolve::resolve(call.caller, Base::Dirfd(dirfd), &bytes, resolve_flags)
    else {
        return Ok(Reply::Continue);
    };
    if flags & libc::O_NOFOLLOW as u32 == 0 {
        match resolve::follow(call.caller, place, resolve_flags) {
            Ok(followed) => place = followed,
            Err(_) => return Ok(Reply::Continue),
        }
    }
    let target = place.target();
    if shared.guard.read_denied(&target) {
        return Err(refuse(ctx, call, Operation::ReadData, &target));
    }
    if shared.guard.is_ancestor(&target) {
        let fd = rustix::fs::openat(
            &place.parent,
            place.kernel_name(),
            oflags(flags) | OFlags::NOCTTY | nofollow(&place),
            Mode::empty(),
        )?;
        return Ok(installed(fd, flags));
    }
    Ok(Reply::Continue)
}

fn oflags(flags: u32) -> OFlags {
    OFlags::from_bits_retain(flags & !(libc::O_CLOEXEC as u32 | libc::O_TRUNC as u32))
}

/// `O_NOFOLLOW` for every name but one on `procfs`, whose links the kernel
/// resolves for whoever follows them.
fn nofollow(place: &Place) -> OFlags {
    if place.in_proc {
        OFlags::empty()
    } else {
        OFlags::NOFOLLOW
    }
}

fn installed(fd: OwnedFd, flags: u32) -> Reply {
    Reply::Fd {
        fd,
        cloexec: flags & libc::O_CLOEXEC as u32 != 0,
    }
}

fn open_write(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    flags: u32,
    mode: u32,
    resolve_flags: ResolveFlags,
) -> Out {
    let shared = ctx.shared();
    let bytes = path_argument(call, path)?;
    let mut place = resolve::resolve(call.caller, Base::Dirfd(dirfd), &bytes, resolve_flags)?;
    let creating = flags & libc::O_CREAT as u32 != 0;
    let exclusive = creating && flags & libc::O_EXCL as u32 != 0;
    if flags & libc::O_NOFOLLOW as u32 == 0 && !exclusive {
        place = resolve::follow(call.caller, place, resolve_flags)?;
    }
    let target = place.target();
    let operation = if creating {
        Operation::WriteCreate
    } else {
        Operation::WriteData
    };
    if shared.guard.write_denied(&target) {
        return Err(refuse(ctx, call, operation, &target));
    }

    let exists = match place.stat() {
        Ok(stat) => {
            if shared.guard.inode_denied(identity(&stat)) {
                return Err(refuse(ctx, call, operation, &target));
            }
            if flags & libc::O_ACCMODE as u32 == libc::O_RDWR as u32
                && shared.guard.read_denied(&target)
            {
                return Err(refuse(ctx, call, Operation::ReadData, &target));
            }
            if is(&stat, FileType::Fifo) && flags & libc::O_NONBLOCK as u32 == 0 {
                ctx.ensure_spare_worker();
            }
            true
        }
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
            if !creating {
                return Err(Errno(libc::ENOENT));
            }
            false
        }
        Err(error) => return Err(error.into()),
    };

    if creating
        && !exists
        && shared.guard.is_ancestor(&place.parent_path)
        && let Some(fd) = open_pooled(ctx, call, &place, flags, mode)?
    {
        return Ok(installed(fd, flags));
    }

    let fd = rustix::fs::openat(
        &place.parent,
        place.kernel_name(),
        oflags(flags) | OFlags::NOCTTY | nofollow(&place),
        mode_of(mode),
    )?;
    let stat = rustix::fs::fstat(&fd)?;
    if shared.guard.inode_denied(identity(&stat)) {
        return Err(refuse(ctx, call, operation, &target));
    }
    if !exists {
        casefold_check(ctx, call, &place, &stat)?;
    }
    finish_open(call, &fd, &stat, flags)?;
    Ok(installed(fd, flags))
}

/// What is left to do to an opened file: truncate it, and keep `/dev/tty` from
/// meaning this process's terminal.
fn finish_open(call: &Call<'_>, fd: &OwnedFd, stat: &Stat, flags: u32) -> Result<(), Errno> {
    if is(stat, FileType::CharacterDevice) {
        let rdev = stat.st_rdev;
        let (major, minor) = (libc::major(rdev), libc::minor(rdev));
        if (major, minor) == DEV_TTY && !same_terminal(call.caller)? {
            return Err(Errno(libc::ENXIO));
        }
    }
    if flags & libc::O_TRUNC as u32 != 0 && is(stat, FileType::RegularFile) {
        rustix::fs::ftruncate(fd, 0)?;
    }
    Ok(())
}

/// The controlling terminal of `/proc/<pid>/stat`, which is its seventh field.
fn terminal_of(stat: &str) -> Option<i64> {
    let after_name = &stat[stat.rfind(')')? + 1..];
    after_name.split_whitespace().nth(4)?.parse().ok()
}

/// Whether the caller's controlling terminal is the one `/dev/tty` means in this
/// process, so the broker does not hand it a terminal it is not attached to.
fn same_terminal(caller: &Caller<'_>) -> Result<bool, Errno> {
    let theirs = std::fs::read_to_string(format!("/proc/{}/stat", caller.tid))?;
    caller.still_valid()?;
    let ours = std::fs::read_to_string("/proc/thread-self/stat")?;
    Ok(match (terminal_of(&theirs), terminal_of(&ours)) {
        (Some(theirs), Some(ours)) => theirs != 0 && theirs == ours,
        _ => false,
    })
}

fn open_tmpfile(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    flags: u32,
    mode: u32,
    resolve_flags: ResolveFlags,
) -> Out {
    let mut bytes = path_argument(call, path)?;
    bytes.extend_from_slice(b"/.");
    let place = resolve::resolve(call.caller, Base::Dirfd(dirfd), &bytes, resolve_flags)?;
    if ctx.shared().guard.write_denied(&place.parent_path) {
        return Err(refuse(
            ctx,
            call,
            Operation::WriteCreate,
            &place.parent_path,
        ));
    }
    let fd = rustix::fs::openat(
        &place.parent,
        ".",
        oflags(flags) | OFlags::NOCTTY,
        mode_of(mode),
    )?;
    Ok(installed(fd, flags))
}

// -- New entries above a denied path -----------------------------------------

/// Whether the directory `parent` has a default ACL, which a created entry
/// would take its permissions from and which the pooled inode cannot reproduce.
fn has_default_acl(parent: &OwnedFd) -> bool {
    let path = format!("/proc/self/fd/{}", parent.as_raw_fd());
    let mut probe: [u8; 0] = [];
    matches!(
        rustix::fs::getxattr(path, "system.posix_acl_default", &mut probe),
        Ok(size) if size > 0
    )
}

/// Move a pooled inode into `place` and make it what a creation there would
/// have made. `Ok(None)` when no pool serves the directory.
fn pooled(ctx: &Context, place: &Place, kind: Kind) -> Result<Option<(OwnedFd, Stat)>, Errno> {
    let shared = ctx.shared();
    let Some(pool) = &shared.pool else {
        return Ok(None);
    };
    let entry = match pool.acquire(&place.parent_path, kind) {
        Ok(entry) => entry,
        Err(false) => return Ok(None),
        Err(true) => {
            tracing::error!(directory = %place.parent_path.display(), "{}", pool.describe(kind));
            return Err(Errno(libc::ENOSPC));
        }
    };
    if has_default_acl(&place.parent) {
        pool.restore(entry);
        return Err(Errno(libc::EOPNOTSUPP));
    }
    let (pool_dir, pool_name) = pool.place(&entry);
    let held = rustix::fs::openat(
        pool_dir,
        pool_name,
        OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    if let Err(errno) = rustix::fs::renameat_with(
        pool_dir,
        pool_name,
        &place.parent,
        place.kernel_name(),
        RenameFlags::NOREPLACE,
    ) {
        pool.restore(entry);
        return Err(errno.into());
    }
    let stat = rustix::fs::fstat(&held)?;
    Ok(Some((held, stat)))
}

/// Give a pooled inode the owner group, permissions and times a new entry in its
/// directory has.
fn settle(
    ctx: &Context,
    call: &Call<'_>,
    place: &Place,
    held: &OwnedFd,
    mode: u32,
    directory: bool,
) -> Result<(), Errno> {
    let _ = ctx;
    let parent = rustix::fs::fstat(&place.parent)?;
    let setgid = parent.st_mode & libc::S_ISGID != 0;
    let umask = call.caller.status()?.umask;
    let mut bits = mode & 0o7777 & !umask;
    if directory && setgid {
        bits |= libc::S_ISGID;
    }
    let path = format!("/proc/self/fd/{}", held.as_raw_fd());
    rustix::fs::chmodat(CWD, &path, Mode::from_bits_truncate(bits), AtFlags::empty())?;
    if setgid {
        rustix::fs::chownat(
            CWD,
            &path,
            None,
            Gid::from_raw(parent.st_gid).into(),
            AtFlags::empty(),
        )?;
    }
    let now = rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_NOW as _,
    };
    rustix::fs::utimensat(
        CWD,
        &path,
        &Timestamps {
            last_access: now,
            last_modification: now,
        },
        AtFlags::empty(),
    )?;
    Ok(())
}

fn open_pooled(
    ctx: &Context,
    call: &Call<'_>,
    place: &Place,
    flags: u32,
    mode: u32,
) -> Result<Option<OwnedFd>, Errno> {
    let Some((held, stat)) = pooled(ctx, place, Kind::File)? else {
        return Ok(None);
    };
    let fd = rustix::fs::openat(
        &place.parent,
        place.kernel_name(),
        oflags(flags) & !(OFlags::CREATE | OFlags::EXCL) | OFlags::NOCTTY | OFlags::NOFOLLOW,
        Mode::empty(),
    )?;
    settle(ctx, call, place, &held, mode, false)?;
    casefold_check(ctx, call, place, &stat)?;
    Ok(Some(fd))
}

/// After an entry was created in a directory with denied names in it, check that
/// none of them now resolves to it, which is what a directory that folds case
/// does when the new name differs from a denied one only in case. The filesystem
/// is asked, so no folding rules are written down here.
pub(crate) fn casefold_check(
    ctx: &Context,
    call: &Call<'_>,
    place: &Place,
    created: &Stat,
) -> Result<(), Errno> {
    let denied = ctx.shared().guard.denied_names(&place.parent_path);
    for name in denied {
        if name.as_slice() == place.name.as_slice() {
            continue;
        }
        let Ok(stat) =
            rustix::fs::statat(&place.parent, name.as_slice(), AtFlags::SYMLINK_NOFOLLOW)
        else {
            continue;
        };
        if identity(&stat) == identity(created) {
            let _ = rustix::fs::unlinkat(&place.parent, place.kernel_name(), AtFlags::empty())
                .or_else(|_| {
                    rustix::fs::unlinkat(&place.parent, place.kernel_name(), AtFlags::REMOVEDIR)
                });
            let target = place.parent_path.join(std::ffi::OsStr::from_bytes(name));
            return Err(refuse(ctx, call, Operation::WriteCreate, &target));
        }
    }
    Ok(())
}

// -- Creation ----------------------------------------------------------------

fn mkdir(ctx: &Context, call: &Call<'_>, dirfd: i32, path: usize, mode: usize) -> Out {
    let place = place_of(call, dirfd, path, ResolveFlags::empty())?;
    let target = place.target();
    if ctx.shared().guard.write_denied(&target) {
        return Err(refuse(ctx, call, Operation::WriteCreate, &target));
    }
    let mode = call.word(mode);
    if ctx.shared().guard.is_ancestor(&place.parent_path)
        && let Some((held, stat)) = pooled(ctx, &place, Kind::Directory)?
    {
        settle(ctx, call, &place, &held, mode, true)?;
        casefold_check(ctx, call, &place, &stat)?;
        return Ok(Reply::Value(0));
    }
    rustix::fs::mkdirat(&place.parent, place.kernel_name(), mode_of(mode))?;
    if let Ok(stat) = place.stat() {
        casefold_check(ctx, call, &place, &stat)?;
    }
    Ok(Reply::Value(0))
}

fn mknod(
    ctx: &Context,
    call: &Call<'_>,
    dirfd: i32,
    path: usize,
    mode: usize,
    device: usize,
) -> Out {
    let place = place_of(call, dirfd, path, ResolveFlags::empty())?;
    let target = place.target();
    if ctx.shared().guard.write_denied(&target) {
        return Err(refuse(ctx, call, Operation::WriteCreate, &target));
    }
    let mode = call.word(mode);
    let kind = match mode & libc::S_IFMT {
        0 => FileType::RegularFile,
        _ => FileType::from_raw_mode(mode),
    };
    if kind == FileType::RegularFile
        && ctx.shared().guard.is_ancestor(&place.parent_path)
        && let Some((held, stat)) = pooled(ctx, &place, Kind::File)?
    {
        settle(ctx, call, &place, &held, mode, false)?;
        casefold_check(ctx, call, &place, &stat)?;
        return Ok(Reply::Value(0));
    }
    rustix::fs::mknodat(
        &place.parent,
        place.kernel_name(),
        kind,
        mode_of(mode),
        call.args[device],
    )?;
    if let Ok(stat) = place.stat() {
        casefold_check(ctx, call, &place, &stat)?;
    }
    Ok(Reply::Value(0))
}

fn symlink(ctx: &Context, call: &Call<'_>, target: usize, dirfd: i32, path: usize) -> Out {
    let contents = path_argument(call, target)?;
    let place = place_of(call, dirfd, path, ResolveFlags::empty())?;
    let name = place.target();
    if ctx.shared().guard.write_denied(&name) {
        return Err(refuse(ctx, call, Operation::WriteCreate, &name));
    }
    rustix::fs::symlinkat(contents.as_slice(), &place.parent, place.kernel_name())?;
    if let Ok(stat) = place.stat() {
        casefold_check(ctx, call, &place, &stat)?;
    }
    Ok(Reply::Value(0))
}

fn link(ctx: &Context, call: &Call<'_>, old: (i32, usize), new: (i32, usize), flags: u32) -> Out {
    let shared = ctx.shared();
    let destination = place_of(call, new.0, new.1, ResolveFlags::empty())?;
    let name = destination.target();
    if shared.guard.write_denied(&name) {
        return Err(refuse(ctx, call, Operation::WriteCreate, &name));
    }

    let old_path = path_argument(call, old.1)?;
    let linked = if old_path.is_empty() && flags & AT_EMPTY_PATH != 0 {
        // A file named by a descriptor, as `O_TMPFILE` files are linked in.
        let held = if old.0 == AT_FDCWD {
            call.caller.base(AT_FDCWD)?
        } else {
            call.caller.reopen(old.0)?
        };
        let (path, stat) = resolve::identify(&held)?;
        check_source(ctx, call, &path, &stat)?;
        rustix::fs::linkat(
            CWD,
            format!("/proc/self/fd/{}", held.as_raw_fd()),
            &destination.parent,
            destination.kernel_name(),
            AtFlags::SYMLINK_FOLLOW,
        )
    } else {
        let mut source = resolve::resolve(
            call.caller,
            Base::Dirfd(old.0),
            &old_path,
            ResolveFlags::empty(),
        )?;
        let follow = flags & AT_SYMLINK_FOLLOW != 0;
        if follow {
            source = resolve::follow(call.caller, source, ResolveFlags::empty())?;
        }
        let stat = rustix::fs::statat(
            &source.parent,
            source.kernel_name(),
            if follow {
                AtFlags::empty()
            } else {
                AtFlags::SYMLINK_NOFOLLOW
            },
        )?;
        check_source(ctx, call, &source.target(), &stat)?;
        rustix::fs::linkat(
            &source.parent,
            source.kernel_name(),
            &destination.parent,
            destination.kernel_name(),
            if follow {
                AtFlags::SYMLINK_FOLLOW
            } else {
                AtFlags::empty()
            },
        )
    };
    linked?;
    if let Ok(stat) = destination.stat() {
        casefold_check(ctx, call, &destination, &stat)?;
    }
    Ok(Reply::Value(0))
}

/// A hard link makes the same file reachable under a name the policy does not
/// cover, so a file in a denied tree, or with a name in one, is not linked.
fn check_source(ctx: &Context, call: &Call<'_>, path: &Path, stat: &Stat) -> Result<(), Errno> {
    let guard = &ctx.shared().guard;
    if guard.write_denied(path) || guard.read_denied(path) || guard.inode_denied(identity(stat)) {
        return Err(refuse(ctx, call, Operation::WriteCreate, path));
    }
    Ok(())
}

fn rename(ctx: &Context, call: &Call<'_>, old: (i32, usize), new: (i32, usize), flags: u32) -> Out {
    // `serve` holds the write side for a rename and the read side for every
    // other call across its check and its act, so a checked name is still the
    // name when it is acted on.
    let shared = ctx.shared();
    let source = place_of(call, old.0, old.1, ResolveFlags::empty())?;
    let destination = place_of(call, new.0, new.1, ResolveFlags::empty())?;
    let (from, to) = (source.target(), destination.target());
    if shared.guard.removal_denied(&from) {
        return Err(refuse(ctx, call, Operation::WriteUnlink, &from));
    }
    if shared.guard.removal_denied(&to) {
        return Err(refuse(ctx, call, Operation::WriteCreate, &to));
    }
    // A file moved into a directory above a denied path keeps no grant there,
    // so it would become unreadable; refusing with `EXDEV` makes the caller copy
    // it instead, which creates a pooled entry.
    if shared.guard.is_ancestor(&destination.parent_path)
        && source.parent_path != destination.parent_path
        && !shared.guard.is_ancestor(&source.parent_path)
        && let Ok(stat) = source.stat()
        && (is(&stat, FileType::RegularFile) || is(&stat, FileType::Directory))
    {
        return Err(Errno(libc::EXDEV));
    }
    rustix::fs::renameat_with(
        &source.parent,
        source.kernel_name(),
        &destination.parent,
        destination.kernel_name(),
        RenameFlags::from_bits_retain(flags),
    )?;
    if let Ok(stat) = destination.stat() {
        casefold_check(ctx, call, &destination, &stat)?;
    }
    Ok(Reply::Value(0))
}

fn unlink(ctx: &Context, call: &Call<'_>, dirfd: i32, path: usize, flags: u32) -> Out {
    let place = place_of(call, dirfd, path, ResolveFlags::empty())?;
    let target = place.target();
    if ctx.shared().guard.removal_denied(&target) {
        return Err(refuse(ctx, call, Operation::WriteUnlink, &target));
    }
    let at = if flags & AT_REMOVEDIR != 0 {
        AtFlags::REMOVEDIR
    } else {
        AtFlags::empty()
    };
    rustix::fs::unlinkat(&place.parent, place.kernel_name(), at)?;
    Ok(Reply::Value(0))
}

fn truncate(ctx: &Context, call: &Call<'_>) -> Out {
    let shared = ctx.shared();
    let place = place_of(call, AT_FDCWD, 0, ResolveFlags::empty())?;
    let place = resolve::follow(call.caller, place, ResolveFlags::empty())?;
    let target = place.target();
    if shared.guard.write_denied(&target) {
        return Err(refuse(ctx, call, Operation::WriteData, &target));
    }
    if let Ok(stat) = place.stat()
        && shared.guard.inode_denied(identity(&stat))
    {
        return Err(refuse(ctx, call, Operation::WriteData, &target));
    }
    let length = u64::try_from(call.args[1] as i64).map_err(|_| Errno(libc::EINVAL))?;
    let fd = rustix::fs::openat(
        &place.parent,
        place.kernel_name(),
        OFlags::WRONLY | OFlags::NONBLOCK | OFlags::NOCTTY | OFlags::CLOEXEC | nofollow(&place),
        Mode::empty(),
    )?;
    rustix::fs::ftruncate(&fd, length)?;
    Ok(Reply::Value(0))
}

// -- Metadata ----------------------------------------------------------------

/// What a metadata call names.
enum Subject {
    /// A path; `follow` says whether a link at its end is followed.
    Path {
        dirfd: i32,
        path: usize,
        follow: bool,
        empty: bool,
    },
    /// An open descriptor of the caller.
    Fd(i32),
}

fn path_subject(dirfd: i32, path: usize, follow: bool) -> Subject {
    Subject::Path {
        dirfd,
        path,
        follow,
        empty: false,
    }
}

/// A path whose handling follows the `AT_` flags the caller passed.
fn flagged_subject(dirfd: i32, path: usize, flags: u32) -> Subject {
    Subject::Path {
        dirfd,
        path,
        follow: flags & AT_SYMLINK_NOFOLLOW == 0,
        empty: flags & AT_EMPTY_PATH != 0,
    }
}

/// The object a metadata call acts on, held so that it is the one checked.
struct Held {
    fd: OwnedFd,
    stat: Stat,
    /// The name, for the calls that can act on a symbolic link itself.
    place: Option<Place>,
}

impl Held {
    fn proc_path(&self) -> String {
        format!("/proc/self/fd/{}", self.fd.as_raw_fd())
    }

    fn is_symlink(&self) -> bool {
        is(&self.stat, FileType::Symlink)
    }
}

fn hold_subject(
    ctx: &Context,
    call: &Call<'_>,
    subject: &Subject,
    operation: Operation,
) -> Result<Held, Errno> {
    let (fd, place) = match *subject {
        Subject::Fd(fd) => (call.caller.reopen(fd)?, None),
        Subject::Path {
            dirfd,
            path,
            follow,
            empty,
        } => {
            let bytes = path_argument(call, path)?;
            if bytes.is_empty() && empty {
                let fd = if dirfd == AT_FDCWD {
                    call.caller.base(AT_FDCWD)?
                } else {
                    call.caller.reopen(dirfd)?
                };
                (fd, None)
            } else {
                let mut place = resolve::resolve(
                    call.caller,
                    Base::Dirfd(dirfd),
                    &bytes,
                    ResolveFlags::empty(),
                )?;
                if follow {
                    place = resolve::follow(call.caller, place, ResolveFlags::empty())?;
                }
                let fd = rustix::fs::openat(
                    &place.parent,
                    place.kernel_name(),
                    OFlags::PATH
                        | OFlags::CLOEXEC
                        | if follow {
                            OFlags::empty()
                        } else {
                            nofollow(&place)
                        }
                        | if follow && !place.in_proc {
                            OFlags::NOFOLLOW
                        } else {
                            OFlags::empty()
                        },
                    Mode::empty(),
                )?;
                (fd, Some(place))
            }
        }
    };
    let (path, stat) = resolve::identify(&fd)?;
    call.caller.still_valid()?;
    let guard = &ctx.shared().guard;
    if guard.write_denied(&path) || guard.inode_denied(identity(&stat)) {
        return Err(refuse(ctx, call, operation, &path));
    }
    Ok(Held { fd, stat, place })
}

fn chmod(ctx: &Context, call: &Call<'_>, subject: Subject, mode: u32) -> Out {
    let held = hold_subject(ctx, call, &subject, Operation::WriteMode)?;
    if held.is_symlink() {
        return Err(Errno(if matches!(subject, Subject::Fd(_)) {
            libc::EBADF
        } else {
            libc::EOPNOTSUPP
        }));
    }
    rustix::fs::chmodat(CWD, held.proc_path(), mode_of(mode), AtFlags::empty())?;
    Ok(Reply::Value(0))
}

fn chown(ctx: &Context, call: &Call<'_>, subject: Subject, ids: usize) -> Out {
    let held = hold_subject(ctx, call, &subject, Operation::WriteOwner)?;
    let user = Some(call.word(ids))
        .filter(|&id| id != u32::MAX)
        .map(Uid::from_raw);
    let group = Some(call.word(ids + 1))
        .filter(|&id| id != u32::MAX)
        .map(Gid::from_raw);
    match (&held.place, held.is_symlink()) {
        (Some(place), true) => rustix::fs::chownat(
            &place.parent,
            place.kernel_name(),
            user,
            group,
            AtFlags::SYMLINK_NOFOLLOW,
        )?,
        (None, true) => return Err(Errno(libc::EBADF)),
        (_, false) => rustix::fs::chownat(CWD, held.proc_path(), user, group, AtFlags::empty())?,
    }
    Ok(Reply::Value(0))
}

/// How a time call spells the times it sets.
#[derive(Clone, Copy)]
enum Times {
    /// `utimensat`: two `timespec`.
    Timespecs,
    /// `utimes` and `futimesat`: two `timeval`.
    Timevals,
    /// `utime`: a `utimbuf` of two seconds.
    Utime,
}

fn read_times(call: &Call<'_>, kind: Times, index: usize) -> Result<Timestamps, Errno> {
    let now = rustix::fs::Timespec {
        tv_sec: 0,
        tv_nsec: libc::UTIME_NOW as _,
    };
    let address = call.address(index);
    if address == 0 {
        return Ok(Timestamps {
            last_access: now,
            last_modification: now,
        });
    }
    let length = match kind {
        Times::Timespecs | Times::Timevals => 32,
        Times::Utime => 16,
    };
    let bytes = call.caller.read_bytes(address, length)?;
    let word = |at: usize| i64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap_or_default());
    let stamp = |seconds: i64, fraction: i64| rustix::fs::Timespec {
        tv_sec: seconds,
        tv_nsec: fraction as _,
    };
    Ok(match kind {
        Times::Timespecs => Timestamps {
            last_access: stamp(word(0), word(8)),
            last_modification: stamp(word(16), word(24)),
        },
        Times::Timevals => Timestamps {
            last_access: stamp(word(0), word(8).saturating_mul(1000)),
            last_modification: stamp(word(16), word(24).saturating_mul(1000)),
        },
        Times::Utime => Timestamps {
            last_access: stamp(word(0), 0),
            last_modification: stamp(word(8), 0),
        },
    })
}

fn utime(ctx: &Context, call: &Call<'_>, kind: Times, subject: Subject, times: usize) -> Out {
    let timestamps = read_times(call, kind, times)?;
    let held = hold_subject(ctx, call, &subject, Operation::WriteTimes)?;
    match (&held.place, held.is_symlink()) {
        (Some(place), true) => rustix::fs::utimensat(
            &place.parent,
            place.kernel_name(),
            &timestamps,
            AtFlags::SYMLINK_NOFOLLOW,
        )?,
        (None, true) => return Err(Errno(libc::EBADF)),
        (_, false) => {
            rustix::fs::utimensat(CWD, held.proc_path(), &timestamps, AtFlags::empty())?;
        }
    }
    Ok(Reply::Value(0))
}

/// Where the value and flags of `setxattr` are.
#[derive(Clone, Copy)]
enum XattrArgs {
    /// `setxattr(path, name, value, size, flags)`.
    Registers,
    /// `setxattrat(dfd, path, at_flags, name, args, size)`.
    Struct,
}

fn xattr_name(call: &Call<'_>, index: usize) -> Result<Vec<u8>, Errno> {
    let name = call.caller.read_path(call.address(index))?;
    if name.is_empty() || name.len() >= XATTR_NAME_MAX {
        return Err(Errno(libc::ERANGE));
    }
    Ok(name)
}

fn set_xattr(ctx: &Context, call: &Call<'_>, subject: Subject, args: XattrArgs) -> Out {
    // The name, value and flags are copied before the subject is resolved.
    let (name, value, flags) = match args {
        XattrArgs::Registers => {
            let size = call.args[3] as usize;
            if size > XATTR_SIZE_MAX {
                return Err(Errno(libc::E2BIG));
            }
            (
                xattr_name(call, 1)?,
                call.caller.read_bytes(call.address(2), size)?,
                call.word(4),
            )
        }
        XattrArgs::Struct => {
            let usize_ = call.args[5] as usize;
            if usize_ < 16 {
                return Err(Errno(libc::EINVAL));
            }
            let header = call.caller.read_bytes(call.address(4), 16)?;
            let value_address = u64::from_ne_bytes(header[0..8].try_into().unwrap_or_default());
            let size = u32::from_ne_bytes(header[8..12].try_into().unwrap_or_default()) as usize;
            let flags = u32::from_ne_bytes(header[12..16].try_into().unwrap_or_default());
            if size > XATTR_SIZE_MAX {
                return Err(Errno(libc::E2BIG));
            }
            (
                xattr_name(call, 3)?,
                call.caller.read_bytes(value_address, size)?,
                flags,
            )
        }
    };
    let held = hold_subject(ctx, call, &subject, Operation::WriteXattr)?;
    if held.is_symlink() {
        return Err(Errno(libc::EPERM));
    }
    rustix::fs::setxattr(
        held.proc_path(),
        name.as_slice(),
        &value,
        XattrFlags::from_bits_retain(flags),
    )?;
    Ok(Reply::Value(0))
}

fn remove_xattr(ctx: &Context, call: &Call<'_>, subject: Subject, name: usize) -> Out {
    let name = xattr_name(call, name)?;
    let held = hold_subject(ctx, call, &subject, Operation::WriteXattr)?;
    if held.is_symlink() {
        return Err(Errno(libc::EPERM));
    }
    rustix::fs::removexattr(held.proc_path(), name.as_slice())?;
    Ok(Reply::Value(0))
}
