//! `connect` and `bind`, performed by the broker on the caller's socket.
//!
//! The address is copied out of the stopped process once and the call is made on
//! that copy, so the address that was judged is the address that is used. The
//! socket is the caller's own: the broker takes a duplicate of the descriptor,
//! which is the same open file description, and acts on it.
//!
//! Outbound TCP may reach one place, the proxy, at its loopback address and
//! port. A unix socket may be connected to unless it belongs to a credential
//! agent or to the user's runtime directory; abstract sockets have no path to
//! check and are refused outright when a read denylist is in force.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

use rustix::fs::ResolveFlags;

use super::Context;
use super::notify::{self, Reply};
use super::ops::{Call, Errno, Out, refuse};
use super::resolve::{self, AT_FDCWD, Base};
use super::sink::Operation;

/// The longest `sockaddr` the kernel accepts, `sizeof(struct sockaddr_storage)`.
const SOCKADDR_MAX: usize = 128;
/// `sizeof(sa_family_t)`.
const FAMILY_LEN: usize = 2;
/// `sizeof(sockaddr_un.sun_path)`.
const SUN_PATH_LEN: usize = 108;

/// What an address names.
enum Address {
    Inet { ip: Ipv4Addr, port: u16 },
    Inet6 { ip: Ipv6Addr, port: u16 },
    Path(Vec<u8>),
    Abstract,
    Other,
}

/// The address argument of a call, as bytes and as what they mean.
struct Parsed {
    bytes: Vec<u8>,
    address: Address,
}

fn parse(call: &Call<'_>) -> Result<Parsed, Errno> {
    let length = usize::try_from(call.args[2] as i32).map_err(|_| Errno(libc::EINVAL))?;
    if length > SOCKADDR_MAX {
        return Err(Errno(libc::EINVAL));
    }
    if length < FAMILY_LEN {
        return Err(Errno(libc::EINVAL));
    }
    let bytes = call.caller.read_bytes(call.args[1], length)?;
    let family = i32::from(u16::from_ne_bytes([bytes[0], bytes[1]]));
    let port = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let address = match family {
        libc::AF_INET if length >= 8 => Address::Inet {
            ip: Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
            port: port(2),
        },
        libc::AF_INET6 if length >= 24 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[8..24]);
            Address::Inet6 {
                ip: Ipv6Addr::from(octets),
                port: port(2),
            }
        }
        libc::AF_UNIX if length > FAMILY_LEN && bytes[FAMILY_LEN] == 0 => Address::Abstract,
        libc::AF_UNIX if length > FAMILY_LEN => {
            let path = &bytes[FAMILY_LEN..];
            let end = path
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(path.len());
            Address::Path(path[..end].to_vec())
        }
        _ => Address::Other,
    };
    Ok(Parsed { bytes, address })
}

/// The IPv4 address an IPv6 address stands for, if it is an IPv4-mapped one.
fn mapped(ip: Ipv6Addr) -> Option<Ipv4Addr> {
    ip.to_ipv4_mapped()
}

pub(crate) fn connect(ctx: &Context, call: &Call<'_>) -> Out {
    let parsed = parse(call)?;
    let shared = ctx.shared();
    match &parsed.address {
        Address::Inet { ip, port } => {
            if !shared.proxy_reachable(*ip, *port) {
                return Err(refuse_network(
                    ctx,
                    call,
                    Operation::NetworkOutbound,
                    &format!("{ip}:{port}"),
                ));
            }
        }
        Address::Inet6 { ip, port } => {
            let allowed = mapped(*ip).is_some_and(|ip| shared.proxy_reachable(ip, *port));
            if !allowed {
                return Err(refuse_network(
                    ctx,
                    call,
                    Operation::NetworkOutbound,
                    &format!("[{ip}]:{port}"),
                ));
            }
        }
        Address::Abstract if shared.guard.abstract_sockets_denied() => {
            return Err(refuse_network(
                ctx,
                call,
                Operation::NetworkOutbound,
                "abstract socket",
            ));
        }
        Address::Path(path) => return unix(ctx, call, path, Syscall::Connect),
        Address::Abstract | Address::Other => {}
    }
    let blocking = socket_blocks(call)?;
    if blocking {
        ctx.ensure_spare_worker();
    }
    perform(call, Syscall::Connect, &parsed.bytes)
}

pub(crate) fn bind(ctx: &Context, call: &Call<'_>) -> Out {
    let parsed = parse(call)?;
    let shared = ctx.shared();
    match &parsed.address {
        Address::Inet { ip, port } => {
            if !ip.is_loopback() {
                return Err(refuse_network(
                    ctx,
                    call,
                    Operation::NetworkBind,
                    &format!("{ip}:{port}"),
                ));
            }
        }
        Address::Inet6 { ip, port } => {
            let loopback = ip.is_loopback() || mapped(*ip).is_some_and(|ip| ip.is_loopback());
            if !loopback {
                return Err(refuse_network(
                    ctx,
                    call,
                    Operation::NetworkBind,
                    &format!("[{ip}]:{port}"),
                ));
            }
        }
        Address::Abstract if shared.guard.abstract_sockets_denied() => {
            return Err(refuse_network(
                ctx,
                call,
                Operation::NetworkBind,
                "abstract socket",
            ));
        }
        Address::Path(path) => return unix(ctx, call, path, Syscall::Bind),
        Address::Abstract | Address::Other => {}
    }
    perform(call, Syscall::Bind, &parsed.bytes)
}

fn refuse_network(ctx: &Context, call: &Call<'_>, operation: Operation, target: &str) -> Errno {
    refuse(ctx, call, operation, &PathBuf::from(target))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Syscall {
    Connect,
    Bind,
}

/// Whether the caller's socket has no `O_NONBLOCK`, so a connect may take long
/// enough to need a worker of its own.
fn socket_blocks(call: &Call<'_>) -> Result<bool, Errno> {
    let tgid = call.caller.status()?.tgid;
    let socket = notify::steal_fd(tgid, call.args[0] as i32)?;
    call.caller.still_valid()?;
    let flags = rustix::fs::fcntl_getfl(&socket)?;
    Ok(!flags.contains(rustix::fs::OFlags::NONBLOCK))
}

/// Run the call on the caller's socket with the address already judged.
fn perform(call: &Call<'_>, which: Syscall, address: &[u8]) -> Out {
    let tgid = call.caller.status()?.tgid;
    let socket = notify::steal_fd(tgid, call.args[0] as i32)?;
    call.caller.still_valid()?;
    let length = libc::socklen_t::try_from(address.len()).map_err(|_| Errno(libc::EINVAL))?;
    // SAFETY: `address` is a copy of `length` bytes and the descriptor is open.
    let result = unsafe {
        match which {
            Syscall::Connect => libc::connect(socket.as_raw_fd(), address.as_ptr().cast(), length),
            Syscall::Bind => libc::bind(socket.as_raw_fd(), address.as_ptr().cast(), length),
        }
    };
    if result == 0 {
        Ok(Reply::Value(0))
    } else {
        Err(Errno(
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO),
        ))
    }
}

/// A unix socket at a path: resolved against held directories, judged by real
/// path and inode, and reached through its directory so the name is the one
/// that was judged.
fn unix(ctx: &Context, call: &Call<'_>, path: &[u8], which: Syscall) -> Out {
    let shared = ctx.shared();
    // The name must stay the name from the check to the call that uses it. A
    // bind is served under the lock already; a connect is not.
    let _held = (which == Syscall::Connect).then(|| shared.read_lock());
    let mut place = resolve::resolve(
        call.caller,
        Base::Dirfd(AT_FDCWD),
        path,
        ResolveFlags::empty(),
    )?;
    if which == Syscall::Connect {
        place = resolve::follow(call.caller, place, ResolveFlags::empty())?;
    }
    let target = place.target();
    match which {
        Syscall::Connect => {
            let id = place.stat().ok().map(|stat| (stat.st_dev, stat.st_ino));
            if shared.guard.socket_denied(&target, id) {
                return Err(refuse(ctx, call, Operation::NetworkOutbound, &target));
            }
        }
        Syscall::Bind => {
            if shared.guard.write_denied(&target) {
                return Err(refuse(ctx, call, Operation::WriteCreate, &target));
            }
        }
    }
    let name = place.kernel_name();
    if name.is_empty() || name.len() >= SUN_PATH_LEN {
        return Err(Errno(libc::ENAMETOOLONG));
    }
    let mut local: libc::sockaddr_un = {
        // SAFETY: an all-zero `sockaddr_un` is a valid value.
        unsafe { std::mem::zeroed() }
    };
    local.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (slot, byte) in local.sun_path.iter_mut().zip(name.iter()) {
        *slot = *byte as libc::c_char;
    }
    let length = FAMILY_LEN + name.len() + 1;
    // Only this thread's working directory changes: workers do not share theirs.
    rustix::process::fchdir(&place.parent)?;
    // SAFETY: `local` is a fully initialised `sockaddr_un` and `length` covers
    // its family and the NUL-terminated name.
    let bytes = unsafe { std::slice::from_raw_parts((&raw const local).cast::<u8>(), length) };
    if which == Syscall::Connect && socket_blocks(call)? {
        ctx.ensure_spare_worker();
    }
    let out = perform(call, which, bytes)?;
    if which == Syscall::Bind
        && let Ok(stat) = place.stat()
    {
        super::ops::casefold_check(ctx, call, &place, &stat)?;
    }
    Ok(out)
}
