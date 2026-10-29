//! Supervising the whole process tree of a sandboxed command on Linux.
//!
//! A descendant that calls `setsid` and outlives its parent is reparented to
//! init, and from then on the only way to find it is to guess from the process
//! table, which turns pid reuse into killing an unrelated process. A command
//! run under a supervisor has no such gap: `heel supervise` runs inside the
//! sandbox as the command's root process and makes itself a child subreaper
//! (never the host), so every orphan of the command is reparented to it, and
//! it reaps nothing it has not yet had the chance to kill.
//!
//! - [`Foreground`]: when the command exits, whatever is left is frozen,
//!   killed and reaped, and reported as a [`TreeReport`].
//! - [`Background`]: the supervisor exits only once the last descendant has.
//! - [`TreeControl::kill`] ends the tree on request, in either mode, and
//!   reports survivors as an error.
//!
//! Dropping the [`Sandbox`](crate::Sandbox) ends a supervised tree through its
//! supervisor too (a kill request, then reaping the supervisor), never by
//! signalling its process group, which would hand every `setsid` member to init.
//!
//! The supervisor reports the command's exit status unchanged: the host
//! waiting on the spawned [`Child`](crate::Child) sees the command's status.
//!
//! This module exists on Linux only; other platforms have no supervisor and
//! no runtime fallback for one.

mod host;
mod procfs;
mod protocol;
mod run;

pub use host::{
    Background, Foreground, ForegroundExit, SupervisedChild, Supervision, TreeControl,
    TreeKillError,
};
pub(crate) use host::{Shared, arguments};
pub use protocol::{LeftoverProcess, Mode, SpawnFailure, TreeReport};
pub use run::{Config, run};
