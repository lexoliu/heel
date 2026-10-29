//! What the host and the supervisor say to each other.
//!
//! One socket pair carries it, one JSON document per line in each direction.
//! The host's end is closed when the host drops its handle, which the
//! supervisor reads as the host being gone.

use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// A process the supervisor found in the tree.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeftoverProcess {
    /// Its process id, as the host sees it.
    pub pid: u32,
    /// Its name (`comm`), read after the tree was frozen.
    pub name: String,
}

/// What a teardown of the tree found.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreeReport {
    /// Processes that were still running and were killed.
    pub killed: Vec<LeftoverProcess>,
    /// Processes that were still alive when the reap budget ran out.
    pub survivors: Vec<LeftoverProcess>,
}

/// How long the supervisor lives, which is what `heel supervise` is told.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Tear the tree down when the command exits.
    Foreground,
    /// Live as long as any descendant does.
    Background,
}

impl Mode {
    /// The spelling `heel supervise --mode` takes.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::Background => "background",
        }
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, String> {
        match text {
            "foreground" => Ok(Self::Foreground),
            "background" => Ok(Self::Background),
            other => Err(format!(
                "unknown supervision mode {other:?}, expected foreground or background"
            )),
        }
    }
}

/// Host to supervisor.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Request {
    /// Freeze, kill and reap the whole tree.
    Kill,
}

/// Supervisor to host.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) enum Event {
    /// The command exited and the tree was torn down (foreground mode).
    Leftover(TreeReport),
    /// A [`Request::Kill`] was carried out.
    Killed(TreeReport),
    /// The supervisor is exiting on its own account: the last thing it says.
    Done,
}

/// The time budget a [`Request`]-driven teardown gets, as the supervisor was
/// started with it.
pub(crate) fn reap_timeout_argument(timeout: Duration) -> String {
    humantime::format_duration(timeout).to_string()
}
