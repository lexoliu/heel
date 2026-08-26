//! Python support: interpreter discovery and virtual environments.

mod venv;

use std::path::{Path, PathBuf};

pub use venv::VenvManager;

/// The interpreter inside a virtual environment.
pub(crate) fn venv_interpreter(venv: &Path) -> PathBuf {
    if cfg!(windows) {
        venv.join("Scripts").join("python.exe")
    } else {
        venv.join("bin").join("python")
    }
}

/// The host's Python interpreter, if there is one.
#[cfg(feature = "python")]
pub(crate) fn system_interpreter() -> Option<PathBuf> {
    which::which("python3")
        .ok()
        .or_else(|| which::which("python").ok())
}

/// The host's Python interpreter, if there is one.
#[cfg(not(feature = "python"))]
pub(crate) fn system_interpreter() -> Option<PathBuf> {
    None
}
