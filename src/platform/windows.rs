//! Windows backend.
//!
//! AppContainer support is not implemented yet. Construction fails rather than
//! returning a backend whose every call errors: a sandbox that cannot isolate
//! must not look like one that can.

use std::process::Output;

use crate::error::{Error, Result};
use crate::platform::{Backend, Child, SpawnRequest};

/// Windows sandbox backend.
pub struct WindowsBackend {
    _private: (),
}

impl WindowsBackend {
    /// Fails until AppContainer support is implemented.
    pub fn new() -> Result<Self> {
        Err(Error::UnsupportedPlatform)
    }
}

impl Backend for WindowsBackend {
    async fn execute(&self, _request: SpawnRequest<'_>) -> Result<Output> {
        Err(Error::UnsupportedPlatform)
    }

    async fn spawn(&self, _request: SpawnRequest<'_>) -> Result<Child> {
        Err(Error::UnsupportedPlatform)
    }
}
