//! Virtual environment creation and package installation.
//!
//! Environments are prepared on the host, before the sandbox starts, because
//! installing packages needs network access the sandbox denies.

use std::path::{Path, PathBuf};
use std::process::Command;

use blocking::unblock;

use crate::config::{VenvBackend, VenvConfig};
use crate::error::{Error, Result};
use crate::python::venv_interpreter;

/// A prepared Python virtual environment.
#[derive(Debug, Clone)]
pub struct VenvManager {
    path: PathBuf,
    interpreter: PathBuf,
}

impl VenvManager {
    /// Create the environment if needed, then install the configured packages.
    ///
    /// An environment that already exists is reused, but its packages are still
    /// installed: reuse must not silently produce an environment missing what
    /// the configuration asked for.
    pub async fn create(config: &VenvConfig) -> Result<Self> {
        let path = config.path().to_path_buf();

        let manager = if path.exists() {
            tracing::debug!(path = %path.display(), "venv: reusing existing environment");
            Self::from_existing(&path)?
        } else {
            match config.backend().resolve()? {
                Tool::Uv(uv) => Self::create_with_uv(&uv, config).await?,
                Tool::Python(python) => Self::create_with_python(&python, config).await?,
            }
        };

        manager.install(config).await?;
        Ok(manager)
    }

    /// Open an environment that already exists.
    pub fn from_existing(path: &Path) -> Result<Self> {
        let interpreter = venv_interpreter(path);
        if !interpreter.exists() {
            return Err(Error::VenvNotFound(path.to_path_buf()));
        }

        Ok(Self {
            path: path.to_path_buf(),
            interpreter,
        })
    }

    /// Create the environment with `uv`.
    async fn create_with_uv(uv: &Path, config: &VenvConfig) -> Result<Self> {
        let path = config.path();
        tracing::debug!(path = %path.display(), "venv: creating with uv");

        let mut cmd = Command::new(uv);
        cmd.arg("venv").arg(path);
        if let Some(python) = config.python() {
            cmd.arg("--python").arg(python);
        }
        if config.system_site_packages() {
            cmd.arg("--system-site-packages");
        }

        run(cmd, Error::VenvCreationFailed).await?;
        Self::from_existing(path)
    }

    /// Create the environment with `python -m venv`.
    async fn create_with_python(python: &Path, config: &VenvConfig) -> Result<Self> {
        let path = config.path();
        tracing::debug!(path = %path.display(), python = %python.display(), "venv: creating with python -m venv");

        let mut cmd = Command::new(python);
        cmd.arg("-m").arg("venv").arg(path);
        if config.system_site_packages() {
            cmd.arg("--system-site-packages");
        }

        run(cmd, Error::VenvCreationFailed).await?;
        Self::from_existing(path)
    }

    /// Install the configured packages into this environment.
    async fn install(&self, config: &VenvConfig) -> Result<()> {
        if config.packages().is_empty() {
            return Ok(());
        }

        tracing::debug!(packages = ?config.packages(), "venv: installing packages");

        let cmd = match config.backend().resolve()? {
            Tool::Uv(uv) => {
                let mut cmd = Command::new(uv);
                cmd.arg("pip")
                    .arg("install")
                    .arg("--python")
                    .arg(&self.interpreter)
                    .args(config.packages());
                cmd
            }
            Tool::Python(_) => {
                let mut cmd = Command::new(&self.interpreter);
                cmd.arg("-m")
                    .arg("pip")
                    .arg("install")
                    .args(config.packages());
                cmd
            }
        };

        run(cmd, Error::PackageInstallFailed).await
    }

    /// Where the environment lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The environment's interpreter.
    pub fn interpreter(&self) -> &Path {
        &self.interpreter
    }
}

/// The tool that manages an environment.
enum Tool {
    Uv(PathBuf),
    Python(PathBuf),
}

impl VenvBackend {
    /// Locate the tool this backend requires.
    fn resolve(self) -> Result<Tool> {
        match self {
            Self::Uv => locate("uv").map(Tool::Uv).ok_or_else(|| {
                Error::VenvCreationFailed(
                    "`uv` was requested but is not installed; install uv or select another \
                     virtual environment backend"
                        .to_string(),
                )
            }),
            Self::Python => system_python()
                .map(Tool::Python)
                .ok_or(Error::PythonNotFound),
            Self::Auto => match locate("uv") {
                Some(uv) => Ok(Tool::Uv(uv)),
                None => system_python()
                    .map(Tool::Python)
                    .ok_or(Error::PythonNotFound),
            },
        }
    }
}

/// Find the host's Python interpreter.
fn system_python() -> Option<PathBuf> {
    locate("python3").or_else(|| locate("python"))
}

/// Find an executable on `PATH`.
#[cfg(feature = "python")]
fn locate(name: &str) -> Option<PathBuf> {
    which::which(name).ok()
}

/// Find an executable on `PATH`.
#[cfg(not(feature = "python"))]
fn locate(_name: &str) -> Option<PathBuf> {
    None
}

/// Run a command off the executor and turn a non-zero exit into `error`.
async fn run(mut cmd: Command, error: fn(String) -> Error) -> Result<()> {
    let output = unblock(move || cmd.output()).await?;

    if !output.status.success() {
        return Err(error(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interpreter_path_follows_platform_layout() {
        let path = Path::new("/tmp/test-venv");

        #[cfg(unix)]
        assert_eq!(
            venv_interpreter(path),
            PathBuf::from("/tmp/test-venv/bin/python")
        );

        #[cfg(windows)]
        assert_eq!(
            venv_interpreter(path),
            PathBuf::from("/tmp/test-venv/Scripts/python.exe")
        );
    }

    #[test]
    fn opening_a_missing_environment_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = VenvManager::from_existing(&dir.path().join("absent")).unwrap_err();
        assert!(matches!(error, Error::VenvNotFound(_)));
    }

    #[test]
    fn a_directory_without_an_interpreter_is_not_an_environment() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = VenvManager::from_existing(dir.path()).unwrap_err();
        assert!(matches!(error, Error::VenvNotFound(_)));
    }

    #[test]
    fn requiring_uv_reports_a_clear_error_when_it_is_missing() {
        // Only meaningful where uv is absent; where it exists, resolution
        // must succeed instead.
        match VenvBackend::Uv.resolve() {
            Ok(Tool::Uv(path)) => assert!(path.exists()),
            Ok(_) => panic!("VenvBackend::Uv must not resolve to another tool"),
            Err(error) => assert!(
                error.to_string().contains("not installed"),
                "unhelpful error: {error}"
            ),
        }
    }
}
