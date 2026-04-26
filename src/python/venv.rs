//! Virtual environment management for Python sandboxing

use std::path::{Path, PathBuf};
use std::process::Command;

use blocking::unblock;

use crate::config::VenvConfig;
use crate::error::{Error, Result};

/// Manages a Python virtual environment
pub struct VenvManager {
    path: PathBuf,
    python_path: PathBuf,
    site_packages_path: PathBuf,
}

impl VenvManager {
    /// Create a new virtual environment from configuration
    pub async fn create(config: &VenvConfig) -> Result<Self> {
        let path = config.path().to_path_buf();

        tracing::debug!(path = %path.display(), "venv: creating virtual environment");

        // Check if venv already exists
        if path.exists() {
            tracing::debug!(path = %path.display(), "venv: already exists, reusing");
            return Self::from_existing(&path);
        }

        // Determine which tool to use for venv creation
        if config.use_uv() && Self::has_uv() {
            Self::create_with_uv(config).await
        } else {
            Self::create_with_python(config).await
        }
    }

    /// Load an existing virtual environment
    pub fn from_existing(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::VenvNotFound(path.to_path_buf()));
        }

        let python_path = Self::python_executable(path);
        if !python_path.exists() {
            return Err(Error::VenvNotFound(path.to_path_buf()));
        }

        let site_packages_path = Self::find_site_packages(path)?;

        tracing::debug!(
            path = %path.display(),
            python = %python_path.display(),
            "venv: loaded existing environment"
        );

        Ok(Self {
            path: path.to_path_buf(),
            python_path,
            site_packages_path,
        })
    }

    /// Check if uv is available
    fn has_uv() -> bool {
        resolve_tool("uv").is_some()
    }

    /// Create venv using uv (faster)
    async fn create_with_uv(config: &VenvConfig) -> Result<Self> {
        let path = config.path();

        tracing::debug!(path = %path.display(), "venv: creating with uv");

        let mut cmd = Command::new("uv");
        cmd.arg("venv").arg(path);

        if let Some(python) = config.python() {
            cmd.arg("--python").arg(python);
        }

        if config.system_site_packages() {
            cmd.arg("--system-site-packages");
        }

        let output = unblock(move || cmd.output()).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::VenvCreationFailed(stderr.to_string()));
        }

        tracing::debug!(path = %path.display(), "venv: created successfully with uv");

        // Install packages if specified
        let manager = Self::from_existing(path)?;
        manager.install_packages_uv(config.packages()).await?;

        Ok(manager)
    }

    /// Create venv using Python's venv module
    async fn create_with_python(config: &VenvConfig) -> Result<Self> {
        let path = config.path();

        // Find Python interpreter
        let python = config
            .python()
            .map(|p| p.to_path_buf())
            .or_else(Self::resolve_python_interpreter)
            .ok_or(Error::PythonNotFound)?;

        tracing::debug!(
            path = %path.display(),
            python = %python.display(),
            "venv: creating with python -m venv"
        );

        let mut cmd = Command::new(&python);
        cmd.arg("-m").arg("venv").arg(path);

        if config.system_site_packages() {
            cmd.arg("--system-site-packages");
        }

        let output = unblock(move || cmd.output()).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::VenvCreationFailed(stderr.to_string()));
        }

        tracing::debug!(path = %path.display(), "venv: created successfully with python");

        // Install packages if specified
        let manager = Self::from_existing(path)?;
        manager.install_packages_pip(config.packages()).await?;

        Ok(manager)
    }

    /// Install packages using uv
    async fn install_packages_uv(&self, packages: &[String]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        tracing::debug!(packages = ?packages, "venv: installing packages with uv");

        let mut cmd = Command::new("uv");
        cmd.arg("pip")
            .arg("install")
            .arg("--python")
            .arg(&self.python_path)
            .args(packages);

        let output = unblock(move || cmd.output()).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::PackageInstallFailed(stderr.to_string()));
        }

        tracing::debug!(packages = ?packages, "venv: packages installed successfully");

        Ok(())
    }

    /// Install packages using pip
    async fn install_packages_pip(&self, packages: &[String]) -> Result<()> {
        if packages.is_empty() {
            return Ok(());
        }

        tracing::debug!(packages = ?packages, "venv: installing packages with pip");

        let mut cmd = Command::new(&self.python_path);
        cmd.arg("-m").arg("pip").arg("install").args(packages);

        let output = unblock(move || cmd.output()).await?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::PackageInstallFailed(stderr.to_string()));
        }

        tracing::debug!(packages = ?packages, "venv: packages installed successfully");

        Ok(())
    }

    /// Get the path to the Python executable in this venv
    fn python_executable(venv_path: &Path) -> PathBuf {
        if cfg!(windows) {
            venv_path.join("Scripts").join("python.exe")
        } else {
            venv_path.join("bin").join("python")
        }
    }

    /// Find the site-packages directory
    fn find_site_packages(venv_path: &Path) -> Result<PathBuf> {
        let lib_path = if cfg!(windows) {
            venv_path.join("Lib").join("site-packages")
        } else {
            // On Unix, it's lib/pythonX.Y/site-packages
            let lib_dir = venv_path.join("lib");
            if !lib_dir.exists() {
                return Err(Error::VenvNotFound(venv_path.to_path_buf()));
            }

            // Find the python version directory
            let mut site_packages = None;
            if let Ok(entries) = std::fs::read_dir(&lib_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let name_str = name.to_string_lossy();
                    if name_str.starts_with("python") {
                        let candidate = entry.path().join("site-packages");
                        if candidate.exists() {
                            site_packages = Some(candidate);
                            break;
                        }
                    }
                }
            }

            site_packages.ok_or_else(|| Error::VenvNotFound(venv_path.to_path_buf()))?
        };

        Ok(lib_path)
    }

    /// Get the venv path
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Get the Python executable path
    pub fn python_path(&self) -> &Path {
        &self.python_path
    }

    /// Get the site-packages path
    pub fn site_packages_path(&self) -> &Path {
        &self.site_packages_path
    }

    /// Resolve a runnable Python interpreter for host-side venv setup.
    pub fn resolve_python_interpreter() -> Option<PathBuf> {
        resolve_python_interpreter()
    }
}

#[cfg(feature = "python")]
fn resolve_tool(name: &str) -> Option<PathBuf> {
    which::which(name).ok()
}

#[cfg(not(feature = "python"))]
fn resolve_tool(_name: &str) -> Option<PathBuf> {
    None
}

fn resolve_python_interpreter() -> Option<PathBuf> {
    let path_candidates = ["python3", "python"]
        .into_iter()
        .filter_map(resolve_tool)
        .filter(|path| is_usable_python_path(path));

    path_candidates
        .chain(known_windows_python_candidates())
        .next()
}

fn is_usable_python_path(path: &Path) -> bool {
    if windows_store_python_alias(path) {
        return false;
    }

    path.exists()
}

fn windows_store_python_alias(path: &Path) -> bool {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .contains("\\microsoft\\windowsapps\\python")
}

#[cfg(target_os = "windows")]
fn known_windows_python_candidates() -> impl Iterator<Item = PathBuf> {
    let mut candidates = Vec::new();

    for root in windows_python_search_roots() {
        collect_python_install_candidates(&root, &mut candidates);
    }

    candidates.sort_by_key(|path| path.to_string_lossy().to_ascii_lowercase());
    candidates.reverse();
    candidates.into_iter().filter(|path| path.exists())
}

#[cfg(not(target_os = "windows"))]
fn known_windows_python_candidates() -> impl Iterator<Item = PathBuf> {
    std::iter::empty()
}

#[cfg(target_os = "windows")]
fn windows_python_search_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
        roots.push(
            PathBuf::from(local_app_data)
                .join("Programs")
                .join("Python"),
        );
    }
    if let Some(program_files) = std::env::var_os("ProgramFiles") {
        roots.push(PathBuf::from(program_files));
    }
    if let Some(program_files_x86) = std::env::var_os("ProgramFiles(x86)") {
        roots.push(PathBuf::from(program_files_x86));
    }

    roots
}

#[cfg(target_os = "windows")]
fn collect_python_install_candidates(root: &Path, candidates: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(root) else {
        return;
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.to_ascii_lowercase().starts_with("python") {
            continue;
        }
        candidates.push(path.join("python.exe"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_python_executable_path() {
        let path = Path::new("/tmp/test-venv");

        #[cfg(unix)]
        assert_eq!(
            VenvManager::python_executable(path),
            PathBuf::from("/tmp/test-venv/bin/python")
        );

        #[cfg(windows)]
        assert_eq!(
            VenvManager::python_executable(path),
            PathBuf::from("/tmp/test-venv/Scripts/python.exe")
        );
    }

    #[test]
    fn windows_store_python_aliases_are_rejected() {
        let alias = Path::new(r"C:\Users\name\AppData\Local\Microsoft\WindowsApps\python.exe");
        assert!(super::windows_store_python_alias(alias));
    }
}
