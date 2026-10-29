//! Python configuration exposed to JavaScript.

use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Virtual environment configuration.
#[napi(object)]
#[derive(Clone, Default)]
pub struct VenvConfigJs {
    /// Where the environment lives. It must exist; the path is resolved once, when the sandbox is created,
    /// and a path crossing a link that a sandbox could have planted is refused.
    pub path: Option<String>,
    /// Interpreter used to create the environment.
    pub python: Option<String>,
    /// Packages to install.
    pub packages: Option<Vec<String>>,
    /// Expose the system's site-packages.
    pub system_site_packages: Option<bool>,
    /// Tool used to create the environment: `auto`, `uv`, or `python`.
    pub backend: Option<String>,
}

impl VenvConfigJs {
    /// Build the configuration around `path`, the environment's resolved location.
    pub fn into_rust(self, path: PathBuf) -> Result<heel::VenvConfig> {
        let mut builder = heel::VenvConfig::builder().path(path);
        if let Some(python) = self.python {
            builder = builder.python(PathBuf::from(python));
        }
        if let Some(packages) = self.packages {
            builder = builder.packages(packages);
        }
        if let Some(enabled) = self.system_site_packages {
            builder = builder.system_site_packages(enabled);
        }
        if let Some(backend) = self.backend {
            builder = builder.backend(match backend.as_str() {
                "auto" => heel::VenvBackend::Auto,
                "uv" => heel::VenvBackend::Uv,
                "python" => heel::VenvBackend::Python,
                other => {
                    return Err(Error::from_reason(format!(
                        "unknown venv backend: {other}. Supported: auto, uv, python"
                    )));
                }
            });
        }

        Ok(builder.build())
    }
}

/// Python configuration.
#[napi(object)]
#[derive(Clone, Default)]
pub struct PythonConfigJs {
    /// Virtual environment configuration.
    pub venv: Option<VenvConfigJs>,
    /// Let the sandboxed process write to the virtual environment.
    pub allow_pip_install: Option<bool>,
}

impl PythonConfigJs {
    /// Where the environment lives, before resolution: the configured path, or
    /// the library's default when none is given.
    pub fn venv_path(&self) -> PathBuf {
        self.venv
            .as_ref()
            .and_then(|venv| venv.path.clone())
            .map_or_else(
                || heel::VenvConfig::default().path().to_path_buf(),
                PathBuf::from,
            )
    }

    /// Whether the sandbox may write the environment.
    pub fn writes_environment(&self) -> bool {
        self.allow_pip_install
            .unwrap_or_else(|| heel::PythonConfig::default().allow_pip_install())
    }

    /// Build the configuration around `venv_path`, the environment's resolved location.
    pub fn into_rust(self, venv_path: PathBuf) -> Result<heel::PythonConfig> {
        let mut builder = heel::PythonConfig::builder();

        builder = builder.venv(self.venv.unwrap_or_default().into_rust(venv_path)?);
        if let Some(enabled) = self.allow_pip_install {
            builder = builder.allow_pip_install(enabled);
        }

        Ok(builder.build())
    }
}
