//! Python configuration exposed to JavaScript.

use std::path::PathBuf;

use napi::bindgen_prelude::*;
use napi_derive::napi;

/// Virtual environment configuration.
#[napi(object)]
#[derive(Clone, Default)]
pub struct VenvConfigJs {
    /// Where the environment lives.
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
    pub fn into_rust(self) -> Result<heel::VenvConfig> {
        let mut builder = heel::VenvConfig::builder();

        if let Some(path) = self.path {
            builder = builder.path(PathBuf::from(path));
        }
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
    pub fn into_rust(self) -> Result<heel::PythonConfig> {
        let mut builder = heel::PythonConfig::builder();

        if let Some(venv) = self.venv {
            builder = builder.venv(venv.into_rust()?);
        }
        if let Some(enabled) = self.allow_pip_install {
            builder = builder.allow_pip_install(enabled);
        }

        Ok(builder.build())
    }
}
