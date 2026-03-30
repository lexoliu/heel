use std::path::PathBuf;

use napi_derive::napi;

/// Virtual environment configuration
#[napi(object)]
#[derive(Clone, Default)]
pub struct VenvConfigJs {
    /// Path to the virtual environment
    pub path: Option<String>,
    /// Python interpreter path
    pub python: Option<String>,
    /// Packages to install
    pub packages: Option<Vec<String>>,
    /// Include system site-packages
    pub system_site_packages: Option<bool>,
    /// Use uv package manager
    pub use_uv: Option<bool>,
}

impl VenvConfigJs {
    pub fn into_rust(self) -> heel::VenvConfig {
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
        if let Some(enabled) = self.use_uv {
            builder = builder.use_uv(enabled);
        }

        builder.build()
    }
}

/// Python sandbox configuration
#[napi(object)]
#[derive(Clone, Default)]
pub struct PythonConfigJs {
    /// Virtual environment configuration
    pub venv: Option<VenvConfigJs>,
    /// Allow pip install in sandbox
    pub allow_pip_install: Option<bool>,
}

impl PythonConfigJs {
    pub fn into_rust(self) -> heel::PythonConfig {
        let mut builder = heel::PythonConfig::builder();

        if let Some(venv) = self.venv {
            builder = builder.venv(venv.into_rust());
        }
        if let Some(enabled) = self.allow_pip_install {
            builder = builder.allow_pip_install(enabled);
        }

        builder.build()
    }
}
