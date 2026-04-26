use std::path::{Path, PathBuf};

use crate::config::SandboxConfigData;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RootAccess {
    Read,
    #[allow(dead_code)]
    Write,
    Execute,
    Full,
    Runtime,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RootGrant {
    pub path: PathBuf,
    pub access: RootAccess,
    pub is_directory: bool,
}

pub(crate) fn grant(path: impl AsRef<Path>, access: RootAccess, is_directory: bool) -> RootGrant {
    RootGrant {
        path: path.as_ref().to_path_buf(),
        access,
        is_directory,
    }
}

pub(crate) fn grants_from_config(config: &SandboxConfigData) -> Vec<RootGrant> {
    let mut grants = Vec::new();

    grants.push(grant(config.working_dir(), RootAccess::Full, true));
    grants.extend(
        config
            .readable_paths()
            .iter()
            .map(|path| grant(path, RootAccess::Read, path.is_dir())),
    );
    grants.extend(
        config
            .writable_paths()
            .iter()
            .map(|path| grant(path, RootAccess::Full, path.is_dir())),
    );
    grants.extend(
        config
            .executable_paths()
            .iter()
            .map(|path| grant(path, RootAccess::Execute, path.is_dir())),
    );

    if let Some(python) = config.python() {
        grants.extend(python_runtime_grants(python));
    }

    grants
}

fn python_runtime_grants(python: &crate::config::PythonConfig) -> Vec<RootGrant> {
    let venv = python.venv();
    let mut grants = vec![grant(venv.path(), RootAccess::Runtime, true)];

    if let Some(runtime_root) = venv.python().and_then(python_runtime_root_for_executable) {
        grants.push(grant(runtime_root, RootAccess::Runtime, true));
    }

    grants.extend(
        pyvenv_runtime_roots(venv.path())
            .into_iter()
            .map(|path| grant(path, RootAccess::Runtime, true)),
    );

    grants
}

fn python_runtime_root_for_executable(python: &Path) -> Option<PathBuf> {
    python.parent().map(Path::to_path_buf)
}

fn pyvenv_runtime_roots(venv_path: &Path) -> Vec<PathBuf> {
    let Ok(config) = std::fs::read_to_string(venv_path.join("pyvenv.cfg")) else {
        return Vec::new();
    };

    pyvenv_runtime_roots_from_text(&config)
}

fn pyvenv_runtime_roots_from_text(config: &str) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for line in config.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let value = value.trim().trim_matches('"');
        if value.is_empty() {
            continue;
        }

        if key.eq_ignore_ascii_case("home") {
            roots.push(PathBuf::from(value));
        } else if key.eq_ignore_ascii_case("executable")
            && let Some(root) = python_runtime_root_for_executable(Path::new(value))
        {
            roots.push(root);
        }
    }

    roots
}

#[cfg(test)]
mod tests {
    use super::{RootAccess, grant};
    use crate::{PythonConfig, VenvConfig};

    #[test]
    fn grant_keeps_path_and_access() {
        let item = grant("C:/HeelTest/session", RootAccess::Full, true);

        assert_eq!(item.path.to_string_lossy(), "C:/HeelTest/session");
        assert_eq!(item.access, RootAccess::Full);
        assert!(item.is_directory);
    }

    #[test]
    fn write_access_class_is_available_for_acl_specialization() {
        let item = grant("C:/HeelTest/out.log", RootAccess::Write, false);

        assert_eq!(item.access, RootAccess::Write);
        assert!(!item.is_directory);
    }

    #[test]
    fn grants_from_config_maps_roots_to_access_classes() {
        let (_, config) = crate::config::SandboxConfig::builder()
            .working_dir("C:/HeelTest/work")
            .readable_path("C:/HeelTest/read")
            .writable_path("C:/HeelTest/write")
            .executable_path("C:/HeelTest/python")
            .build()
            .expect("config")
            .into_parts();

        let grants = super::grants_from_config(&config);

        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Full && item.path.ends_with("work"))
        );
        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Read && item.path.ends_with("read"))
        );
        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Full && item.path.ends_with("write"))
        );
        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Execute && item.path.ends_with("python"))
        );
    }

    #[test]
    fn grants_from_config_includes_python_venv_and_base_runtime() {
        let python = PythonConfig::builder()
            .venv(
                VenvConfig::builder()
                    .path("C:/HeelTest/venv")
                    .python("C:/Python314/python.exe")
                    .build(),
            )
            .build();
        let (_, config) = crate::config::SandboxConfig::builder()
            .working_dir("C:/HeelTest/work")
            .python(python)
            .build()
            .expect("config")
            .into_parts();

        let grants = super::grants_from_config(&config);

        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Runtime && item.path.ends_with("venv"))
        );
        assert!(
            grants
                .iter()
                .any(|item| item.access == RootAccess::Runtime && item.path.ends_with("Python314"))
        );
    }

    #[test]
    fn pyvenv_runtime_roots_parse_home_and_executable() {
        let roots = super::pyvenv_runtime_roots_from_text(
            "home = C:/Python314\nexecutable = C:/Python314/python.exe\n",
        );

        assert!(roots.iter().any(|path| path.ends_with("Python314")));
        assert_eq!(roots.len(), 2);
    }

    #[test]
    fn grants_from_config_do_not_expand_permissive_security_to_home() {
        let (_, config) = crate::config::SandboxConfig::builder()
            .working_dir("C:/HeelTest/work")
            .security(crate::SecurityConfig::permissive())
            .build()
            .expect("config")
            .into_parts();

        let grants = super::grants_from_config(&config);

        assert_eq!(grants.len(), 1);
        assert!(grants[0].path.ends_with("work"));
    }
}
