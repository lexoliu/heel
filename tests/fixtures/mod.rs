use std::path::{Path, PathBuf};

pub fn compile(dir: &Path, source: &str, name: &str) -> PathBuf {
    let binary = dir
        .join(name)
        .with_extension(std::env::consts::EXE_EXTENSION);
    let input = dir.join(name).with_extension("rs");
    std::fs::write(&input, source).expect("fixture source");
    let result = std::process::Command::new("rustc")
        .args(["--edition=2021", "-O", "-o"])
        .arg(&binary)
        .arg(&input)
        .output()
        .expect("fixture compiler");
    assert!(
        result.status.success(),
        "rustc: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    binary
}
