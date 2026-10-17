//! Windows path comparison, kept pure so its tests run on every platform.
//!
//! `std::path` parses prefixes only when compiled for Windows, so the `\\?\`
//! verbatim form `std::fs::canonicalize` returns there is plain text
//! anywhere else — and a text prefix match is what once read the sibling
//! `C:\Program Files Extra` as inside `C:\Program Files`. The comparison
//! here strips the verbatim prefixes and matches component by component,
//! case-insensitively, the way Windows itself compares.

use std::path::Path;

/// Whether `path` is `root` itself or lives beneath it.
pub(crate) fn contains(root: &Path, path: &Path) -> bool {
    let root = components(root);
    !root.is_empty() && components(path).starts_with(&root)
}

/// The path's components, lowercased.
fn components(path: &Path) -> Vec<String> {
    // `/` is a separator on Windows too; normalizing it first lets the
    // prefixes and the split both look at `\` alone.
    let text = path.to_string_lossy().replace('/', "\\");
    strip_verbatim(&text)
        .split('\\')
        .filter(|component| !component.is_empty())
        .map(str::to_lowercase)
        .collect()
}

/// The path with its verbatim prefix removed.
///
/// `\\?\` makes the rest of the path literal — `\\?\C:\x` is `C:\x` — and
/// `\\?\UNC\server\share` is the verbatim spelling of the `\\server\share`
/// form, so the marker goes with the prefix.
fn strip_verbatim(text: &str) -> &str {
    let Some(rest) = text.strip_prefix(r"\\?\") else {
        return text;
    };
    match rest.get(..4) {
        Some(marker) if marker.eq_ignore_ascii_case("UNC\\") => &rest[4..],
        _ => rest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verbatim_path_matches_its_plain_root() {
        assert!(contains(
            Path::new(r"C:\Program Files"),
            Path::new(r"\\?\C:\Program Files\App")
        ));
    }

    #[test]
    fn a_plain_path_matches_its_verbatim_root() {
        assert!(contains(
            Path::new(r"\\?\C:\Program Files"),
            Path::new(r"C:\Program Files\App")
        ));
    }

    #[test]
    fn a_verbatim_unc_path_matches_the_share() {
        assert!(contains(
            Path::new(r"\\server\share"),
            Path::new(r"\\?\UNC\server\share\dir")
        ));
        assert!(contains(
            Path::new(r"\\?\UNC\server\share"),
            Path::new(r"\\server\share\dir")
        ));
    }

    #[test]
    fn components_compare_case_insensitively() {
        assert!(contains(
            Path::new(r"c:\program files"),
            Path::new(r"C:\PROGRAM FILES\app")
        ));
    }

    #[test]
    fn a_sibling_sharing_a_component_prefix_does_not_match() {
        assert!(!contains(
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\Program Files Extra")
        ));
    }

    #[test]
    fn the_root_itself_matches() {
        assert!(contains(
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\Program Files")
        ));
    }

    #[test]
    fn forward_slashes_separate_components() {
        assert!(contains(
            Path::new("C:/Program Files"),
            Path::new(r"C:\Program Files\App")
        ));
    }

    #[test]
    fn a_different_root_does_not_match() {
        assert!(!contains(
            Path::new(r"C:\Program Files"),
            Path::new(r"D:\Program Files\App")
        ));
    }

    #[test]
    fn an_empty_root_matches_nothing() {
        assert!(!contains(Path::new(""), Path::new(r"C:\anything")));
    }
}
