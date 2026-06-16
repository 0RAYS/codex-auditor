use anyhow::{Result, anyhow};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_EXCLUDE_PARTS: &[&str] = &[
    ".git",
    ".hg",
    ".svn",
    ".cache",
    "__pycache__",
    "node_modules",
    "target",
    "build",
    "out",
    "dist",
    "vendor",
    "third_party",
];

const C_FAMILY_EXTS: &[&str] = &["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"];

pub fn absolutize_path(workspace: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        workspace.join(path)
    }
}

pub fn rel(workspace: &Path, path: &Path) -> Result<String> {
    Ok(fs::canonicalize(path)?
        .strip_prefix(workspace)
        .map_err(|_| anyhow!("path is outside workspace: {}", path.display()))?
        .to_string_lossy()
        .replace('\\', "/"))
}

pub fn in_workspace(workspace: &Path, path: &Path) -> bool {
    fs::canonicalize(path)
        .ok()
        .and_then(|p| p.strip_prefix(workspace).ok().map(|_| ()))
        .is_some()
}

pub fn ext(path: &Path) -> String {
    path.extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
}

pub fn source_lang(path: &Path) -> Option<&'static str> {
    match ext(path).as_str() {
        "c" => Some("c"),
        "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx" => Some("cpp"),
        "h" => Some("c-header"),
        _ => None,
    }
}

pub fn is_c_family(path: &Path) -> bool {
    C_FAMILY_EXTS.contains(&ext(path).as_str())
}

pub fn should_skip(path: &Path, exclude_parts: &HashSet<String>) -> bool {
    path.components().any(|part| {
        part.as_os_str()
            .to_str()
            .is_some_and(|value| exclude_parts.contains(value))
    })
}
