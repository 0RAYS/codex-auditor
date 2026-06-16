use anyhow::{Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

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

#[derive(Clone, Debug, Default)]
pub struct PathCache {
    canonicalized: Arc<Mutex<HashMap<PathBuf, PathBuf>>>,
}

impl PathCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn canonicalize(&self, path: &Path) -> std::io::Result<PathBuf> {
        let key = path.to_path_buf();
        if let Some(value) = self
            .canonicalized
            .lock()
            .expect("path cache mutex poisoned")
            .get(&key)
            .cloned()
        {
            return Ok(value);
        }
        let value = fs::canonicalize(path)?;
        self.canonicalized
            .lock()
            .expect("path cache mutex poisoned")
            .insert(key, value.clone());
        Ok(value)
    }

    pub fn canonicalize_or_original(&self, path: &Path) -> PathBuf {
        self.canonicalize(path)
            .unwrap_or_else(|_| path.to_path_buf())
    }

    pub fn rel(&self, workspace: &Path, path: &Path) -> Result<String> {
        let workspace = self.canonicalize(workspace)?;
        Ok(self
            .canonicalize(path)?
            .strip_prefix(&workspace)
            .map_err(|_| anyhow!("path is outside workspace: {}", path.display()))?
            .to_string_lossy()
            .replace('\\', "/"))
    }
}

pub fn ext(path: &Path) -> String {
    path.extension()
        .and_then(|v| v.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase()
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
