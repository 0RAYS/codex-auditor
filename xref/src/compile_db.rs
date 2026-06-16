use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

use crate::path_util::{
    DEFAULT_EXCLUDE_PARTS, PathCache, absolutize_path, is_c_family, should_skip,
};

#[derive(Clone, Debug)]
pub struct CompileCommand {
    pub source: PathBuf,
    pub args: Vec<String>,
}

#[derive(Deserialize)]
struct CompileCommandJson {
    directory: Option<String>,
    file: Option<String>,
    arguments: Option<Vec<serde_json::Value>>,
    command: Option<String>,
}

pub fn find_compile_commands(
    workspace: &Path,
    explicit: Option<&Path>,
    path_cache: &PathCache,
) -> Option<PathBuf> {
    if let Some(path) = explicit {
        return Some(path_cache.canonicalize_or_original(&absolutize_path(workspace, path)));
    }
    let direct = workspace.join("compile_commands.json");
    if direct.exists() {
        return Some(path_cache.canonicalize_or_original(&direct));
    }
    for name in ["build", "cmake-build-debug", "cmake-build-release", "out"] {
        let candidate = workspace.join(name).join("compile_commands.json");
        if candidate.exists() {
            return Some(path_cache.canonicalize_or_original(&candidate));
        }
    }
    for entry in WalkDir::new(workspace).into_iter().filter_map(Result::ok) {
        if entry.file_type().is_file()
            && entry.file_name() == "compile_commands.json"
            && !should_skip(entry.path(), &default_excludes_without_build_out())
        {
            return Some(path_cache.canonicalize_or_original(entry.path()));
        }
    }
    None
}

fn default_excludes_without_build_out() -> HashSet<String> {
    DEFAULT_EXCLUDE_PARTS
        .iter()
        .filter(|value| **value != "build" && **value != "out")
        .map(|value| (*value).to_owned())
        .collect()
}

fn clang_resource_dir() -> String {
    for binary in [
        "clang", "clang-22", "clang-21", "clang-20", "clang-19", "clang-18", "clang-17",
    ] {
        if let Ok(output) = Command::new(binary).arg("-print-resource-dir").output() {
            if output.status.success() {
                let value = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                if !value.is_empty() {
                    return value;
                }
            }
        }
    }
    String::new()
}

pub fn load_compile_commands(
    path: Option<&Path>,
    workspace: &Path,
    path_cache: &PathCache,
    suppress_libclang_warnings: bool,
) -> Result<(Vec<CompileCommand>, String)> {
    let Some(path) = path else {
        return Ok((Vec::new(), String::new()));
    };
    if !path.exists() {
        return Ok((Vec::new(), String::new()));
    }
    let text = fs::read_to_string(path).with_context(|| format!("无法读取 {}", path.display()))?;
    let data: Vec<CompileCommandJson> = serde_json::from_str(&text)
        .with_context(|| format!("compile_commands.json 不是 JSON 数组: {}", path.display()))?;
    let resource_dir = clang_resource_dir();
    let mut seen = HashSet::new();
    let mut commands = Vec::new();
    for item in data {
        let directory = item.directory.as_deref().map(PathBuf::from).map_or_else(
            || workspace.to_path_buf(),
            |p| absolutize_path(workspace, &p),
        );
        let directory = path_cache.canonicalize_or_original(&directory);
        let Some(file_value) = item.file else {
            continue;
        };
        let source = absolutize_path(&directory, Path::new(&file_value));
        let source = match path_cache.canonicalize(&source) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !is_c_family(&source) || !source.exists() || !seen.insert(source.clone()) {
            continue;
        }
        let raw_args = if let Some(arguments) = item.arguments {
            arguments.into_iter().map(json_value_to_string).collect()
        } else if let Some(command) = item.command {
            shell_words::split(&command)
                .unwrap_or_else(|_| vec!["clang".to_owned(), source.display().to_string()])
        } else {
            vec!["clang".to_owned(), source.display().to_string()]
        };
        let args = clean_compile_args(
            &raw_args,
            &directory,
            &source,
            path_cache,
            &resource_dir,
            suppress_libclang_warnings,
        );
        commands.push(CompileCommand { source, args });
    }
    Ok((commands, path.display().to_string()))
}

fn json_value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

fn compiler_payload(raw_args: &[String]) -> &[String] {
    let wrappers = ["ccache", "sccache", "distcc", "icecc"];
    let compilers = [
        "cc", "c++", "gcc", "g++", "clang", "clang++", "cl", "emcc", "em++",
    ];
    let mut i = 0;
    while i < raw_args.len() {
        let arg = &raw_args[i];
        let base = Path::new(arg)
            .file_name()
            .and_then(|v| v.to_str())
            .unwrap_or(arg);
        if arg == "env" || looks_like_env_assignment(arg) || wrappers.contains(&base) {
            i += 1;
            continue;
        }
        if compilers.contains(&base) || looks_like_target_compiler(base) {
            return &raw_args[i + 1..];
        }
        break;
    }
    if raw_args.is_empty() {
        raw_args
    } else {
        &raw_args[1..]
    }
}

fn looks_like_env_assignment(arg: &str) -> bool {
    let Some((first, rest)) = arg.split_once('=') else {
        return false;
    };
    let mut chars = first.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !rest.is_empty()
}

fn looks_like_target_compiler(base: &str) -> bool {
    ["gcc", "g++", "clang", "clang++", "cc", "c++"]
        .iter()
        .any(|suffix| base == *suffix || base.ends_with(&format!("-{suffix}")))
}

fn source_arg_matches(arg: &str, directory: &Path, source: &Path, path_cache: &PathCache) -> bool {
    let candidate = absolutize_path(directory, Path::new(arg));
    path_cache
        .canonicalize(&candidate)
        .is_ok_and(|p| p == source)
}

fn absolutize_arg_path(value: &str, directory: &Path, path_cache: &PathCache) -> String {
    if value.is_empty() || value.starts_with('$') {
        value.to_owned()
    } else {
        let path = absolutize_path(directory, Path::new(value));
        path_cache
            .canonicalize(&path)
            .unwrap_or(path)
            .display()
            .to_string()
    }
}

fn clean_compile_args(
    raw_args: &[String],
    directory: &Path,
    source: &Path,
    path_cache: &PathCache,
    resource_dir: &str,
    suppress_libclang_warnings: bool,
) -> Vec<String> {
    let args = compiler_payload(raw_args);
    let path_taking_opts = [
        "-I",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-include",
        "-imacros",
        "-isysroot",
        "--sysroot",
    ];
    let mut cleaned = Vec::new();
    let mut skip_next = false;
    let mut pending_path_opt = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if pending_path_opt {
            cleaned.push(absolutize_arg_path(arg, directory, path_cache));
            pending_path_opt = false;
            continue;
        }
        if arg == "-c"
            || arg == "-S"
            || arg
                == source
                    .file_name()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
            || source_arg_matches(arg, directory, source, path_cache)
        {
            continue;
        }
        if arg == "-o" {
            skip_next = true;
            continue;
        }
        if arg.starts_with("-o") && arg.len() > 2 {
            continue;
        }
        if path_taking_opts.contains(&arg.as_str()) {
            cleaned.push(arg.clone());
            pending_path_opt = true;
            continue;
        }
        let mut handled_joined = false;
        for opt in [
            "-I",
            "-isystem",
            "-iquote",
            "-idirafter",
            "-include",
            "-imacros",
        ] {
            if arg.starts_with(opt) && arg.len() > opt.len() {
                cleaned.push(format!(
                    "{opt}{}",
                    absolutize_arg_path(&arg[opt.len()..], directory, path_cache)
                ));
                handled_joined = true;
                break;
            }
        }
        if handled_joined {
            continue;
        }
        if let Some(value) = arg.strip_prefix("--sysroot=") {
            cleaned.push(format!(
                "--sysroot={}",
                absolutize_arg_path(value, directory, path_cache)
            ));
            continue;
        }
        cleaned.push(arg.clone());
    }
    if !resource_dir.is_empty()
        && !cleaned
            .iter()
            .any(|arg| arg == "-resource-dir" || arg.starts_with("-resource-dir="))
    {
        cleaned.push("-resource-dir".to_owned());
        cleaned.push(resource_dir.to_owned());
    }
    if suppress_libclang_warnings && !cleaned.iter().any(|arg| arg == "-w") {
        cleaned.push("-w".to_owned());
    }
    cleaned
}
