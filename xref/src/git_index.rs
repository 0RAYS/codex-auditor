use anyhow::Result;
use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

const SECURITY_TERMS: &[&str] = &[
    "security", "cve", "overflow", "oob", "uaf", "race", "crash", "fuzz", "sanitize", "bounds",
    "fix",
];

fn git_output(workspace: &Path, args: &[&str]) -> Option<String> {
    if !workspace.join(".git").exists() {
        return None;
    }
    let output = Command::new("git")
        .arg("-C")
        .arg(workspace)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn git_metadata(workspace: &Path) -> HashMap<String, String> {
    let head = git_output(workspace, &["rev-parse", "HEAD"]).unwrap_or_default();
    let status = git_output(workspace, &["status", "--porcelain"]);
    HashMap::from([
        ("workspace".to_owned(), workspace.display().to_string()),
        ("git_head".to_owned(), head),
        (
            "git_dirty".to_owned(),
            status.as_ref().map_or_else(
                || "unknown".to_owned(),
                |value| if value.is_empty() { "no" } else { "yes" }.to_owned(),
            ),
        ),
        (
            "git_status_count".to_owned(),
            status
                .map(|value| value.lines().count().to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
        ),
    ])
}

pub fn index_commits(conn: &Connection, workspace: &Path, max_commits: i32) -> Result<()> {
    if max_commits <= 0 || !workspace.join(".git").exists() {
        return Ok(());
    }
    let Some(raw) = git_output(
        workspace,
        &[
            "log",
            &format!("-n{max_commits}"),
            "--date=iso-strict",
            "--name-only",
            "--format=%H%x09%ad%x09%s",
        ],
    ) else {
        return Ok(());
    };
    let mut commits = Vec::<CommitInfo>::new();
    let mut current: Option<CommitInfo> = None;
    for line in raw.lines() {
        if line.contains('\t') {
            if let Some(item) = current.take() {
                commits.push(item);
            }
            let mut parts = line.splitn(3, '\t');
            current = Some(CommitInfo {
                hash: parts.next().unwrap_or_default().to_owned(),
                date: parts.next().unwrap_or_default().to_owned(),
                subject: parts.next().unwrap_or_default().to_owned(),
                files: Vec::new(),
            });
        } else if let Some(item) = current.as_mut() {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                item.files.push(trimmed.to_owned());
            }
        }
    }
    if let Some(item) = current {
        commits.push(item);
    }
    let mut stmt = conn.prepare(
        "INSERT OR REPLACE INTO commits(hash, subject, date, files, diff_hints, audit_signal) VALUES (?, ?, ?, ?, ?, ?)",
    )?;
    for item in commits {
        let (hints, signal) = commit_hints(&item.subject, &item.files);
        stmt.execute(params![
            item.hash,
            item.subject,
            item.date,
            serde_json::to_string(&item.files)?,
            serde_json::to_string(&hints)?,
            signal,
        ])?;
    }
    Ok(())
}

struct CommitInfo {
    hash: String,
    date: String,
    subject: String,
    files: Vec<String>,
}

fn commit_hints(subject: &str, files: &[String]) -> (Vec<String>, String) {
    let haystack = format!("{subject} {}", files.join(" ")).to_ascii_lowercase();
    let hints = SECURITY_TERMS
        .iter()
        .filter(|term| haystack.contains(**term))
        .take(5)
        .map(|term| (*term).to_owned())
        .collect::<Vec<_>>();
    let signal = hints.join(",");
    (hints, signal)
}
