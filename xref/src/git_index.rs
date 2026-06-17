use anyhow::{Context, Result};
use git2::{Commit, Delta, DiffDelta, DiffOptions, Oid, Repository, Sort, StatusOptions};
use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::db::{CommitInsertRow, XrefDb};
use crate::progress::format_progress;

pub fn git_metadata(workspace: &Path) -> HashMap<String, String> {
    let (head, dirty, status_count) = git_metadata_values(workspace);
    HashMap::from([
        ("workspace".to_owned(), workspace.display().to_string()),
        ("git_head".to_owned(), head),
        ("git_dirty".to_owned(), dirty),
        ("git_status_count".to_owned(), status_count),
    ])
}

pub fn current_git_metadata(workspace: &Path) -> HashMap<String, String> {
    let (head, dirty, status_count) = git_metadata_values(workspace);
    HashMap::from([
        ("current_git_head".to_owned(), head),
        ("current_git_dirty".to_owned(), dirty),
        ("current_git_status_count".to_owned(), status_count),
    ])
}

pub fn index_commits(db: &XrefDb, workspace: &Path, batch_size: usize) -> Result<usize> {
    let started = Instant::now();
    let Some(repo) = discover_repository(workspace) else {
        eprintln!("{}", format_progress("commits", 0, 0, Duration::ZERO));
        return Ok(0);
    };
    let oids = reachable_head_oids(&repo)?;
    let total = oids.len();
    if total == 0 {
        eprintln!("{}", format_progress("commits", 0, 0, Duration::ZERO));
        return Ok(0);
    }

    let mut batch = Vec::new();
    let mut done = 0;
    let mut printed_completion = false;
    for oid in oids {
        batch.push(commit_row(&repo, oid)?);
        done += 1;
        if batch.len() >= batch_size {
            db.insert_commits(std::mem::take(&mut batch))?;
            eprintln!(
                "{}",
                format_progress("commits", done, total, started.elapsed())
            );
            printed_completion = done == total;
        }
    }
    if !batch.is_empty() {
        db.insert_commits(batch)?;
        eprintln!(
            "{}",
            format_progress("commits", done, total, started.elapsed())
        );
        printed_completion = done == total;
    }
    if !printed_completion {
        eprintln!(
            "{}",
            format_progress("commits", done, total, started.elapsed())
        );
    }
    Ok(done)
}

#[cfg(test)]
pub fn collect_commits(workspace: &Path) -> Result<Vec<CommitInsertRow>> {
    let Some(repo) = discover_repository(workspace) else {
        return Ok(Vec::new());
    };
    reachable_head_oids(&repo)?
        .into_iter()
        .map(|oid| commit_row(&repo, oid))
        .collect()
}

fn discover_repository(workspace: &Path) -> Option<Repository> {
    Repository::discover(workspace).ok()
}

fn git_metadata_values(workspace: &Path) -> (String, String, String) {
    let Some(repo) = discover_repository(workspace) else {
        return (String::new(), "unknown".to_owned(), "unknown".to_owned());
    };
    let head = repo
        .head()
        .ok()
        .and_then(|head| head.target())
        .map(|oid| oid.to_string())
        .unwrap_or_default();
    let status_count = status_count(&repo);
    let dirty = status_count.map_or_else(
        || "unknown".to_owned(),
        |count| {
            if count == 0 {
                "no".to_owned()
            } else {
                "yes".to_owned()
            }
        },
    );
    (
        head,
        dirty,
        status_count
            .map(|count| count.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
    )
}

fn status_count(repo: &Repository) -> Option<usize> {
    let mut options = StatusOptions::new();
    options.include_untracked(true).recurse_untracked_dirs(true);
    repo.statuses(Some(&mut options))
        .ok()
        .map(|statuses| statuses.len())
}

fn reachable_head_oids(repo: &Repository) -> Result<Vec<Oid>> {
    let mut revwalk = repo.revwalk().context("无法创建 git revwalk")?;
    if revwalk.push_head().is_err() {
        return Ok(Vec::new());
    }
    revwalk
        .set_sorting(Sort::TOPOLOGICAL)
        .context("无法设置 git revwalk 排序")?;
    let mut oids = Vec::new();
    for oid in revwalk {
        oids.push(oid.context("无法读取 git commit OID")?);
    }
    Ok(oids)
}

fn commit_row(repo: &Repository, oid: Oid) -> Result<CommitInsertRow> {
    let commit = repo
        .find_commit(oid)
        .with_context(|| format!("无法读取 git commit {oid}"))?;
    let subject = commit.summary().unwrap_or_default().to_owned();
    let files = commit_files(repo, &commit)?;
    Ok(CommitInsertRow {
        hash: oid.to_string(),
        subject,
        files,
    })
}

fn commit_files(repo: &Repository, commit: &Commit<'_>) -> Result<Vec<String>> {
    let new_tree = commit
        .tree()
        .with_context(|| format!("无法读取 commit tree: {}", commit.id()))?;
    let old_tree = if commit.parent_count() == 0 {
        None
    } else {
        Some(
            commit
                .parent(0)
                .with_context(|| format!("无法读取 first parent: {}", commit.id()))?
                .tree()
                .with_context(|| format!("无法读取 first parent tree: {}", commit.id()))?,
        )
    };
    let mut options = DiffOptions::new();
    let diff = repo
        .diff_tree_to_tree(old_tree.as_ref(), Some(&new_tree), Some(&mut options))
        .with_context(|| format!("无法计算 commit diff: {}", commit.id()))?;
    let mut files = Vec::new();
    diff.foreach(
        &mut |delta, _| {
            if let Some(path) = delta_path(delta) {
                files.push(path);
            }
            true
        },
        None,
        None,
        None,
    )?;
    files.sort();
    files.dedup();
    Ok(files)
}

fn delta_path(delta: DiffDelta<'_>) -> Option<String> {
    let path = if delta.status() == Delta::Deleted {
        delta.old_file().path().or_else(|| delta.new_file().path())
    } else {
        delta.new_file().path().or_else(|| delta.old_file().path())
    }?;
    Some(display_git_path(path))
}

fn display_git_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::Signature;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempRepo {
        path: std::path::PathBuf,
    }

    impl TempRepo {
        fn new(name: &str) -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "xref_git_{name}_{}_{}",
                std::process::id(),
                unique
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempRepo {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn tree_with_files(repo: &Repository, entries: &[(&str, &str)]) -> Oid {
        let mut builder = repo.treebuilder(None).unwrap();
        for (path, content) in entries {
            let blob = repo.blob(content.as_bytes()).unwrap();
            builder.insert(*path, blob, 0o100644).unwrap();
        }
        builder.write().unwrap()
    }

    fn commit_tree(
        repo: &Repository,
        update_ref: &str,
        message: &str,
        tree_oid: Oid,
        parents: &[Oid],
    ) -> Oid {
        let author = Signature::now("xref test", "xref@example.invalid").unwrap();
        let tree = repo.find_tree(tree_oid).unwrap();
        let parent_commits = parents
            .iter()
            .map(|oid| repo.find_commit(*oid).unwrap())
            .collect::<Vec<_>>();
        let parent_refs = parent_commits.iter().collect::<Vec<_>>();
        repo.commit(
            Some(update_ref),
            &author,
            &author,
            message,
            &tree,
            &parent_refs,
        )
        .unwrap()
    }

    #[test]
    fn collect_commits_uses_git2_diffs_and_first_parent_for_merges() {
        let temp = TempRepo::new("history");
        let repo = Repository::init(&temp.path).unwrap();
        let root_tree = tree_with_files(&repo, &[("root.txt", "root\n")]);
        let root = commit_tree(&repo, "HEAD", "root security", root_tree, &[]);
        let normal_tree =
            tree_with_files(&repo, &[("root.txt", "root\n"), ("normal.txt", "normal\n")]);
        let normal = commit_tree(&repo, "HEAD", "normal fix", normal_tree, &[root]);
        let branch_tree =
            tree_with_files(&repo, &[("root.txt", "root\n"), ("branch.txt", "branch\n")]);
        let branch = commit_tree(
            &repo,
            "refs/heads/feature",
            "branch overflow",
            branch_tree,
            &[root],
        );
        let merge_tree = tree_with_files(
            &repo,
            &[
                ("root.txt", "root\n"),
                ("normal.txt", "normal\n"),
                ("branch.txt", "branch\n"),
            ],
        );
        let merge = commit_tree(
            &repo,
            "HEAD",
            "merge feature",
            merge_tree,
            &[normal, branch],
        );

        let rows = collect_commits(&temp.path).unwrap();
        let by_hash = rows
            .iter()
            .map(|row| (row.hash.as_str(), row))
            .collect::<HashMap<_, _>>();

        assert_eq!(rows.len(), 4);
        assert_eq!(by_hash[&root.to_string().as_str()].files, vec!["root.txt"]);
        assert_eq!(
            by_hash[&normal.to_string().as_str()].files,
            vec!["normal.txt"]
        );
        assert_eq!(
            by_hash[&branch.to_string().as_str()].files,
            vec!["branch.txt"]
        );
        assert_eq!(
            by_hash[&merge.to_string().as_str()].files,
            vec!["branch.txt"]
        );
        assert_eq!(by_hash[&normal.to_string().as_str()].subject, "normal fix");
    }
}
