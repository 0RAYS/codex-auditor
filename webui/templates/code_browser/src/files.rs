use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use sha1::{Digest, Sha1};
use std::collections::HashSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::path_util::{in_workspace, rel, should_skip, source_lang};

pub fn index_files(
    conn: &Connection,
    workspace: &Path,
    paths: &[PathBuf],
    exclude_parts: &HashSet<String>,
    limit: Option<usize>,
    compile_db_sources: &HashSet<String>,
    batch_size: usize,
) -> Result<()> {
    let mut rows = Vec::new();
    let mut count = 0usize;
    for base in paths {
        if !base.exists() {
            continue;
        }
        if base.is_file() {
            if push_file_row(
                conn,
                workspace,
                base,
                compile_db_sources,
                &mut rows,
                batch_size,
            )? {
                count += 1;
            }
        } else {
            for entry in WalkDir::new(base)
                .into_iter()
                .filter_entry(|entry| !should_skip(entry.path(), exclude_parts))
            {
                let entry = match entry {
                    Ok(entry) => entry,
                    Err(_) => continue,
                };
                if !entry.file_type().is_file() {
                    continue;
                }
                if limit.is_some_and(|max| count >= max) {
                    break;
                }
                if push_file_row(
                    conn,
                    workspace,
                    entry.path(),
                    compile_db_sources,
                    &mut rows,
                    batch_size,
                )? {
                    count += 1;
                }
            }
        }
        if limit.is_some_and(|max| count >= max) {
            break;
        }
    }
    flush_file_rows(conn, &mut rows, true, batch_size)
}

fn push_file_row(
    conn: &Connection,
    workspace: &Path,
    path: &Path,
    compile_db_sources: &HashSet<String>,
    rows: &mut Vec<(String, String, String, i64, f64, i32)>,
    batch_size: usize,
) -> Result<bool> {
    let Some(lang) = source_lang(path) else {
        return Ok(false);
    };
    if !in_workspace(workspace, path) {
        return Ok(false);
    }
    let data = fs::read(path).with_context(|| format!("无法读取源码文件: {}", path.display()))?;
    let rpath = rel(workspace, path)?;
    let stat = fs::metadata(path)?;
    let mtime = stat
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0.0, |duration| duration.as_secs_f64());
    let mut sha1 = String::with_capacity(40);
    for byte in Sha1::digest(&data) {
        write!(&mut sha1, "{byte:02x}")?;
    }
    let size = i64::try_from(stat.len()).context("源码文件大小超过 SQLite INTEGER 可表示范围")?;
    rows.push((
        rpath.clone(),
        lang.to_owned(),
        sha1,
        size,
        mtime,
        i32::from(compile_db_sources.contains(&rpath)),
    ));
    flush_file_rows(conn, rows, false, batch_size)?;
    Ok(true)
}

fn flush_file_rows(
    conn: &Connection,
    rows: &mut Vec<(String, String, String, i64, f64, i32)>,
    force: bool,
    batch_size: usize,
) -> Result<()> {
    while !rows.is_empty() && (force || rows.len() >= batch_size) {
        let chunk_size = if force { rows.len() } else { batch_size };
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR REPLACE INTO files(path, lang, sha1, size, mtime, in_compile_db) VALUES (?, ?, ?, ?, ?, ?)",
            )?;
            for row in rows.drain(..chunk_size) {
                stmt.execute(params![row.0, row.1, row.2, row.3, row.4, row.5])?;
            }
        }
        tx.commit()?;
    }
    Ok(())
}
