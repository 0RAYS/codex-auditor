use anyhow::{Context, Result, bail};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

use crate::db::{IndexMeta, SymbolRow, XrefDb};
use crate::git_index::current_git_metadata;

pub fn meta(workspace: &Path, db: &Path) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    let Some(meta) = db.index_meta()? else {
        bail!("索引缺少 index_meta，请重新运行 xref index");
    };
    let current = current_git_metadata(workspace);
    print_index_meta(&meta);
    let mut current_keys = current.keys().collect::<Vec<_>>();
    current_keys.sort();
    for key in current_keys {
        println!("{key}: {}", current[key]);
    }
    println!("index_freshness: {}", freshness(&meta, &current));
    Ok(())
}

pub fn symbols(_workspace: &Path, db: &Path, name: &str, limit: usize) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    let rows = db.fetch_symbols(name, limit, false)?;
    print_symbol_rows(&rows, true);
    Ok(())
}

pub fn definition(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    let mut rows = db.fetch_symbols(term, limit, true)?;
    if rows.is_empty() {
        rows = db.fetch_symbols(term, limit, false)?;
    }
    print_symbol_rows(&rows, true);
    Ok(())
}

pub fn refs(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    let mut candidates = db.exact_symbol_candidates(term, limit)?;
    let exact_usr = db.usr_exists(term)?;
    let target_usr = if exact_usr {
        term.to_owned()
    } else {
        let usrs = db.symbol_usrs_for_name(term, limit.saturating_add(1))?;
        if usrs.len() > 1 {
            if distinct_usrs(&candidates).len() < usrs.len() {
                candidates = db.exact_symbol_candidates(term, limit.max(usrs.len()))?;
            }
            print_ambiguous_refs(&candidates);
            return Ok(());
        }
        usrs.first().cloned().unwrap_or_default()
    };

    let rows = if target_usr.is_empty() {
        Vec::new()
    } else {
        db.ref_rows_by_usr(&target_usr, limit)?
    };
    for row in rows {
        println!("{}:{}: {}", row.path, row.line, row.context);
    }
    Ok(())
}

pub fn commits(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    print_commits(&db, term, limit)
}

pub fn context(
    workspace: &Path,
    db: &Path,
    term: &str,
    pattern: Option<&str>,
    window: usize,
    limit: usize,
) -> Result<()> {
    let db = XrefDb::open_existing(db)?;
    let (path, mut start, mut end, mut symbol_rows) =
        resolve_context_target(&db, workspace, term, limit)?;
    if let (Some(pattern), Some(_), Some(_)) = (pattern, start, end) {
        if workspace.join(&path).exists() {
            if let Some(line) = find_pattern_line(workspace, &path, pattern)? {
                start = Some(line.saturating_sub(window.saturating_sub(1)));
                end = Some(line.saturating_add(window));
            }
        }
    }
    let (Some(start), Some(end)) = (start, end) else {
        println!("未找到上下文目标: {term}");
        return Ok(());
    };
    if symbol_rows.is_empty() {
        symbol_rows = db.nearby_symbols(&path, start, end, limit)?;
    }
    println!("== 符号 ==");
    print_symbol_rows(&symbol_rows, false);
    println!("== 源码 ==");
    source_window(
        workspace,
        &path,
        start.saturating_sub(window.saturating_sub(1)),
        end.saturating_add(window),
    )?;
    println!("== 引用 ==");
    if let Some(target_usr) = symbol_rows.first().map(|row| row.usr.as_str()) {
        if !target_usr.is_empty() {
            for row in db.ref_rows_by_usr(target_usr, limit.min(10))? {
                println!("{}:{}: {}", row.path, row.line, row.context);
            }
        }
    }
    println!("== commits ==");
    print_commits(&db, &path, 5)
}

fn print_index_meta(meta: &IndexMeta) {
    println!("compile_commands: {}", meta.compile_commands);
    println!("compile_command_count: {}", meta.compile_command_count);
    println!("symbol_count: {}", meta.symbol_count);
    println!("ref_count: {}", meta.ref_count);
    println!("commit_count: {}", meta.commit_count);
    println!("git_head: {}", meta.git_head);
    println!("git_dirty: {}", meta.git_dirty);
    println!(
        "git_status_count: {}",
        meta.git_status_count
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_owned())
    );
    println!("jobs: {}", meta.jobs);
    println!(
        "tu_limit: {}",
        meta.tu_limit
            .map(|value| value.to_string())
            .unwrap_or_default()
    );
    println!("batch_size: {}", meta.batch_size);
    println!(
        "detailed_processing_record: {}",
        if meta.detailed_processing_record {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "semantic_elapsed_seconds: {:.3}",
        meta.semantic_elapsed_seconds
    );
    println!("commit_elapsed_seconds: {:.3}", meta.commit_elapsed_seconds);
    println!("total_elapsed_seconds: {:.3}", meta.total_elapsed_seconds);
}

fn freshness(meta: &IndexMeta, current: &HashMap<String, String>) -> String {
    let indexed = meta.git_head.as_str();
    let current_head = current.get("current_git_head").map_or("", String::as_str);
    if indexed.is_empty() {
        return "未知：索引缺少 git_head".to_owned();
    }
    if current_head.is_empty() {
        return "未知：当前 git head 不可用".to_owned();
    }
    if indexed != current_head {
        return format!(
            "过期：索引 {} 当前 {}",
            prefix_chars(indexed, 12),
            prefix_chars(current_head, 12)
        );
    }
    "新鲜".to_owned()
}

fn normalize_path(workspace: &Path, value: &str) -> String {
    let mut text = value.trim();
    if text.is_empty() {
        return String::new();
    }
    let path = Path::new(text);
    if path.is_absolute() {
        if let Ok(relative) = path.strip_prefix(workspace) {
            return display_path(relative);
        }
        if let Ok(canonical) = fs::canonicalize(path) {
            if let Ok(relative) = canonical.strip_prefix(workspace) {
                return display_path(relative);
            }
        }
        return display_path(path);
    }
    if let Some(stripped) = text.strip_prefix("./") {
        text = stripped;
    }
    text.to_owned()
}

fn split_location(workspace: &Path, value: &str) -> Result<(String, Option<usize>, Option<usize>)> {
    let text = value.trim();
    let Some((path, range)) = text.rsplit_once(':') else {
        return Ok((normalize_path(workspace, text), None, None));
    };
    let Some((start, end)) = parse_line_range(range) else {
        return Ok((normalize_path(workspace, text), None, None));
    };
    if end < start {
        bail!("无效行号范围: {start}-{end}");
    }
    Ok((normalize_path(workspace, path), Some(start), Some(end)))
}

fn parse_line_range(value: &str) -> Option<(usize, usize)> {
    if let Some((start, end)) = value.split_once('-') {
        let start = start.parse::<usize>().ok()?;
        let end = end.parse::<usize>().ok()?;
        return Some((start, end));
    }
    let line = value.parse::<usize>().ok()?;
    Some((line, line))
}

fn distinct_usrs(rows: &[SymbolRow]) -> HashSet<&str> {
    rows.iter()
        .filter_map(|row| (!row.usr.is_empty()).then_some(row.usr.as_str()))
        .collect()
}

fn resolve_context_target(
    db: &XrefDb,
    workspace: &Path,
    term: &str,
    limit: usize,
) -> Result<(String, Option<usize>, Option<usize>, Vec<SymbolRow>)> {
    let (path, start, end) = split_location(workspace, term)?;
    if start.is_some() {
        return Ok((path, start, end, Vec::new()));
    }
    if workspace.join(&path).exists() {
        return Ok((path, Some(1), Some(80), Vec::new()));
    }
    let rows = db.fetch_symbols(term, limit, false)?;
    let Some(row) = rows.first() else {
        return Ok((path, None, None, Vec::new()));
    };
    let line = usize::try_from(row.line).unwrap_or(1).max(1);
    Ok((
        row.path.clone(),
        Some(line.saturating_sub(7).max(1)),
        Some(line.saturating_add(8)),
        rows,
    ))
}

fn print_commits(db: &XrefDb, term: &str, limit: usize) -> Result<()> {
    for row in db.commit_rows(term, limit)? {
        let files = row.files.into_iter().take(3).collect::<Vec<_>>();
        println!(
            "{} | {} | files={}",
            prefix_chars(&row.hash, 12),
            row.subject,
            if files.is_empty() {
                "-".to_owned()
            } else {
                files.join(",")
            }
        );
    }
    Ok(())
}

fn source_window(workspace: &Path, path: &str, start: usize, end: usize) -> Result<()> {
    let abs_path = workspace.join(path);
    if !abs_path.exists() {
        println!("缺少文件: {path}");
        return Ok(());
    }
    let lines = fs::read_to_string(&abs_path)
        .with_context(|| format!("无法读取源码文件: {}", abs_path.display()))?
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let start = start.max(1);
    let end = end.min(lines.len());
    for line_no in start..=end {
        if let Some(line) = lines.get(line_no - 1) {
            println!("{path}:{line_no}: {line}");
        }
    }
    Ok(())
}

fn find_pattern_line(workspace: &Path, path: &str, pattern: &str) -> Result<Option<usize>> {
    let abs_path = workspace.join(path);
    if !abs_path.exists() {
        return Ok(None);
    }
    let regex = Regex::new(pattern).with_context(|| format!("无效 pattern 正则: {pattern}"))?;
    let text = fs::read_to_string(&abs_path)
        .with_context(|| format!("无法读取源码文件: {}", abs_path.display()))?;
    Ok(text
        .lines()
        .enumerate()
        .find_map(|(idx, line)| regex.is_match(line).then_some(idx + 1)))
}

fn print_ambiguous_refs(candidates: &[SymbolRow]) {
    println!("歧义符号：refs <name> 匹配多个 USR，请改用 refs <usr>。候选：");
    for row in candidates {
        println!(
            "{} | {} | {} | {}:{} | def={} | {}",
            row.usr, row.name, row.kind, row.path, row.line, row.is_definition, row.signature
        );
    }
}

fn print_symbol_rows(rows: &[SymbolRow], include_usr: bool) {
    for row in rows {
        if include_usr {
            println!(
                "{} | {} | {} | {} | {} | {} | {}",
                row.name, row.kind, row.path, row.line, row.is_definition, row.signature, row.usr
            );
        } else {
            println!(
                "{} | {} | {} | {} | {} | {}",
                row.name, row.kind, row.path, row.line, row.is_definition, row.signature
            );
        }
    }
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn prefix_chars(value: &str, len: usize) -> String {
    value.chars().take(len).collect()
}
