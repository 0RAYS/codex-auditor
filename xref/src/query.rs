use anyhow::{Context, Result, anyhow, bail};
use regex::Regex;
use rusqlite::{Connection, OptionalExtension, params};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;
use std::process::Command;

#[derive(Clone, Debug)]
struct SymbolRow {
    usr: String,
    name: String,
    kind: String,
    path: String,
    line: i64,
    is_definition: i64,
    signature: String,
}

#[derive(Debug)]
struct RefRow {
    name: String,
    kind: String,
    path: String,
    line: i64,
    context: String,
}

pub fn meta(workspace: &Path, db: &Path) -> Result<()> {
    let conn = connect(db)?;
    let meta = meta_dict(&conn)?;
    let current = current_git_metadata(workspace);
    for key in [
        "backend",
        "compile_commands",
        "compile_command_count",
        "symbol_count",
        "ref_count",
        "git_head",
        "git_dirty",
        "git_status_count",
    ] {
        if let Some(value) = meta.get(key) {
            println!("{key}: {value}");
        }
    }
    let mut current_keys = current.keys().collect::<Vec<_>>();
    current_keys.sort();
    for key in current_keys {
        println!("{key}: {}", current[key]);
    }
    println!("index_freshness: {}", freshness(&meta, &current));
    Ok(())
}

pub fn symbols(_workspace: &Path, db: &Path, name: &str, limit: usize) -> Result<()> {
    let conn = connect(db)?;
    let rows = fetch_symbols(&conn, name, limit, false)?;
    print_symbol_rows(&rows, true);
    Ok(())
}

pub fn definition(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let conn = connect(db)?;
    let mut rows = fetch_symbols(&conn, term, limit, true)?;
    if rows.is_empty() {
        rows = fetch_symbols(&conn, term, limit, false)?;
    }
    print_symbol_rows(&rows, true);
    Ok(())
}

pub fn refs(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let conn = connect(db)?;
    let mut candidates = exact_symbol_candidates(&conn, term, limit)?;
    let exact_usr = conn
        .query_row(
            "SELECT 1 FROM symbols WHERE usr = ? LIMIT 1",
            [term],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    let target_usr = if exact_usr {
        term.to_owned()
    } else {
        let usrs = symbol_usrs_for_name(&conn, term, limit.saturating_add(1))?;
        if usrs.len() > 1 {
            if distinct_usrs(&candidates).len() < usrs.len() {
                candidates = exact_symbol_candidates(&conn, term, limit.max(usrs.len()))?;
            }
            print_ambiguous_refs(&candidates);
            return Ok(());
        }
        usrs.first().cloned().unwrap_or_default()
    };

    let rows = if target_usr.is_empty() {
        ref_rows_by_name(&conn, term, limit)?
    } else {
        ref_rows_by_usr(&conn, &target_usr, limit)?
    };
    for row in rows {
        println!(
            "{}:{}: {} [{}] {}",
            row.path, row.line, row.name, row.kind, row.context
        );
    }
    Ok(())
}

pub fn commits(_workspace: &Path, db: &Path, term: &str, limit: usize) -> Result<()> {
    let conn = connect(db)?;
    print_commits(&conn, term, limit)
}

pub fn context(
    workspace: &Path,
    db: &Path,
    term: &str,
    pattern: Option<&str>,
    window: usize,
    limit: usize,
) -> Result<()> {
    let conn = connect(db)?;
    let (path, mut start, mut end, mut symbol_rows) =
        resolve_context_target(&conn, workspace, term, limit)?;
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
        symbol_rows = nearby_symbols(&conn, &path, start, end, limit)?;
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
            for row in ref_rows_by_usr(&conn, target_usr, limit.min(10))? {
                println!(
                    "{}:{}: {} [{}] {}",
                    row.path, row.line, row.name, row.kind, row.context
                );
            }
        }
    }
    println!("== commits ==");
    print_commits(&conn, &path, 5)
}

fn connect(db: &Path) -> Result<Connection> {
    if !db.exists() {
        bail!(
            "找不到索引: {}\n请先运行 xref --workspace <目标工作区> index",
            db.display()
        );
    }
    let conn = Connection::open(db).with_context(|| format!("无法打开数据库: {}", db.display()))?;
    Ok(conn)
}

fn meta_dict(conn: &Connection) -> Result<HashMap<String, String>> {
    let mut stmt = conn.prepare("SELECT key, value FROM meta")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut values = HashMap::new();
    for row in rows {
        let (key, value) = row?;
        values.insert(key, value);
    }
    Ok(values)
}

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

fn current_git_metadata(workspace: &Path) -> HashMap<String, String> {
    let head = git_output(workspace, &["rev-parse", "HEAD"]).unwrap_or_default();
    let status = git_output(workspace, &["status", "--porcelain"]);
    HashMap::from([
        ("current_git_head".to_owned(), head),
        (
            "current_git_dirty".to_owned(),
            status.as_ref().map_or_else(
                || "unknown".to_owned(),
                |value| if value.is_empty() { "no" } else { "yes" }.to_owned(),
            ),
        ),
        (
            "current_git_status_count".to_owned(),
            status
                .map(|value| value.lines().count().to_string())
                .unwrap_or_else(|| "unknown".to_owned()),
        ),
    ])
}

fn freshness(meta: &HashMap<String, String>, current: &HashMap<String, String>) -> String {
    let indexed = meta.get("git_head").map_or("", String::as_str);
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

fn fetch_symbols(
    conn: &Connection,
    term: &str,
    limit: usize,
    definitions_only: bool,
) -> Result<Vec<SymbolRow>> {
    let like = format!("%{term}%");
    let definition_clause = if definitions_only {
        "AND is_definition = 1"
    } else {
        ""
    };
    let sql = format!(
        r#"
        SELECT
          COALESCE(usr, '') AS usr, name, kind, path, line,
          is_definition, COALESCE(type, '') AS type,
          COALESCE(signature, '') AS signature
        FROM symbols
        WHERE (usr = ? OR name = ? OR name LIKE ?) {definition_clause}
        ORDER BY
          CASE WHEN usr = ? THEN 0 WHEN name = ? THEN 1 ELSE 2 END,
          is_definition DESC, path, line
        LIMIT ?
        "#
    );
    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(
        params![term, term, like, term, term, limit_i64(limit)?],
        symbol_from_row,
    )?;
    collect_rows(rows)
}

fn exact_symbol_candidates(conn: &Connection, term: &str, limit: usize) -> Result<Vec<SymbolRow>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT
          COALESCE(usr, '') AS usr, name, kind, path, line, is_definition,
          COALESCE(type, '') AS type,
          COALESCE(signature, '') AS signature
        FROM symbols
        WHERE usr = ? OR name = ?
        ORDER BY CASE WHEN usr = ? THEN 0 ELSE 1 END, is_definition DESC, path, line
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(
        params![term, term, term, limit_i64(limit)?],
        symbol_from_row,
    )?;
    collect_rows(rows)
}

fn symbol_usrs_for_name(conn: &Connection, name: &str, limit: usize) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT DISTINCT usr
        FROM symbols
        WHERE name = ? AND usr IS NOT NULL AND usr != ''
        ORDER BY usr
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(params![name, limit_i64(limit)?], |row| {
        row.get::<_, String>(0)
    })?;
    collect_rows(rows)
}

fn distinct_usrs(rows: &[SymbolRow]) -> HashSet<&str> {
    rows.iter()
        .filter_map(|row| (!row.usr.is_empty()).then_some(row.usr.as_str()))
        .collect()
}

fn ref_rows_by_usr(conn: &Connection, usr: &str, limit: usize) -> Result<Vec<RefRow>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT name, kind, path, line, context
        FROM refs
        WHERE referenced_usr = ?
        ORDER BY path, line
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(params![usr, limit_i64(limit)?], ref_from_row)?;
    collect_rows(rows)
}

fn ref_rows_by_name(conn: &Connection, name: &str, limit: usize) -> Result<Vec<RefRow>> {
    let mut stmt = conn.prepare(
        r#"
        SELECT name, kind, path, line, context
        FROM refs
        WHERE name = ?
        ORDER BY path, line
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(params![name, limit_i64(limit)?], ref_from_row)?;
    collect_rows(rows)
}

fn nearby_symbols(
    conn: &Connection,
    path: &str,
    start: usize,
    end: usize,
    limit: usize,
) -> Result<Vec<SymbolRow>> {
    let margin_start = start.saturating_sub(19).max(1);
    let margin_end = end.saturating_add(20);
    let mut stmt = conn.prepare(
        r#"
        SELECT
          COALESCE(usr, '') AS usr, name, kind, path, line,
          is_definition, COALESCE(type, '') AS type,
          COALESCE(signature, '') AS signature
        FROM symbols
        WHERE path = ? AND line BETWEEN ? AND ?
        ORDER BY
          ABS(line - ?), is_definition DESC, line
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(
        params![
            path,
            i64::try_from(margin_start)?,
            i64::try_from(margin_end)?,
            i64::try_from(start)?,
            limit_i64(limit)?
        ],
        symbol_from_row,
    )?;
    collect_rows(rows)
}

fn resolve_context_target(
    conn: &Connection,
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
    let rows = fetch_symbols(conn, term, limit, false)?;
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

fn print_commits(conn: &Connection, term: &str, limit: usize) -> Result<()> {
    let like = format!("%{term}%");
    let mut stmt = conn.prepare(
        r#"
        SELECT hash, date, subject, files, diff_hints, audit_signal
        FROM commits
        WHERE subject LIKE ? OR files LIKE ? OR diff_hints LIKE ? OR audit_signal LIKE ?
        ORDER BY date DESC
        LIMIT ?
        "#,
    )?;
    let rows = stmt.query_map(params![like, like, like, like, limit_i64(limit)?], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?.unwrap_or_default(),
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, String>(4)?,
            row.get::<_, String>(5)?,
        ))
    })?;
    for row in rows {
        let (hash, date, subject, files, diff_hints, audit_signal) = row?;
        let files = json_list(&files).into_iter().take(3).collect::<Vec<_>>();
        let hints = json_list(&diff_hints).join(",");
        let hints = if hints.is_empty() {
            if audit_signal.is_empty() {
                "-".to_owned()
            } else {
                audit_signal
            }
        } else {
            hints
        };
        println!(
            "{} | {} | {} | files={} | hints={}",
            prefix_chars(&hash, 12),
            date,
            subject,
            if files.is_empty() {
                "-".to_owned()
            } else {
                files.join(",")
            },
            hints
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

fn symbol_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SymbolRow> {
    Ok(SymbolRow {
        usr: row.get("usr")?,
        name: row.get("name")?,
        kind: row.get("kind")?,
        path: row.get("path")?,
        line: row.get("line")?,
        is_definition: row.get("is_definition")?,
        signature: row.get("signature")?,
    })
}

fn ref_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RefRow> {
    Ok(RefRow {
        name: row.get("name")?,
        kind: row.get("kind")?,
        path: row.get("path")?,
        line: row.get("line")?,
        context: row.get("context")?,
    })
}

fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
) -> Result<Vec<T>> {
    let mut values = Vec::new();
    for row in rows {
        values.push(row?);
    }
    Ok(values)
}

fn json_list(value: &str) -> Vec<String> {
    serde_json::from_str::<Vec<String>>(value).unwrap_or_default()
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn prefix_chars(value: &str, len: usize) -> String {
    value.chars().take(len).collect()
}

fn limit_i64(limit: usize) -> Result<i64> {
    i64::try_from(limit).map_err(|_| anyhow!("limit 过大: {limit}"))
}
