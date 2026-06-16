use anyhow::{Context, Result};
use rusqlite::{Connection, params};
use serde::Deserialize;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Deserialize)]
struct RouteJson {
    pattern: Option<String>,
    skill: Option<String>,
    reason: Option<String>,
}

pub fn reset_db(conn: &mut Connection) -> Result<()> {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema.sql");
    let schema = fs::read_to_string(&schema_path)
        .with_context(|| format!("无法读取 schema: {}", schema_path.display()))?;
    conn.execute_batch(&schema)?;
    conn.execute("DROP TABLE IF EXISTS tests", [])?;
    let legacy_columns = {
        let mut stmt = conn.prepare("PRAGMA table_info(commits)")?;
        let columns = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        columns.contains("source_files") || columns.contains("test_files")
    };
    if legacy_columns {
        conn.execute("DROP TABLE IF EXISTS commits", [])?;
        conn.execute_batch(&schema)?;
    }
    for table in [
        "files",
        "symbols",
        "refs",
        "diagnostics",
        "commits",
        "routes",
        "meta",
    ] {
        conn.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}

pub fn insert_routes(conn: &Connection, route_file: Option<&Path>) -> Result<()> {
    let Some(route_file) = route_file else {
        return Ok(());
    };
    let text = fs::read_to_string(route_file)
        .with_context(|| format!("无法读取 route file: {}", route_file.display()))?;
    let data: Vec<RouteJson> =
        serde_json::from_str(&text).context("route file 必须是 JSON 数组")?;
    for item in data {
        let pattern = item.pattern.unwrap_or_default().trim().to_owned();
        let skill = item.skill.unwrap_or_default().trim().to_owned();
        let reason = item.reason.unwrap_or_default().trim().to_owned();
        if !pattern.is_empty() && !skill.is_empty() {
            conn.execute(
                "INSERT OR REPLACE INTO routes(pattern, skill, reason) VALUES (?, ?, ?)",
                params![pattern, skill, reason],
            )?;
        }
    }
    Ok(())
}

pub fn count_table(conn: &Connection, table: &str) -> Result<usize> {
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    usize::try_from(count).context("SQLite COUNT(*) 返回了无法表示为 usize 的值")
}
