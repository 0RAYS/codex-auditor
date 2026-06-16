use anyhow::{Context, Result};
use rusqlite::Connection;
use std::fs;
use std::path::Path;

pub fn reset_db(conn: &mut Connection) -> Result<()> {
    let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("schema.sql");
    let schema = fs::read_to_string(&schema_path)
        .with_context(|| format!("无法读取 schema: {}", schema_path.display()))?;
    for table in [
        "tests",
        "routes",
        "diagnostics",
        "symbols",
        "refs",
        "commits",
        "files",
        "meta",
    ] {
        conn.execute(&format!("DROP TABLE IF EXISTS {table}"), [])?;
    }
    conn.execute_batch(&schema)?;
    Ok(())
}

pub fn count_table(conn: &Connection, table: &str) -> Result<usize> {
    let count: i64 = conn.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
        row.get(0)
    })?;
    usize::try_from(count).context("SQLite COUNT(*) 返回了无法表示为 usize 的值")
}
