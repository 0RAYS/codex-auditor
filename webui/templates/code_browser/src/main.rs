mod compile_db;
mod db;
mod git_index;
mod path_util;
mod semantic;

use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use rusqlite::{Connection, params};
use std::fs;
use std::path::PathBuf;
use std::thread;
use std::time::Instant;

use compile_db::{find_compile_commands, load_compile_commands};
use db::reset_db;
use git_index::{git_metadata, index_commits};
use semantic::index_translation_units;

const DEFAULT_DB: &str = "code_browser/code_browser.sqlite";

#[derive(Parser, Debug)]
#[command(about = "构建面向 C/C++ 审计的 libclang 语义索引。")]
struct Args {
    #[arg(long, default_value = ".")]
    workspace: PathBuf,
    #[arg(long, default_value = DEFAULT_DB)]
    db: PathBuf,
    #[arg(long)]
    compile_commands: Option<PathBuf>,
    #[arg(long, default_value_t = 500)]
    max_commits: i32,
    #[arg(long, value_parser = positive_usize)]
    tu_limit: Option<usize>,
    #[arg(long, default_value_t = default_jobs(), value_parser = positive_usize)]
    jobs: usize,
    #[arg(long, default_value_t = 5000, value_parser = positive_usize)]
    batch_size: usize,
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    detailed_processing_record: bool,
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    libclang_warnings: bool,
}

fn default_jobs() -> usize {
    thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(8)
}

fn positive_usize(value: &str) -> std::result::Result<usize, String> {
    let parsed = value
        .parse::<usize>()
        .map_err(|exc| format!("invalid integer: {exc}"))?;
    if parsed == 0 {
        Err("must be >= 1".to_owned())
    } else {
        Ok(parsed)
    }
}

fn main() -> Result<()> {
    let total_started = Instant::now();
    let args = Args::parse();
    let workspace = fs::canonicalize(&args.workspace)
        .with_context(|| format!("无法解析 workspace: {}", args.workspace.display()))?;
    let db = if args.db.is_absolute() {
        args.db.clone()
    } else {
        workspace.join(&args.db)
    };
    if let Some(parent) = db.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建数据库目录: {}", parent.display()))?;
    }

    let compile_commands_path = find_compile_commands(&workspace, args.compile_commands.as_deref());
    let (mut compile_commands, compile_commands_meta) = load_compile_commands(
        compile_commands_path.as_deref(),
        &workspace,
        !args.libclang_warnings,
    )?;
    if let Some(limit) = args.tu_limit {
        compile_commands.truncate(limit);
    }

    let mut conn =
        Connection::open(&db).with_context(|| format!("无法打开数据库: {}", db.display()))?;
    reset_db(&mut conn)?;

    let semantic_started = Instant::now();
    let (symbol_count, ref_count) = index_translation_units(
        &conn,
        &workspace,
        &compile_commands,
        args.jobs,
        args.batch_size,
        args.detailed_processing_record,
    )?;
    let semantic_elapsed = semantic_started.elapsed().as_secs_f64();
    let commit_started = Instant::now();
    index_commits(&conn, &workspace, args.max_commits)?;
    let commit_elapsed = commit_started.elapsed().as_secs_f64();
    let total_elapsed = total_started.elapsed().as_secs_f64();

    let mut meta = git_metadata(&workspace);
    meta.insert("backend".to_owned(), "libclang".to_owned());
    meta.insert("compile_commands".to_owned(), compile_commands_meta);
    meta.insert(
        "compile_command_count".to_owned(),
        compile_commands.len().to_string(),
    );
    meta.insert("symbol_count".to_owned(), symbol_count.to_string());
    meta.insert("ref_count".to_owned(), ref_count.to_string());
    meta.insert("jobs".to_owned(), args.jobs.to_string());
    meta.insert(
        "tu_limit".to_owned(),
        args.tu_limit.map_or_else(String::new, |v| v.to_string()),
    );
    meta.insert("batch_size".to_owned(), args.batch_size.to_string());
    meta.insert(
        "detailed_processing_record".to_owned(),
        if args.detailed_processing_record {
            "yes"
        } else {
            "no"
        }
        .to_owned(),
    );
    meta.insert(
        "libclang_warnings".to_owned(),
        if args.libclang_warnings { "yes" } else { "no" }.to_owned(),
    );
    meta.insert(
        "semantic_elapsed_seconds".to_owned(),
        format!("{semantic_elapsed:.3}"),
    );
    meta.insert(
        "commit_elapsed_seconds".to_owned(),
        format!("{commit_elapsed:.3}"),
    );
    meta.insert(
        "total_elapsed_seconds".to_owned(),
        format!("{total_elapsed:.3}"),
    );
    for (key, value) in meta {
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)",
            params![key, value],
        )?;
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")?;
    println!(
        "已索引 backend=libclang symbols={symbol_count} refs={ref_count} db={}",
        db.display()
    );
    Ok(())
}
