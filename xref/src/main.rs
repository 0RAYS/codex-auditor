mod compile_db;
mod db;
mod git_index;
mod path_util;
mod query;
mod semantic;

use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use rusqlite::{Connection, params};
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Instant;

use compile_db::{find_compile_commands, load_compile_commands};
use db::reset_db;
use git_index::{git_metadata, index_commits};
use path_util::PathCache;
use semantic::index_translation_units;

const DEFAULT_DB: &str = "xref.db";

#[derive(Parser, Debug)]
#[command(about = "面向 C/C++ 审计的源码索引和查询工具。")]
struct Cli {
    #[arg(short = 'w', long, default_value = ".", global = true)]
    workspace: PathBuf,
    #[arg(short = 'd', long, default_value = DEFAULT_DB, global = true)]
    db: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "构建 libclang 语义索引。")]
    Index(IndexArgs),
    #[command(about = "显示索引元数据和新鲜度。")]
    Meta,
    #[command(about = "按名称或 USR 查询符号。")]
    Symbols(SymbolArgs),
    #[command(about = "按名称或 USR 查询符号。")]
    Symbol(SymbolArgs),
    #[command(name = "def", about = "优先查询定义位置。")]
    Definition(TermArgs),
    #[command(about = "查询符号引用。")]
    Refs(TermArgs),
    #[command(about = "查询近期 commit 辅助信息。")]
    Commits(CommitArgs),
    #[command(about = "显示文件位置或符号附近上下文。")]
    Context(ContextArgs),
}

#[derive(Args, Debug)]
struct IndexArgs {
    #[arg(short = 'c', long)]
    compile_commands: Option<PathBuf>,
    #[arg(short = 'm', long, default_value_t = 500)]
    max_commits: i32,
    #[arg(short = 't', long, value_parser = positive_usize)]
    tu_limit: Option<usize>,
    #[arg(short = 'j', long, default_value_t = default_jobs(), value_parser = positive_usize)]
    jobs: usize,
    #[arg(short = 'b', long, default_value_t = 5000, value_parser = positive_usize)]
    batch_size: usize,
    #[arg(short = 'r', long, action = ArgAction::SetTrue, default_value_t = false)]
    detailed_processing_record: bool,
    #[arg(short = 'W', long, action = ArgAction::SetTrue, default_value_t = false)]
    libclang_warnings: bool,
}

#[derive(Args, Debug)]
struct SymbolArgs {
    name: String,
    #[arg(short = 'l', long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug)]
struct TermArgs {
    term: String,
    #[arg(short = 'l', long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug)]
struct CommitArgs {
    #[arg(default_value = "")]
    term: String,
    #[arg(short = 'l', long, default_value_t = 20)]
    limit: usize,
}

#[derive(Args, Debug)]
struct ContextArgs {
    term: String,
    #[arg(short = 'p', long)]
    pattern: Option<String>,
    #[arg(short = 'n', long, default_value_t = 8)]
    window: usize,
    #[arg(short = 'l', long, default_value_t = 20)]
    limit: usize,
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
    let cli = Cli::parse();
    let workspace = resolve_workspace(&cli.workspace)?;
    let db = resolve_db(&workspace, &cli.db);
    match cli.command {
        Command::Index(args) => index_workspace(&workspace, &db, args),
        Command::Meta => query::meta(&workspace, &db),
        Command::Symbols(args) | Command::Symbol(args) => {
            query::symbols(&workspace, &db, &args.name, args.limit)
        }
        Command::Definition(args) => query::definition(&workspace, &db, &args.term, args.limit),
        Command::Refs(args) => query::refs(&workspace, &db, &args.term, args.limit),
        Command::Commits(args) => query::commits(&workspace, &db, &args.term, args.limit),
        Command::Context(args) => query::context(
            &workspace,
            &db,
            &args.term,
            args.pattern.as_deref(),
            args.window,
            args.limit,
        ),
    }
}

fn resolve_workspace(workspace: &Path) -> Result<PathBuf> {
    if workspace.exists() {
        return fs::canonicalize(workspace)
            .with_context(|| format!("无法解析 workspace: {}", workspace.display()));
    }
    let absolute = if workspace.is_absolute() {
        workspace.to_path_buf()
    } else {
        std::env::current_dir()?.join(workspace)
    };
    Ok(absolute)
}

fn resolve_db(workspace: &Path, db: &Path) -> PathBuf {
    if db.is_absolute() {
        db.to_path_buf()
    } else {
        workspace.join(db)
    }
}

fn index_workspace(workspace: &Path, db: &Path, args: IndexArgs) -> Result<()> {
    let total_started = Instant::now();
    let workspace = fs::canonicalize(workspace)
        .with_context(|| format!("无法解析 workspace: {}", workspace.display()))?;
    let path_cache = PathCache::new();
    if let Some(parent) = db.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建数据库目录: {}", parent.display()))?;
    }

    let compile_commands_path =
        find_compile_commands(&workspace, args.compile_commands.as_deref(), &path_cache);
    let (mut compile_commands, compile_commands_meta) = load_compile_commands(
        compile_commands_path.as_deref(),
        &workspace,
        &path_cache,
        !args.libclang_warnings,
    )?;
    if let Some(limit) = args.tu_limit {
        compile_commands.truncate(limit);
    }

    let mut conn =
        Connection::open(db).with_context(|| format!("无法打开数据库: {}", db.display()))?;
    reset_db(&mut conn)?;

    let semantic_started = Instant::now();
    let (symbol_count, ref_count) = index_translation_units(
        &conn,
        &workspace,
        &compile_commands,
        &path_cache,
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
