mod compile_db;
mod db;
mod git_index;
mod path_util;
mod progress;
mod query;
mod semantic;

use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser, Subcommand};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

use compile_db::{find_compile_commands, load_compile_commands};
use db::{IndexMeta, XrefDb};
use git_index::{git_metadata, index_commits};
use path_util::PathCache;
use semantic::index_translation_units;

const DEFAULT_DB: &str = "xref.db";
const APP_DATA_DIR: &str = "xref";
const SCHEMA_FILE: &str = "schema.sql";
const XREF_PREFIX_ENV: &str = "XREF_PREFIX";
const COMPILED_DEFAULT_PREFIX: &str = env!("XREF_DEFAULT_PREFIX");

#[derive(Parser, Debug)]
#[command(about = "面向 C/C++ 审计的源码索引和查询工具。")]
struct Cli {
    #[arg(short = 'w', long, default_value = ".", global = true)]
    workspace: PathBuf,
    #[arg(short = 'd', long, default_value = DEFAULT_DB, global = true)]
    db: PathBuf,
    #[arg(
        long,
        global = true,
        value_name = "PREFIX",
        help = "运行时数据文件 prefix，用于查找 schema.sql"
    )]
    prefix: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    #[command(about = "构建 C/C++ 语义索引。")]
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
    #[command(about = "查询 commit 辅助信息。")]
    Commits(CommitArgs),
    #[command(about = "显示文件位置或符号附近上下文。")]
    Context(ContextArgs),
}

#[derive(Args, Debug)]
struct IndexArgs {
    #[arg(short = 'c', long)]
    compile_commands: Option<PathBuf>,
    #[arg(long, action = ArgAction::SetTrue, default_value_t = false)]
    skip_commits: bool,
    #[arg(short = 't', long, value_parser = positive_usize)]
    tu_limit: Option<usize>,
    #[arg(short = 'j', long, default_value_t = 1, value_parser = positive_usize)]
    jobs: usize,
    #[arg(short = 'b', long, default_value_t = 500, value_parser = positive_usize)]
    batch_size: usize,
    #[arg(short = 'r', long, action = ArgAction::SetTrue, default_value_t = false)]
    detailed_processing_record: bool,
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
    let db_path = resolve_db(&workspace, &cli.db);
    let runtime_paths = RuntimePaths::new(cli.prefix.as_deref())?;
    match cli.command {
        Command::Index(args) => index_workspace(&workspace, &db_path, &runtime_paths, args),
        Command::Meta => query::meta(&workspace, &db_path),
        Command::Symbols(args) | Command::Symbol(args) => {
            query::symbols(&workspace, &db_path, &args.name, args.limit)
        }
        Command::Definition(args) => {
            query::definition(&workspace, &db_path, &args.term, args.limit)
        }
        Command::Refs(args) => query::refs(&workspace, &db_path, &args.term, args.limit),
        Command::Commits(args) => query::commits(&workspace, &db_path, &args.term, args.limit),
        Command::Context(args) => query::context(
            &workspace,
            &db_path,
            &args.term,
            args.pattern.as_deref(),
            args.window,
            args.limit,
        ),
    }
}

#[derive(Debug)]
struct RuntimePaths {
    prefix: PathBuf,
}

impl RuntimePaths {
    fn new(cli_prefix: Option<&Path>) -> Result<Self> {
        let prefix = match cli_prefix {
            Some(prefix) => absolutize_prefix(prefix)?,
            None => match std::env::var_os(XREF_PREFIX_ENV) {
                Some(prefix) => absolutize_prefix(Path::new(&prefix))?,
                None => PathBuf::from(COMPILED_DEFAULT_PREFIX),
            },
        };
        Ok(Self { prefix })
    }

    fn schema_path(&self) -> Result<PathBuf> {
        schema_candidates(&self.prefix)
            .into_iter()
            .find(|path| path.exists())
            .with_context(|| {
                format!(
                    "无法找到 schema。请把 {SCHEMA_FILE} 放到 prefix 下，或使用 --prefix <路径> / {XREF_PREFIX_ENV}=<路径> 指定数据目录；当前 prefix={}，编译期默认 prefix={}",
                    self.prefix.display(),
                    COMPILED_DEFAULT_PREFIX
                )
            })
    }
}

fn absolutize_prefix(prefix: &Path) -> Result<PathBuf> {
    if prefix.is_absolute() {
        Ok(prefix.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(prefix))
    }
}

fn schema_candidates(prefix: &Path) -> Vec<PathBuf> {
    vec![
        prefix.join(SCHEMA_FILE),
        prefix.join(APP_DATA_DIR).join(SCHEMA_FILE),
        prefix.join("share").join(APP_DATA_DIR).join(SCHEMA_FILE),
    ]
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

fn index_workspace(
    workspace: &Path,
    db: &Path,
    runtime_paths: &RuntimePaths,
    args: IndexArgs,
) -> Result<()> {
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
    let (mut compile_commands, compile_commands_meta) =
        load_compile_commands(compile_commands_path.as_deref(), &workspace, &path_cache)?;
    if let Some(limit) = args.tu_limit {
        compile_commands.truncate(limit);
    }

    let mut xref_db = XrefDb::create_for_index(db)?;
    xref_db.reset_schema(&runtime_paths.schema_path()?)?;

    let semantic_started = Instant::now();
    let (symbol_count, ref_count) = index_translation_units(
        &xref_db,
        &workspace,
        &compile_commands,
        &path_cache,
        args.jobs,
        args.batch_size,
        args.detailed_processing_record,
    )?;
    let semantic_elapsed = semantic_started.elapsed().as_secs_f64();
    let commit_started = Instant::now();
    let commit_count = if args.skip_commits {
        0
    } else {
        index_commits(&xref_db, &workspace, args.batch_size)?
    };
    let commit_elapsed = commit_started.elapsed().as_secs_f64();
    let total_elapsed = total_started.elapsed().as_secs_f64();

    let git_meta = git_metadata(&workspace);
    let meta = IndexMeta {
        workspace: git_meta.get("workspace").cloned().unwrap_or_default(),
        git_head: git_meta.get("git_head").cloned().unwrap_or_default(),
        git_dirty: git_meta
            .get("git_dirty")
            .cloned()
            .unwrap_or_else(|| "unknown".to_owned()),
        git_status_count: git_meta
            .get("git_status_count")
            .and_then(|value| value.parse::<usize>().ok()),
        compile_commands: compile_commands_meta,
        compile_command_count: compile_commands.len(),
        symbol_count,
        ref_count,
        commit_count,
        jobs: args.jobs,
        tu_limit: args.tu_limit,
        batch_size: args.batch_size,
        detailed_processing_record: args.detailed_processing_record,
        semantic_elapsed_seconds: semantic_elapsed,
        commit_elapsed_seconds: commit_elapsed,
        total_elapsed_seconds: total_elapsed,
    };
    xref_db.replace_index_meta(&meta)?;
    xref_db.checkpoint()?;
    println!(
        "已索引 symbols={symbol_count} refs={ref_count} db={}",
        db.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_default_prefix_is_absolute() {
        assert!(Path::new(COMPILED_DEFAULT_PREFIX).is_absolute());
    }

    #[test]
    fn schema_candidates_support_install_and_data_prefixes() {
        assert!(
            schema_candidates(Path::new("/usr"))
                .contains(&PathBuf::from("/usr/share/xref/schema.sql"))
        );
        assert!(
            schema_candidates(Path::new("/usr/share"))
                .contains(&PathBuf::from("/usr/share/xref/schema.sql"))
        );
        assert!(
            schema_candidates(Path::new("/usr/share/xref"))
                .contains(&PathBuf::from("/usr/share/xref/schema.sql"))
        );
    }
}
