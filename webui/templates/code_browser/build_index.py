#!/usr/bin/env python3
import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import sqlite3
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
SCHEMA = SCRIPT_DIR / "schema.sql"
DEFAULT_DB = Path("code_browser") / "code_browser.sqlite"

SOURCE_EXTS = {
    ".c": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".h": "c-header",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".hxx": "cpp",
    ".inc": "text",
    ".rs": "rust",
    ".go": "go",
    ".py": "python",
    ".js": "js",
    ".mjs": "js",
    ".ts": "ts",
    ".java": "java",
    ".kt": "kotlin",
    ".swift": "swift",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".cmake": "cmake",
    ".gn": "gn",
    ".gni": "gn",
    ".md": "markdown",
    ".proto": "proto",
    ".thrift": "thrift",
    ".idl": "idl",
}

C_FAMILY_EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
DEFAULT_EXCLUDE_PARTS = {
    ".git",
    ".hg",
    ".svn",
    ".cache",
    "__pycache__",
    "node_modules",
    "target",
    "build",
    "out",
    "dist",
    "vendor",
    "third_party",
}

TEST_PATH_PARTS = {"test", "tests", "spec", "fuzz", "fuzzer", "unittest", "integration"}
SECURITY_TERMS = ("security", "cve", "overflow", "oob", "uaf", "race", "crash", "fuzz", "sanitize", "bounds", "fix")


@dataclass(frozen=True)
class CompileCommand:
    source: Path
    directory: Path
    args: list[str]


@dataclass
class TuRows:
    symbols: list[tuple]
    refs: list[tuple]
    diagnostics: list[tuple]


def resolve_workspace(value: str) -> Path:
    return Path(value).expanduser().resolve()


def rel(workspace: Path, path: Path) -> str:
    return path.resolve().relative_to(workspace).as_posix()


def in_workspace(workspace: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(workspace)
        return True
    except ValueError:
        return False


def sha1_bytes(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


def git_output(workspace: Path, args: list[str]) -> str | None:
    if not (workspace / ".git").exists():
        return None
    try:
        return subprocess.check_output(
            ["git", "-C", str(workspace), *args],
            text=True,
            errors="replace",
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def git_metadata(workspace: Path) -> dict[str, str]:
    head = git_output(workspace, ["rev-parse", "HEAD"]) or ""
    status = git_output(workspace, ["status", "--porcelain"])
    return {
        "workspace": str(workspace),
        "git_head": head,
        "git_dirty": "unknown" if status is None else ("yes" if status else "no"),
        "git_status_count": "unknown" if status is None else str(len(status.splitlines())),
    }


def ensure_schema(conn: sqlite3.Connection):
    schema = SCHEMA.read_text(encoding="utf-8")
    conn.executescript(schema)
    conn.execute("DROP TABLE IF EXISTS tests")
    columns = {row[1] for row in conn.execute("PRAGMA table_info(commits)")}
    if {"source_files", "test_files"} & columns:
        conn.execute("DROP TABLE IF EXISTS commits")
        conn.executescript(schema)


def reset_db(conn: sqlite3.Connection):
    ensure_schema(conn)
    for table in ("files", "symbols", "refs", "diagnostics", "commits", "routes", "meta"):
        conn.execute(f"DELETE FROM {table}")


def should_skip(path: Path, exclude_parts: set[str]) -> bool:
    return any(part in exclude_parts for part in path.parts)


def is_test_path(workspace: Path, path: Path) -> bool:
    try:
        parts = path.resolve().relative_to(workspace).parts
    except ValueError:
        parts = path.parts
    lower_parts = [part.lower() for part in parts]
    if any(part in TEST_PATH_PARTS for part in lower_parts[:-1]):
        return True
    name = lower_parts[-1] if lower_parts else path.name.lower()
    return (
        name.startswith("test_")
        or name in {"test.js", "spec.js"}
        or name.endswith(
            (
                "_test.c",
                "_test.cc",
                "_test.cpp",
                "_test.cxx",
                "_test.h",
                "_test.hpp",
                "_test.go",
                "_test.rs",
                "_test.py",
            )
        )
    )


def iter_files(workspace: Path, paths: list[Path], exclude_parts: set[str], limit: int | None):
    count = 0
    for base in paths:
        if not base.exists():
            continue
        candidates = [base] if base.is_file() else (p for p in base.rglob("*") if p.is_file())
        for path in candidates:
            if path.suffix not in SOURCE_EXTS:
                continue
            if not in_workspace(workspace, path):
                continue
            if should_skip(path, exclude_parts):
                continue
            if is_test_path(workspace, path):
                continue
            yield path
            count += 1
            if limit and count >= limit:
                return


def find_compile_commands(workspace: Path, explicit: Path | None) -> Path | None:
    if explicit:
        path = explicit.expanduser()
        return path if path.is_absolute() else workspace / path
    direct = workspace / "compile_commands.json"
    if direct.exists():
        return direct
    for name in ("build", "cmake-build-debug", "cmake-build-release", "out"):
        candidate = workspace / name / "compile_commands.json"
        if candidate.exists():
            return candidate
    for candidate in workspace.rglob("compile_commands.json"):
        if should_skip(candidate, DEFAULT_EXCLUDE_PARTS - {"build", "out"}):
            continue
        return candidate
    return None


def clang_resource_dir() -> str:
    for binary in ("clang", "clang-20", "clang-19", "clang-18", "clang-17"):
        try:
            value = subprocess.check_output([binary, "-print-resource-dir"], text=True, stderr=subprocess.DEVNULL).strip()
        except (OSError, subprocess.CalledProcessError):
            continue
        if value:
            return value
    return ""


def source_arg_matches(arg: str, directory: Path, source: Path) -> bool:
    path = Path(arg)
    candidate = path if path.is_absolute() else directory / path
    try:
        return candidate.resolve() == source.resolve()
    except OSError:
        return False


def absolutize_arg_path(value: str, directory: Path) -> str:
    if not value or value.startswith("$"):
        return value
    path = Path(value)
    return str(path if path.is_absolute() else (directory / path).resolve())


def compiler_payload(raw_args: list[str]) -> list[str]:
    wrappers = {"ccache", "sccache", "distcc", "icecc"}
    compilers = {"cc", "c++", "gcc", "g++", "clang", "clang++", "cl", "emcc", "em++"}
    i = 0
    while i < len(raw_args):
        arg = raw_args[i]
        base = Path(arg).name
        if arg == "env" or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", arg):
            i += 1
            continue
        if base in wrappers:
            i += 1
            continue
        if base in compilers or re.match(r"^(?:[A-Za-z0-9_.+-]+-)?(?:gcc|g\+\+|clang|clang\+\+|cc|c\+\+)$", base):
            return raw_args[i + 1 :]
        break
    return raw_args[1:] if raw_args else []


def clean_compile_args(raw_args: list[str], directory: Path, source: Path, resource_dir: str) -> list[str]:
    args = compiler_payload(raw_args)
    cleaned: list[str] = []
    skip_next = False
    pending_path_opt: str | None = None
    path_taking_opts = {
        "-I",
        "-isystem",
        "-iquote",
        "-idirafter",
        "-include",
        "-imacros",
        "-isysroot",
        "--sysroot",
    }
    drop_value_opts = {"-o"}

    for arg in args:
        if skip_next:
            skip_next = False
            continue
        if pending_path_opt:
            cleaned.append(absolutize_arg_path(arg, directory))
            pending_path_opt = None
            continue
        if arg in {"-c", "-S"} or arg == source.name or source_arg_matches(arg, directory, source):
            continue
        if arg in drop_value_opts:
            skip_next = True
            continue
        if arg.startswith("-o") and len(arg) > 2:
            continue
        if arg in path_taking_opts:
            cleaned.append(arg)
            pending_path_opt = arg
            continue
        handled_joined = False
        for opt in ("-I", "-isystem", "-iquote", "-idirafter", "-include", "-imacros"):
            if arg.startswith(opt) and len(arg) > len(opt):
                cleaned.append(opt + absolutize_arg_path(arg[len(opt) :], directory))
                handled_joined = True
                break
        if handled_joined:
            continue
        if arg.startswith("--sysroot="):
            cleaned.append("--sysroot=" + absolutize_arg_path(arg.split("=", 1)[1], directory))
            continue
        cleaned.append(arg)

    if resource_dir and "-resource-dir" not in cleaned and not any(arg.startswith("-resource-dir=") for arg in cleaned):
        cleaned.extend(["-resource-dir", resource_dir])
    return cleaned


def load_compile_commands(path: Path | None, workspace: Path) -> tuple[list[CompileCommand], str]:
    if not path or not path.exists():
        return [], ""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit(f"compile_commands.json 不是 JSON 数组: {path}")
    resource_dir = clang_resource_dir()
    commands: list[CompileCommand] = []
    seen: set[Path] = set()
    for item in data:
        if not isinstance(item, dict):
            continue
        directory = Path(str(item.get("directory") or workspace)).expanduser()
        directory = directory if directory.is_absolute() else workspace / directory
        file_value = item.get("file")
        if not file_value:
            continue
        source = Path(str(file_value)).expanduser()
        source = source if source.is_absolute() else directory / source
        source = source.resolve()
        if source.suffix not in C_FAMILY_EXTS or not source.exists():
            continue
        if in_workspace(workspace, source) and is_test_path(workspace, source):
            continue
        if source in seen:
            continue
        seen.add(source)
        if isinstance(item.get("arguments"), list):
            raw_args = [str(arg) for arg in item["arguments"]]
        elif item.get("command"):
            raw_args = shlex.split(str(item["command"]))
        else:
            raw_args = ["clang", str(source)]
        commands.append(CompileCommand(source, directory.resolve(), clean_compile_args(raw_args, directory.resolve(), source, resource_dir)))
    return commands, str(path)


def load_routes(route_file: Path | None):
    if not route_file:
        return []
    data = json.loads(route_file.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise SystemExit("route file 必须是 JSON 数组")
    routes = []
    for item in data:
        if not isinstance(item, dict):
            continue
        pattern = str(item.get("pattern") or "").strip()
        skill = str(item.get("skill") or "").strip()
        reason = str(item.get("reason") or "").strip()
        if pattern and skill:
            routes.append((pattern, skill, reason))
    return routes


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def commit_hints(subject: str, files: list[str]) -> tuple[list[str], str]:
    haystack = (subject + " " + " ".join(files)).lower()
    hints = [term for term in SECURITY_TERMS if term in haystack]
    signal = ",".join(hints[:5])
    return hints, signal


def index_commits(conn: sqlite3.Connection, workspace: Path, max_commits: int):
    if max_commits <= 0 or not (workspace / ".git").exists():
        return
    raw = git_output(
        workspace,
        ["log", f"-n{max_commits}", "--date=iso-strict", "--name-only", "--format=%H%x09%ad%x09%s"],
    )
    if not raw:
        return
    current = None
    commits = []
    for line in raw.splitlines():
        if "\t" in line:
            if current:
                commits.append(current)
            parts = line.split("\t", 2)
            current = {"hash": parts[0], "date": parts[1] if len(parts) > 1 else "", "subject": parts[2] if len(parts) > 2 else "", "files": []}
        elif current is not None and line.strip():
            current["files"].append(line.strip())
    if current:
        commits.append(current)

    for item in commits:
        hints, signal = commit_hints(item["subject"], item["files"])
        conn.execute(
            """
            INSERT OR REPLACE INTO commits(hash, subject, date, files, diff_hints, audit_signal)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                item["hash"],
                item["subject"],
                item["date"],
                json.dumps(item["files"]),
                json.dumps(hints),
                signal,
            ),
        )


def cursor_location(cursor):
    loc = cursor.location
    if not loc or not loc.file:
        return None
    return Path(str(loc.file.name)).resolve(), int(loc.line or 0), int(loc.column or 0)


def cursor_extent(cursor):
    extent = cursor.extent
    return (
        int(extent.start.line or 0),
        int(extent.start.column or 0),
        int(extent.end.line or 0),
        int(extent.end.column or 0),
    )


def cursor_usr(cursor) -> str:
    try:
        return cursor.get_usr() or ""
    except Exception:
        return ""


def cursor_signature(cursor) -> str:
    try:
        args = [arg.spelling or "" for arg in cursor.get_arguments() or []]
    except Exception:
        args = []
    if args:
        return f"{cursor.spelling}({', '.join(args)})"
    return cursor.displayname or cursor.spelling or ""


def line_context(path: Path, line: int, cache: dict[Path, list[str]]) -> str:
    if path not in cache:
        try:
            cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            cache[path] = []
    lines = cache[path]
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:300]
    return ""


def severity_name(value: int) -> str:
    return {0: "ignored", 1: "note", 2: "warning", 3: "error", 4: "fatal"}.get(value, str(value))


def count_table(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def flush_batch(conn: sqlite3.Connection, sql: str, rows: list[tuple], batch_size: int, force: bool = False):
    while rows and (force or len(rows) >= batch_size):
        chunk_size = len(rows) if force else batch_size
        conn.executemany(sql, rows[:chunk_size])
        del rows[:chunk_size]


def parse_options(cindex, detailed_processing_record: bool) -> int:
    if detailed_processing_record:
        return cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD
    return 0


def extract_translation_unit_rows(args: tuple[str, CompileCommand, bool]) -> TuRows:
    workspace_value, command, detailed_processing_record = args
    workspace = Path(workspace_value)
    rows = TuRows(symbols=[], refs=[], diagnostics=[])
    source_cache: dict[Path, list[str]] = {}
    try:
        from clang import cindex
    except Exception as exc:
        rpath = rel(workspace, command.source) if in_workspace(workspace, command.source) else str(command.source)
        rows.diagnostics.append((rpath, 0, 0, 4, f"libclang import failed: {exc}"))
        return rows

    declaration_kinds = {
        cindex.CursorKind.FUNCTION_DECL,
        cindex.CursorKind.CXX_METHOD,
        cindex.CursorKind.CONSTRUCTOR,
        cindex.CursorKind.DESTRUCTOR,
        cindex.CursorKind.FUNCTION_TEMPLATE,
        cindex.CursorKind.CLASS_DECL,
        cindex.CursorKind.CLASS_TEMPLATE,
        cindex.CursorKind.STRUCT_DECL,
        cindex.CursorKind.UNION_DECL,
        cindex.CursorKind.ENUM_DECL,
        cindex.CursorKind.TYPEDEF_DECL,
        cindex.CursorKind.TYPE_ALIAS_DECL,
        cindex.CursorKind.VAR_DECL,
        cindex.CursorKind.FIELD_DECL,
        cindex.CursorKind.ENUM_CONSTANT_DECL,
        cindex.CursorKind.NAMESPACE,
    }
    reference_kinds = {
        cindex.CursorKind.DECL_REF_EXPR,
        cindex.CursorKind.MEMBER_REF_EXPR,
        cindex.CursorKind.CALL_EXPR,
        cindex.CursorKind.TYPE_REF,
        cindex.CursorKind.TEMPLATE_REF,
        cindex.CursorKind.NAMESPACE_REF,
        cindex.CursorKind.MEMBER_REF,
    }

    index = cindex.Index.create()
    try:
        tu = index.parse(str(command.source), args=command.args, options=parse_options(cindex, detailed_processing_record))
    except Exception as exc:
        rpath = rel(workspace, command.source) if in_workspace(workspace, command.source) else str(command.source)
        rows.diagnostics.append((rpath, 0, 0, 4, f"libclang parse failed: {exc}"))
        return rows

    for diagnostic in tu.diagnostics:
        loc = diagnostic.location
        path = None
        if loc and loc.file:
            dpath = Path(str(loc.file.name)).resolve()
            path = rel(workspace, dpath) if in_workspace(workspace, dpath) else str(dpath)
        rows.diagnostics.append(
            (
                path,
                int(loc.line or 0),
                int(loc.column or 0),
                int(diagnostic.severity),
                f"{severity_name(int(diagnostic.severity))}: {diagnostic.spelling}",
            )
        )

    stack = [tu.cursor]
    while stack:
        cursor = stack.pop()
        location = cursor_location(cursor)
        if not location:
            stack.extend(reversed(list(cursor.get_children())))
            continue
        path, line, column = location
        if not in_workspace(workspace, path):
            continue

        stack.extend(reversed(list(cursor.get_children())))
        rpath = rel(workspace, path)
        spelling = cursor.spelling or cursor.displayname or ""

        if cursor.kind in declaration_kinds and spelling:
            start_line, start_col, end_line, end_col = cursor_extent(cursor)
            try:
                type_text = cursor.type.spelling or ""
            except Exception:
                type_text = ""
            rows.symbols.append(
                (
                    cursor_usr(cursor),
                    spelling,
                    str(cursor.kind).split(".")[-1],
                    rpath,
                    line,
                    column,
                    start_line,
                    start_col,
                    end_line,
                    end_col,
                    1 if cursor.is_definition() else 0,
                    type_text,
                    cursor_signature(cursor),
                )
            )

        if cursor.kind in reference_kinds:
            referenced = cursor.referenced
            if not referenced:
                continue
            ref_usr = cursor_usr(referenced)
            ref_name = referenced.spelling or cursor.spelling or cursor.displayname or ""
            if not ref_usr or not ref_name:
                continue
            rows.refs.append(
                (
                    ref_usr,
                    ref_name,
                    str(cursor.kind).split(".")[-1],
                    rpath,
                    line,
                    column,
                    line_context(path, line, source_cache),
                )
            )

    return rows


def index_translation_units(
    conn: sqlite3.Connection,
    workspace: Path,
    commands: list[CompileCommand],
    jobs: int,
    batch_size: int,
    detailed_processing_record: bool,
) -> tuple[int, int, int]:
    if not commands:
        return 0, 0, 0
    try:
        from clang import cindex  # noqa: F401
    except Exception as exc:
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", ("libclang_error", str(exc)))
        return 0, 0, 0

    symbol_sql = """
        INSERT OR IGNORE INTO symbols(
          usr, name, kind, path, line, column,
          extent_start_line, extent_start_column, extent_end_line, extent_end_column,
          is_definition, type, signature, backend
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'libclang')
    """
    ref_sql = """
        INSERT OR IGNORE INTO refs(referenced_usr, name, kind, path, line, column, context)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """
    diagnostic_sql = "INSERT INTO diagnostics(path, line, column, severity, message) VALUES (?, ?, ?, ?, ?)"
    symbol_rows: list[tuple] = []
    ref_rows: list[tuple] = []
    diagnostic_rows: list[tuple] = []

    def write_rows(rows: TuRows):
        symbol_rows.extend(rows.symbols)
        ref_rows.extend(rows.refs)
        diagnostic_rows.extend(rows.diagnostics)
        flush_batch(conn, symbol_sql, symbol_rows, batch_size)
        flush_batch(conn, ref_sql, ref_rows, batch_size)
        flush_batch(conn, diagnostic_sql, diagnostic_rows, batch_size)

    if jobs <= 1 or len(commands) <= 1:
        for command in commands:
            write_rows(extract_translation_unit_rows((str(workspace), command, detailed_processing_record)))
    else:
        max_workers = min(jobs, len(commands))
        with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(extract_translation_unit_rows, (str(workspace), command, detailed_processing_record)): command
                for command in commands
            }
            for future in concurrent.futures.as_completed(futures):
                command = futures[future]
                try:
                    write_rows(future.result())
                except Exception as exc:
                    rpath = rel(workspace, command.source) if in_workspace(workspace, command.source) else str(command.source)
                    diagnostic_rows.append((rpath, 0, 0, 4, f"index worker failed: {exc}"))
                    flush_batch(conn, diagnostic_sql, diagnostic_rows, batch_size)

    flush_batch(conn, symbol_sql, symbol_rows, batch_size, force=True)
    flush_batch(conn, ref_sql, ref_rows, batch_size, force=True)
    flush_batch(conn, diagnostic_sql, diagnostic_rows, batch_size, force=True)
    return count_table(conn, "symbols"), count_table(conn, "refs"), count_table(conn, "diagnostics")


def main():
    parser = argparse.ArgumentParser(description="构建面向 C/C++ 审计的 libclang 语义索引。")
    parser.add_argument("--workspace", default=".", help="目标工作区根目录。")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite 索引路径。")
    parser.add_argument("--compile-commands", type=Path, help="compile_commands.json 路径；默认在 workspace 内查找。")
    parser.add_argument("--path", action="append", default=[], help="要收集文件辅助信息的路径，可重复。默认整个 workspace。")
    parser.add_argument("--exclude-part", action="append", default=[], help="要跳过的路径组件，可重复。")
    parser.add_argument("--route-file", type=Path, help="包含 pattern/skill/reason 条目的 JSON 路由文件。")
    parser.add_argument("--max-commits", type=int, default=500)
    parser.add_argument("--limit", type=int, help="Limit indexed files for quick validation.")
    parser.add_argument("--tu-limit", type=positive_int, help="Limit compile commands used for semantic indexing.")
    parser.add_argument("--jobs", type=positive_int, default=min(os.cpu_count() or 1, 8), help="Semantic indexing worker count.")
    parser.add_argument("--batch-size", type=positive_int, default=5000, help="SQLite executemany batch size.")
    parser.add_argument(
        "--detailed-processing-record",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use libclang PARSE_DETAILED_PROCESSING_RECORD.",
    )
    args = parser.parse_args()

    workspace = resolve_workspace(args.workspace)
    db = args.db if args.db.is_absolute() else workspace / args.db
    db.parent.mkdir(parents=True, exist_ok=True)

    paths = [Path(p).expanduser() for p in args.path] if args.path else [workspace]
    paths = [p if p.is_absolute() else workspace / p for p in paths]
    exclude_parts = set(DEFAULT_EXCLUDE_PARTS) | set(args.exclude_part)

    compile_commands_path = find_compile_commands(workspace, args.compile_commands)
    compile_commands, compile_commands_meta = load_compile_commands(compile_commands_path, workspace)
    compile_db_sources = {rel(workspace, command.source) for command in compile_commands if in_workspace(workspace, command.source)}
    if args.tu_limit:
        compile_commands = compile_commands[: args.tu_limit]

    conn = sqlite3.connect(db)
    reset_db(conn)
    for pattern, skill, reason in load_routes(args.route_file):
        conn.execute("INSERT OR REPLACE INTO routes(pattern, skill, reason) VALUES (?, ?, ?)", (pattern, skill, reason))

    file_sql = "INSERT OR REPLACE INTO files(path, lang, sha1, size, mtime, in_compile_db) VALUES (?, ?, ?, ?, ?, ?)"
    file_rows: list[tuple] = []
    for path in iter_files(workspace, paths, exclude_parts, args.limit):
        data = path.read_bytes()
        rpath = rel(workspace, path)
        lang = SOURCE_EXTS.get(path.suffix, "text")
        stat = path.stat()
        file_rows.append((rpath, lang, sha1_bytes(data), stat.st_size, stat.st_mtime, 1 if rpath in compile_db_sources else 0))
        flush_batch(conn, file_sql, file_rows, args.batch_size)
    flush_batch(conn, file_sql, file_rows, args.batch_size, force=True)
    file_count = count_table(conn, "files")

    semantic_started = time.perf_counter()
    symbol_count, ref_count, diag_count = index_translation_units(
        conn,
        workspace,
        compile_commands,
        args.jobs,
        args.batch_size,
        args.detailed_processing_record,
    )
    semantic_elapsed = time.perf_counter() - semantic_started
    index_commits(conn, workspace, args.max_commits)

    meta = {
        **git_metadata(workspace),
        "backend": "libclang",
        "compile_commands": compile_commands_meta,
        "compile_command_count": str(len(compile_commands)),
        "indexed_paths": json.dumps([rel(workspace, p) if in_workspace(workspace, p) else str(p) for p in paths]),
        "route_file": str(args.route_file or ""),
        "file_count": str(file_count),
        "symbol_count": str(symbol_count),
        "ref_count": str(ref_count),
        "diagnostic_count": str(diag_count),
        "jobs": str(args.jobs),
        "tu_limit": str(args.tu_limit or ""),
        "batch_size": str(args.batch_size),
        "detailed_processing_record": "yes" if args.detailed_processing_record else "no",
        "semantic_elapsed_seconds": f"{semantic_elapsed:.3f}",
    }
    for key, value in meta.items():
        conn.execute("INSERT OR REPLACE INTO meta(key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    print(
        "已索引 "
        f"backend=libclang files={file_count} symbols={symbol_count} refs={ref_count} "
        f"diagnostics={diag_count} db={db}"
    )


if __name__ == "__main__":
    main()
