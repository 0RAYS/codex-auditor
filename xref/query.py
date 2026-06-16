#!/usr/bin/env python3
import argparse
import json
import re
import sqlite3
import subprocess
from pathlib import Path


DEFAULT_DB = Path("xref.db")
LOCATION_RE = re.compile(r"^(?P<path>.+):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def workspace_path(value: str) -> Path:
    return Path(value).expanduser().resolve()


def resolve_db(workspace: Path, db: Path) -> Path:
    return db if db.is_absolute() else workspace / db


def connect(db: Path):
    if not db.exists():
        raise SystemExit(
            f"找不到索引: {db}\n"
            "请先运行 xref 索引命令，或用源码执行: "
            "cargo run --release --manifest-path xref/Cargo.toml --bin build_index --"
        )
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    return conn


def meta_dict(conn) -> dict[str, str]:
    return {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}


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


def current_git_metadata(workspace: Path) -> dict[str, str]:
    head = git_output(workspace, ["rev-parse", "HEAD"]) or ""
    status = git_output(workspace, ["status", "--porcelain"])
    return {
        "current_git_head": head,
        "current_git_dirty": "unknown" if status is None else ("yes" if status else "no"),
        "current_git_status_count": "unknown" if status is None else str(len(status.splitlines())),
    }


def freshness(meta: dict[str, str], current: dict[str, str]) -> str:
    indexed = meta.get("git_head", "")
    current_head = current.get("current_git_head", "")
    if not indexed:
        return "未知：索引缺少 git_head"
    if not current_head:
        return "未知：当前 git head 不可用"
    if indexed != current_head:
        return f"过期：索引 {indexed[:12]} 当前 {current_head[:12]}"
    return "新鲜"


def normalize_path(workspace: Path, value: str) -> str:
    text = str(value).strip()
    if not text:
        return text
    path = Path(text)
    if path.is_absolute():
        try:
            return path.resolve().relative_to(workspace).as_posix()
        except ValueError:
            return path.as_posix()
    if text.startswith("./"):
        text = text[2:]
    return text


def split_location(workspace: Path, value: str):
    text = str(value).strip()
    match = LOCATION_RE.match(text)
    if not match:
        return normalize_path(workspace, text), None, None
    path = normalize_path(workspace, match.group("path"))
    start = int(match.group("start"))
    end = int(match.group("end") or start)
    if end < start:
        raise SystemExit(f"无效行号范围: {start}-{end}")
    return path, start, end


def print_rows(rows, fields):
    for row in rows:
        print(" | ".join(str(row[field] if row[field] is not None else "") for field in fields))


def json_list(value) -> list[str]:
    if not value:
        return []
    try:
        data = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        return []
    return [str(item) for item in data] if isinstance(data, list) else []


def source_window(workspace: Path, path: str, start: int, end: int):
    abs_path = workspace / path
    if not abs_path.exists():
        print(f"缺少文件: {path}")
        return
    lines = abs_path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, start)
    end = min(len(lines), end)
    for line_no in range(start, end + 1):
        print(f"{path}:{line_no}: {lines[line_no - 1]}")


def find_pattern_line(workspace: Path, path: str, pattern: str):
    regex = re.compile(pattern)
    abs_path = workspace / path
    if not abs_path.exists():
        return None
    for line_no, line in enumerate(abs_path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if regex.search(line):
            return line_no
    return None


def fetch_symbols(conn, term: str, limit: int, definitions_only: bool = False):
    like = f"%{term}%"
    definition_clause = "AND is_definition = 1" if definitions_only else ""
    return conn.execute(
        f"""
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
        """,
        (term, term, like, term, term, limit),
    ).fetchall()


def exact_symbol_candidates(conn, term: str, limit: int):
    return conn.execute(
        """
        SELECT
          COALESCE(usr, '') AS usr, name, kind, path, line, is_definition,
          COALESCE(signature, '') AS signature
        FROM symbols
        WHERE usr = ? OR name = ?
        ORDER BY CASE WHEN usr = ? THEN 0 ELSE 1 END, is_definition DESC, path, line
        LIMIT ?
        """,
        (term, term, term, limit),
    ).fetchall()


def symbol_usrs_for_name(conn, name: str, limit: int = 50) -> list[str]:
    rows = conn.execute(
        """
        SELECT DISTINCT usr
        FROM symbols
        WHERE name = ? AND usr IS NOT NULL AND usr != ''
        ORDER BY usr
        LIMIT ?
        """,
        (name, limit),
    ).fetchall()
    return [row["usr"] for row in rows]


def distinct_usrs(rows) -> list[str]:
    values = []
    for row in rows:
        usr = row["usr"]
        if usr and usr not in values:
            values.append(usr)
    return values


def cmd_meta(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    meta = meta_dict(conn)
    current = current_git_metadata(workspace)
    for key in (
        "backend",
        "compile_commands",
        "compile_command_count",
        "symbol_count",
        "ref_count",
        "git_head",
        "git_dirty",
        "git_status_count",
    ):
        if key in meta:
            print(f"{key}: {meta[key]}")
    for key in sorted(current):
        print(f"{key}: {current[key]}")
    print(f"index_freshness: {freshness(meta, current)}")


def cmd_symbols(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    rows = fetch_symbols(conn, args.name, args.limit)
    print_rows(rows, ["name", "kind", "path", "line", "is_definition", "signature", "usr"])


def cmd_def(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    rows = fetch_symbols(conn, args.term, args.limit, definitions_only=True)
    if not rows:
        rows = fetch_symbols(conn, args.term, args.limit)
    print_rows(rows, ["name", "kind", "path", "line", "is_definition", "signature", "usr"])


def print_ambiguous_refs(candidates):
    print("歧义符号：refs <name> 匹配多个 USR，请改用 refs <usr>。候选：")
    for row in candidates:
        print(f"{row['usr']} | {row['name']} | {row['kind']} | {row['path']}:{row['line']} | def={row['is_definition']} | {row['signature']}")


def cmd_refs(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    candidates = exact_symbol_candidates(conn, args.term, args.limit)
    exact_usr = conn.execute("SELECT 1 FROM symbols WHERE usr = ? LIMIT 1", (args.term,)).fetchone()
    if exact_usr:
        target_usr = args.term
    else:
        usrs = symbol_usrs_for_name(conn, args.term, args.limit + 1)
        if len(usrs) > 1:
            if len(distinct_usrs(candidates)) < len(usrs):
                candidates = exact_symbol_candidates(conn, args.term, max(args.limit, len(usrs)))
            print_ambiguous_refs(candidates)
            return
        target_usr = usrs[0] if usrs else ""

    if target_usr:
        rows = conn.execute(
            """
            SELECT referenced_usr, name, kind, path, line, context
            FROM refs
            WHERE referenced_usr = ?
            ORDER BY path, line
            LIMIT ?
            """,
            (target_usr, args.limit),
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT referenced_usr, name, kind, path, line, context
            FROM refs
            WHERE name = ?
            ORDER BY path, line
            LIMIT ?
            """,
            (args.term, args.limit),
        ).fetchall()
    for row in rows:
        print(f"{row['path']}:{row['line']}: {row['name']} [{row['kind']}] {row['context']}")


def cmd_commits(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    term = args.term or ""
    like = f"%{term}%"
    rows = conn.execute(
        """
        SELECT hash, date, subject, files, diff_hints, audit_signal
        FROM commits
        WHERE subject LIKE ? OR files LIKE ? OR diff_hints LIKE ? OR audit_signal LIKE ?
        ORDER BY date DESC
        LIMIT ?
        """,
        (like, like, like, like, args.limit),
    ).fetchall()
    for row in rows:
        print(
            f"{row['hash'][:12]} | {row['date']} | {row['subject']} | "
            f"files={','.join(json_list(row['files'])[:3]) or '-'} | "
            f"hints={','.join(json_list(row['diff_hints'])) or row['audit_signal'] or '-'}"
        )


def nearby_symbols(conn, path: str, start: int, end: int, limit: int):
    margin_start = max(1, start - 20)
    margin_end = end + 20
    return conn.execute(
        """
        SELECT name, kind, path, line, is_definition, COALESCE(signature, '') AS signature, COALESCE(usr, '') AS usr
        FROM symbols
        WHERE path = ? AND line BETWEEN ? AND ?
        ORDER BY
          ABS(line - ?), is_definition DESC, line
        LIMIT ?
        """,
        (path, margin_start, margin_end, start, limit),
    ).fetchall()


def resolve_context_target(conn, workspace: Path, term: str, limit: int):
    path, start, end = split_location(workspace, term)
    if start is not None:
        return path, start, end, []
    if (workspace / path).exists():
        return path, 1, 80, []
    rows = fetch_symbols(conn, term, limit)
    if not rows:
        return path, None, None, []
    row = rows[0]
    return row["path"], max(1, int(row["line"]) - 8), int(row["line"]) + 8, rows


def cmd_context(args):
    workspace = workspace_path(args.workspace)
    conn = connect(resolve_db(workspace, args.db))
    path, start, end, symbol_rows = resolve_context_target(conn, workspace, args.term, args.limit)
    if args.pattern and path and (workspace / path).exists():
        line = find_pattern_line(workspace, path, args.pattern)
        if line:
            start = max(1, line - args.window)
            end = line + args.window
    if start is None or end is None:
        print(f"未找到上下文目标: {args.term}")
        return
    if not symbol_rows:
        symbol_rows = nearby_symbols(conn, path, start, end, args.limit)
    print("== 符号 ==")
    print_rows(symbol_rows, ["name", "kind", "path", "line", "is_definition", "signature"])
    print("== 源码 ==")
    source_window(workspace, path, max(1, start - args.window), end + args.window)
    print("== 引用 ==")
    if symbol_rows:
        target_usr = symbol_rows[0]["usr"]
        if target_usr:
            rows = conn.execute(
                "SELECT name, kind, path, line, context FROM refs WHERE referenced_usr = ? ORDER BY path, line LIMIT ?",
                (target_usr, min(args.limit, 10)),
            ).fetchall()
            for ref in rows:
                print(f"{ref['path']}:{ref['line']}: {ref['name']} [{ref['kind']}] {ref['context']}")
    print("== commits ==")
    cmd_commits(argparse.Namespace(workspace=args.workspace, db=args.db, term=path, limit=5))


def build_parser():
    parser = argparse.ArgumentParser(description="查询面向 C/C++ 审计的 libclang 语义索引。")
    parser.add_argument("--workspace", default=".", help="目标工作区根目录。")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="SQLite 索引路径。")
    sub = parser.add_subparsers(required=True)

    p = sub.add_parser("meta")
    p.set_defaults(func=cmd_meta)

    for name in ("symbols", "symbol"):
        p = sub.add_parser(name)
        p.add_argument("name")
        p.add_argument("--limit", type=int, default=20)
        p.set_defaults(func=cmd_symbols)

    p = sub.add_parser("def")
    p.add_argument("term")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_def)

    p = sub.add_parser("refs")
    p.add_argument("term")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_refs)

    p = sub.add_parser("commits")
    p.add_argument("term", nargs="?", default="")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_commits)

    p = sub.add_parser("context")
    p.add_argument("term")
    p.add_argument("--pattern")
    p.add_argument("--window", type=int, default=8)
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_context)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
