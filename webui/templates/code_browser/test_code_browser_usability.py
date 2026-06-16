import json
import os
import sqlite3
import subprocess
from pathlib import Path

import pytest


CODE_BROWSER_DIR = Path(__file__).resolve().parent
CARGO_MANIFEST = CODE_BROWSER_DIR / "Cargo.toml"
QUERY = CODE_BROWSER_DIR / "query.py"


def project_root() -> Path:
    value = os.environ.get("CODE_BROWSER_PROJECT")
    if not value:
        pytest.skip("set CODE_BROWSER_PROJECT=/path/to/C-or-CXX-project")
    root = Path(value).expanduser().resolve()
    if not root.exists():
        pytest.skip(f"CODE_BROWSER_PROJECT does not exist: {root}")
    if not find_compile_commands(root):
        pytest.skip("project has no compile_commands.json; generate one with CMake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON or Bear")
    return root


def find_compile_commands(root: Path) -> Path | None:
    direct = root / "compile_commands.json"
    if direct.exists():
        return direct
    for name in ("build", "cmake-build-debug", "cmake-build-release", "out"):
        candidate = root / name / "compile_commands.json"
        if candidate.exists():
            return candidate
    for candidate in root.rglob("compile_commands.json"):
        return candidate
    return None


def build_index_cmd(*args: str) -> list[str]:
    return ["cargo", "run", "--release", "--manifest-path", str(CARGO_MANIFEST), "--bin", "build_index", "--", *args]


def build_timeout() -> int:
    return int(os.environ.get("CODE_BROWSER_BUILD_TIMEOUT", "240"))


@pytest.fixture(scope="session")
def indexed_db(tmp_path_factory):
    root = project_root()
    db = tmp_path_factory.mktemp("code_browser") / "code_browser.sqlite"
    proc = subprocess.run(
        build_index_cmd("--workspace", str(root), "--db", str(db)),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=build_timeout(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return root, db


@pytest.fixture()
def conn(indexed_db):
    _, db = indexed_db
    handle = sqlite3.connect(db)
    handle.row_factory = sqlite3.Row
    try:
        yield handle
    finally:
        handle.close()


def run_query(root: Path, db: Path, *args: str) -> str:
    proc = subprocess.run(
        ["python3", str(QUERY), "--workspace", str(root), "--db", str(db), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def write_two_source_project(root: Path):
    src = root / "src"
    src.mkdir(parents=True)
    first = src / "first.c"
    second = src / "second.c"
    first.write_text("int alpha_helper(void) { return 7; }\nint alpha_main(void) { return alpha_helper(); }\n", encoding="utf-8")
    second.write_text("int beta_helper(void) { return 11; }\nint beta_main(void) { return beta_helper(); }\n", encoding="utf-8")
    commands = [
        {"directory": str(root), "file": str(first), "arguments": ["cc", "-c", str(first)]},
        {"directory": str(root), "file": str(second), "arguments": ["cc", "-c", str(second)]},
    ]
    (root / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")


def test_c_family_test_and_fuzz_translation_units_are_indexed(tmp_path):
    root = tmp_path / "project"
    src = root / "src"
    tests = root / "tests"
    fuzz = root / "fuzz"
    src.mkdir(parents=True)
    tests.mkdir()
    fuzz.mkdir()
    (src / "main.c").write_text("int helper(void) { return 1; }\nint main(void) { return helper(); }\n", encoding="utf-8")
    (src / "helper_test.c").write_text("int helper_test(void) { return 0; }\n", encoding="utf-8")
    (tests / "test_main.c").write_text("int test_main(void) { return 0; }\n", encoding="utf-8")
    (fuzz / "fuzz_main.c").write_text("int fuzz_main(void) { return 0; }\n", encoding="utf-8")
    commands = [
        {"directory": str(root), "file": str(src / "main.c"), "arguments": ["cc", "-c", str(src / "main.c")]},
        {"directory": str(root), "file": str(tests / "test_main.c"), "arguments": ["cc", "-c", str(tests / "test_main.c")]},
        {"directory": str(root), "file": str(fuzz / "fuzz_main.c"), "arguments": ["cc", "-c", str(fuzz / "fuzz_main.c")]},
    ]
    (root / "compile_commands.json").write_text(json.dumps(commands), encoding="utf-8")
    db = tmp_path / "code_browser.sqlite"

    proc = subprocess.run(
        build_index_cmd("--workspace", str(root), "--db", str(db)),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=build_timeout(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    handle = sqlite3.connect(db)
    try:
        tables = {row[0] for row in handle.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        assert "tests" not in tables
        meta = {row[0]: row[1] for row in handle.execute("SELECT key, value FROM meta")}
        assert meta["compile_command_count"] == "3"
        assert meta["detailed_processing_record"] == "no"
        names = {row[0] for row in handle.execute("SELECT name FROM symbols")}
        assert {"helper", "test_main", "fuzz_main"} <= names
        assert "helper_test" not in names
    finally:
        handle.close()


def test_tu_limit_restricts_semantic_indexing(tmp_path):
    root = tmp_path / "project"
    write_two_source_project(root)
    db = tmp_path / "code_browser.sqlite"

    proc = subprocess.run(
        build_index_cmd("--workspace", str(root), "--db", str(db), "--jobs", "1", "--tu-limit", "1"),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=build_timeout(),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr

    handle = sqlite3.connect(db)
    try:
        meta = {row[0]: row[1] for row in handle.execute("SELECT key, value FROM meta")}
        assert meta["compile_command_count"] == "1"
        assert meta["tu_limit"] == "1"
        names = {row[0] for row in handle.execute("SELECT name FROM symbols")}
        assert "alpha_helper" in names
        assert "beta_helper" not in names
    finally:
        handle.close()


def test_parallel_and_serial_index_same_rows(tmp_path):
    root = tmp_path / "project"
    write_two_source_project(root)
    serial_db = tmp_path / "serial.sqlite"
    parallel_db = tmp_path / "parallel.sqlite"

    for db, jobs in ((serial_db, "1"), (parallel_db, "2")):
        proc = subprocess.run(
            build_index_cmd("--workspace", str(root), "--db", str(db), "--jobs", jobs),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=build_timeout(),
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr

    def indexed_rows(db: Path, table: str, columns: str):
        handle = sqlite3.connect(db)
        try:
            return set(handle.execute(f"SELECT {columns} FROM {table}").fetchall())
        finally:
            handle.close()

    assert indexed_rows(serial_db, "symbols", "usr, name, kind, path, line, is_definition") == indexed_rows(
        parallel_db, "symbols", "usr, name, kind, path, line, is_definition"
    )
    assert indexed_rows(serial_db, "refs", "referenced_usr, name, kind, path, line, context") == indexed_rows(
        parallel_db, "refs", "referenced_usr, name, kind, path, line, context"
    )


def sample_definitions(conn, limit: int = 12):
    return conn.execute(
        """
        SELECT usr, name, kind, path, line
        FROM symbols
        WHERE usr IS NOT NULL
          AND usr != ''
          AND is_definition = 1
          AND kind IN (
            'FUNCTION_DECL', 'CXX_METHOD', 'CONSTRUCTOR', 'DESTRUCTOR', 'FUNCTION_TEMPLATE',
            'TYPEDEF_DECL', 'STRUCT_DECL', 'CLASS_DECL', 'UNION_DECL', 'ENUM_DECL', 'VAR_DECL'
          )
        ORDER BY
          CASE kind
            WHEN 'FUNCTION_DECL' THEN 0
            WHEN 'CXX_METHOD' THEN 1
            WHEN 'TYPEDEF_DECL' THEN 2
            WHEN 'STRUCT_DECL' THEN 3
            WHEN 'CLASS_DECL' THEN 4
            WHEN 'ENUM_DECL' THEN 5
            ELSE 6
          END,
          path, line
        LIMIT ?
        """,
        (limit,),
    ).fetchall()


def test_build_index_smoke(conn):
    meta = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}
    assert int(meta.get("symbol_count", "0")) > 0
    assert int(meta.get("ref_count", "0")) > 0


def test_simplified_schema(conn):
    tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert {"meta", "symbols", "refs", "commits"} <= tables
    assert {"files", "diagnostics", "routes"}.isdisjoint(tables)

    symbol_columns = {row[1] for row in conn.execute("PRAGMA table_info(symbols)")}
    assert {"column", "extent_start_line", "extent_start_column", "extent_end_line", "extent_end_column", "backend"}.isdisjoint(
        symbol_columns
    )
    assert {"usr", "name", "kind", "path", "line", "is_definition", "type", "signature"} <= symbol_columns

    ref_columns = {row[1] for row in conn.execute("PRAGMA table_info(refs)")}
    assert "column" not in ref_columns
    assert {"referenced_usr", "name", "kind", "path", "line", "context"} <= ref_columns

    meta = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}
    assert {"file_count", "diagnostic_count", "indexed_paths", "route_file", "file_elapsed_seconds"}.isdisjoint(meta)


def test_symbol_queries_from_index(indexed_db, conn):
    root, db = indexed_db
    rows = sample_definitions(conn, 8)
    if not rows:
        pytest.skip("no suitable semantic definitions indexed")
    for row in rows:
        out = run_query(root, db, "symbols", row["name"], "--limit", "20")
        assert row["name"] in out
        assert row["path"] in out


def test_refs_by_usr(indexed_db, conn):
    root, db = indexed_db
    row = conn.execute(
        """
        SELECT s.usr, s.name
        FROM symbols s
        WHERE s.usr IS NOT NULL
          AND s.usr != ''
          AND s.is_definition = 1
          AND EXISTS (SELECT 1 FROM refs r WHERE r.referenced_usr = s.usr)
        LIMIT 1
        """
    ).fetchone()
    if not row:
        pytest.skip("no definition with semantic refs indexed")
    out = run_query(root, db, "refs", row["usr"], "--limit", "20")
    assert ":1:" in out or ":2:" in out or ":" in out
    for line in [item for item in out.splitlines() if item.strip()]:
        parts = line.split(":", 3)
        assert len(parts) >= 3
        path = root / parts[0]
        assert path.exists(), line
        line_no = int(parts[1])
        assert line_no > 0
        assert line_no <= len(path.read_text(encoding="utf-8", errors="replace").splitlines())


def test_context_by_definition_location(indexed_db, conn):
    root, db = indexed_db
    rows = sample_definitions(conn, 1)
    if not rows:
        pytest.skip("no suitable semantic definitions indexed")
    row = rows[0]
    out = run_query(root, db, "context", f"{row['path']}:{row['line']}")
    assert "== 源码 ==" in out
    assert row["name"] in out or "== 符号 ==" in out


def test_ambiguous_name_behavior(indexed_db, conn):
    root, db = indexed_db
    row = conn.execute(
        """
        SELECT name
        FROM symbols
        WHERE usr IS NOT NULL AND usr != ''
        GROUP BY name
        HAVING COUNT(DISTINCT usr) > 1
        LIMIT 1
        """
    ).fetchone()
    if not row:
        pytest.skip("no ambiguous symbol names indexed")
    out = run_query(root, db, "refs", row["name"], "--limit", "20")
    assert "歧义" in out or "候选" in out or "ambiguous" in out.lower()


def test_regression_no_regex_container_bug(indexed_db, conn):
    root, db = indexed_db
    trace = root / "src" / "trace.c"
    if not trace.exists():
        pytest.skip("project has no src/trace.c")
    if "info_parse" not in trace.read_text(encoding="utf-8", errors="replace"):
        pytest.skip("project has no info_parse in src/trace.c")
    out = run_query(root, db, "symbols", "info_parse", "--limit", "20")
    assert "flag_name" not in out
