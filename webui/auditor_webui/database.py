"""SQLite persistence for targets, sessions, messages, and runs."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from .config import CONFIG, target_workspace
from .schema import BUSY_STATUSES, SESSION_TYPES, TARGET_COLORS, JsonObject, JsonValue, RowDict, row_int, row_str
from .workspace import delete_target_workspace, validate_target_name

TARGET_COLUMNS = {
    "id",
    "name",
    "note",
    "workspace_path",
    "color_index",
    "auto_mining_state",
    "consecutive_nonzero_exit_count",
    "last_nonzero_exit_reason",
    "intervention_required",
    "intervention_reason",
    "intervention_notice_read",
    "created_at",
    "updated_at",
}
SESSION_COLUMNS = {
    "id",
    "target_id",
    "name",
    "session_type",
    "prompt",
    "bug_ids",
    "codex_session_id",
    "status",
    "last_error",
    "created_at",
    "updated_at",
}
MESSAGE_COLUMNS = {"id", "session_id", "role", "content", "kind", "created_at"}
RUN_COLUMNS = {
    "id",
    "session_id",
    "source",
    "prompt",
    "model",
    "status",
    "returncode",
    "started_at",
    "ended_at",
    "codex_session_id_before",
    "codex_session_id_after",
    "event_log_path",
    "last_message",
    "error",
}


def now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def ensure_dirs() -> None:
    CONFIG.audit_dir.mkdir(parents=True, exist_ok=True)
    CONFIG.temp_dir.mkdir(parents=True, exist_ok=True)
    CONFIG.workspace.mkdir(parents=True, exist_ok=True)


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(CONFIG.db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    ensure_dirs()
    with connect_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        )
        if schema_needs_rebuild(conn):
            rebuild_schema(conn)
        else:
            create_current_tables(conn)
        set_default_setting(conn, "theme", "light")
        set_default_setting(conn, "selected_target_id", "")
        set_default_setting(conn, "selected_session_id", "")
        timestamp = now_iso()
        conn.execute("UPDATE sessions SET status = 'interrupted', updated_at = ? WHERE status = 'running'", (timestamp,))
        conn.execute("UPDATE sessions SET status = 'finished' WHERE status IN ('idle', 'completed')")
        conn.execute("UPDATE sessions SET status = 'error' WHERE status = 'failed'")
        conn.execute(
            "UPDATE runs SET status = 'interrupted', ended_at = ? WHERE status = 'running'",
            (timestamp,),
        )
        conn.execute("UPDATE runs SET status = 'finished' WHERE status = 'completed'")
        conn.execute("UPDATE runs SET status = 'error' WHERE status = 'failed'")


def schema_needs_rebuild(conn: sqlite3.Connection) -> bool:
    expected = {
        "targets": TARGET_COLUMNS,
        "sessions": SESSION_COLUMNS,
        "messages": MESSAGE_COLUMNS,
        "runs": RUN_COLUMNS,
    }
    return any(
        table_exists(conn, table) and table_columns(conn, table) != columns
        for table, columns in expected.items()
    )


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}


def table_rows(conn: sqlite3.Connection, table: str) -> list[dict[str, object]]:
    if not table_exists(conn, table):
        return []
    return [dict(row) for row in conn.execute(f"SELECT * FROM {table}").fetchall()]


def create_current_tables(conn: sqlite3.Connection, suffix: str = "") -> None:
    targets = f"targets{suffix}"
    sessions = f"sessions{suffix}"
    messages = f"messages{suffix}"
    runs = f"runs{suffix}"
    conn.executescript(
        f"""
        CREATE TABLE IF NOT EXISTS {targets} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            note TEXT NOT NULL DEFAULT '',
            workspace_path TEXT NOT NULL UNIQUE,
            color_index INTEGER NOT NULL DEFAULT 0,
            auto_mining_state TEXT NOT NULL DEFAULT 'running',
            consecutive_nonzero_exit_count INTEGER NOT NULL DEFAULT 0,
            last_nonzero_exit_reason TEXT NOT NULL DEFAULT '',
            intervention_required INTEGER NOT NULL DEFAULT 0,
            intervention_reason TEXT NOT NULL DEFAULT '',
            intervention_notice_read INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS {sessions} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target_id INTEGER NOT NULL REFERENCES {targets}(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            session_type TEXT NOT NULL,
            prompt TEXT NOT NULL DEFAULT '',
            bug_ids TEXT NOT NULL DEFAULT '',
            codex_session_id TEXT,
            status TEXT NOT NULL DEFAULT 'finished',
            last_error TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS {messages} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES {sessions}(id) ON DELETE CASCADE,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            kind TEXT NOT NULL DEFAULT 'message',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS {runs} (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id INTEGER NOT NULL REFERENCES {sessions}(id) ON DELETE CASCADE,
            source TEXT NOT NULL,
            prompt TEXT NOT NULL,
            model TEXT NOT NULL,
            status TEXT NOT NULL,
            returncode INTEGER,
            started_at TEXT NOT NULL,
            ended_at TEXT,
            codex_session_id_before TEXT,
            codex_session_id_after TEXT,
            event_log_path TEXT,
            last_message TEXT,
            error TEXT
        );
        """,
    )


def rebuild_schema(conn: sqlite3.Connection) -> None:
    target_rows = table_rows(conn, "targets")
    session_rows = table_rows(conn, "sessions")
    message_rows = table_rows(conn, "messages")
    run_rows = table_rows(conn, "runs")
    targets, target_id_map, workspace_moves = migrate_targets(target_rows)
    sessions, session_id_map, generated_targets = migrate_sessions(session_rows, target_id_map, targets)
    targets.extend(generated_targets)

    conn.commit()
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("BEGIN")
        for table in ("runs_new", "messages_new", "sessions_new", "targets_new"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        create_current_tables(conn, "_new")
        insert_migrated_rows(conn, targets, sessions, message_rows, run_rows, session_id_map)
        for table in ("runs", "messages", "sessions", "targets"):
            conn.execute(f"DROP TABLE IF EXISTS {table}")
        for table in ("targets", "sessions", "messages", "runs"):
            conn.execute(f"ALTER TABLE {table}_new RENAME TO {table}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")

    for old_path, new_path in workspace_moves:
        try:
            old_resolved = old_path.resolve()
            root = CONFIG.workspace.resolve()
            can_move = old_resolved.is_relative_to(root) and old_resolved != root
            if can_move and old_path.exists() and not new_path.exists():
                old_path.rename(new_path)
        except OSError:
            continue


def migrate_targets(
    rows: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[int, int], list[tuple[Path, Path]]]:
    migrated: list[dict[str, object]] = []
    id_map: dict[int, int] = {}
    workspace_moves: list[tuple[Path, Path]] = []
    used_names: set[str] = set()
    timestamp = now_iso()
    for row in rows:
        raw_name = row.get("name")
        if not isinstance(raw_name, str):
            continue
        try:
            old_id = int(str(row.get("id", "")))
            name = validate_target_name(raw_name)
        except (TypeError, ValueError):
            continue
        if name in used_names:
            continue
        used_names.add(name)
        workspace = target_workspace(name)
        old_workspace = Path(str(row.get("workspace_path") or workspace))
        if old_workspace != workspace:
            workspace_moves.append((old_workspace, workspace))
        id_map[old_id] = old_id
        migrated.append(
            {
                "id": old_id,
                "name": name,
                "note": str(row.get("note") or ""),
                "workspace_path": str(workspace),
                "color_index": parse_int(row.get("color_index")) or 0,
                "auto_mining_state": normalize_auto_mining_state(row.get("auto_mining_state")),
                "consecutive_nonzero_exit_count": max(parse_int(row.get("consecutive_nonzero_exit_count")) or 0, 0),
                "last_nonzero_exit_reason": str(row.get("last_nonzero_exit_reason") or ""),
                "intervention_required": 1 if truthy(row.get("intervention_required")) else 0,
                "intervention_reason": str(row.get("intervention_reason") or ""),
                "intervention_notice_read": 0 if row.get("intervention_notice_read") in {0, "0", False} else 1,
                "created_at": str(row.get("created_at") or timestamp),
                "updated_at": str(row.get("updated_at") or timestamp),
            },
        )
    return migrated, id_map, workspace_moves


def migrate_sessions(
    rows: list[dict[str, object]],
    target_id_map: dict[int, int],
    targets: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[int, int], list[dict[str, object]]]:
    migrated: list[dict[str, object]] = []
    generated_targets: list[dict[str, object]] = []
    session_id_map: dict[int, int] = {}
    target_by_name = {str(target["name"]): int(str(target["id"])) for target in targets}
    next_target_id = max((int(str(target["id"])) for target in targets), default=0) + 1
    timestamp = now_iso()
    for row in rows:
        try:
            old_session_id = int(str(row.get("id", "")))
        except ValueError:
            continue
        old_target_id = parse_int(row.get("target_id"))
        target_id = target_id_map.get(old_target_id) if old_target_id is not None else None
        if target_id is None:
            raw_identifier = row.get("identifier")
            if not isinstance(raw_identifier, str):
                continue
            try:
                legacy_name = validate_target_name(raw_identifier)
            except ValueError:
                continue
            target_id = target_by_name.get(legacy_name)
            if target_id is None:
                target_id = next_target_id
                next_target_id += 1
                target_by_name[legacy_name] = target_id
                generated_targets.append(
                    {
                        "id": target_id,
                        "name": legacy_name,
                        "note": "",
                        "workspace_path": str(target_workspace(legacy_name)),
                        "color_index": (target_id - 1) % len(TARGET_COLORS),
                        "auto_mining_state": "running",
                        "consecutive_nonzero_exit_count": 0,
                        "last_nonzero_exit_reason": "",
                        "intervention_required": 0,
                        "intervention_reason": "",
                        "intervention_notice_read": 1,
                        "created_at": str(row.get("created_at") or timestamp),
                        "updated_at": str(row.get("updated_at") or timestamp),
                    },
                )
        session_type = str(row.get("session_type") or "debug")
        if session_type not in SESSION_TYPES:
            session_type = "debug"
        status = normalize_session_status(row.get("status"))
        session_id_map[old_session_id] = old_session_id
        migrated.append(
            {
                "id": old_session_id,
                "target_id": target_id,
                "name": str(row.get("name") or session_type),
                "session_type": session_type,
                "prompt": str(row.get("prompt") or ""),
                "bug_ids": normalize_bug_ids(row.get("bug_ids")),
                "codex_session_id": optional_text(row.get("codex_session_id")),
                "status": status,
                "last_error": optional_text(row.get("last_error")),
                "created_at": str(row.get("created_at") or timestamp),
                "updated_at": str(row.get("updated_at") or timestamp),
            },
        )
    return migrated, session_id_map, generated_targets


def insert_migrated_rows(
    conn: sqlite3.Connection,
    targets: list[dict[str, object]],
    sessions: list[dict[str, object]],
    message_rows: list[dict[str, object]],
    run_rows: list[dict[str, object]],
    session_id_map: dict[int, int],
) -> None:
    for row in targets:
        conn.execute(
            """
            INSERT INTO targets_new(
                id, name, note, workspace_path, color_index, auto_mining_state,
                consecutive_nonzero_exit_count, last_nonzero_exit_reason, intervention_required,
                intervention_reason, intervention_notice_read, created_at, updated_at
            )
            VALUES (
                :id, :name, :note, :workspace_path, :color_index, :auto_mining_state,
                :consecutive_nonzero_exit_count, :last_nonzero_exit_reason, :intervention_required,
                :intervention_reason, :intervention_notice_read, :created_at, :updated_at
            )
            """,
            row,
        )
    for row in sessions:
        conn.execute(
            """
            INSERT INTO sessions_new(
                id, target_id, name, session_type, prompt, bug_ids, codex_session_id, status, last_error, created_at,
                updated_at
            )
            VALUES (
                :id, :target_id, :name, :session_type, :prompt, :bug_ids, :codex_session_id, :status, :last_error,
                :created_at, :updated_at
            )
            """,
            row,
        )
    for row in message_rows:
        session_id = parse_int(row.get("session_id"))
        if session_id not in session_id_map:
            continue
        conn.execute(
            """
            INSERT INTO messages_new(id, session_id, role, content, kind, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                parse_int(row.get("id")),
                session_id_map[session_id],
                str(row.get("role") or "assistant"),
                str(row.get("content") or ""),
                str(row.get("kind") or "message"),
                str(row.get("created_at") or now_iso()),
            ),
        )
    for row in run_rows:
        session_id = parse_int(row.get("session_id"))
        if session_id not in session_id_map:
            continue
        status = normalize_run_status(row.get("status"))
        ended_at = optional_text(row.get("ended_at"))
        if status == "running":
            status = "interrupted"
            ended_at = now_iso()
        conn.execute(
            """
            INSERT INTO runs_new(
                id, session_id, source, prompt, model, status, returncode, started_at, ended_at,
                codex_session_id_before, codex_session_id_after, event_log_path, last_message, error
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                parse_int(row.get("id")),
                session_id_map[session_id],
                str(row.get("source") or "user"),
                str(row.get("prompt") or ""),
                str(row.get("model") or CONFIG.main_model),
                status,
                parse_int(row.get("returncode")),
                str(row.get("started_at") or now_iso()),
                ended_at,
                optional_text(row.get("codex_session_id_before")),
                optional_text(row.get("codex_session_id_after")),
                optional_text(row.get("event_log_path")),
                optional_text(row.get("last_message")),
                optional_text(row.get("error")),
            ),
        )


def parse_int(value: object) -> int | None:
    try:
        return int(str(value)) if value is not None else None
    except ValueError:
        return None


def truthy(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int | float):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return False


def normalize_auto_mining_state(value: object) -> str:
    return "frozen" if str(value or "").strip().lower() == "frozen" else "running"


def normalize_session_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status in {"running", "pause", "interrupted", "error", "finished"}:
        return status
    if status in {"failed"}:
        return "error"
    if status in {"running"}:
        return "running"
    return "finished"


def normalize_run_status(value: object) -> str:
    status = str(value or "").strip().lower()
    if status in {"running", "pause", "interrupted", "error", "finished"}:
        return status
    if status == "completed":
        return "finished"
    if status == "failed":
        return "error"
    return "error"


def optional_text(value: object) -> str | None:
    return None if value is None else str(value)


def normalize_bug_ids(value: object) -> str:
    if value is None:
        return ""
    ids: set[int] = set()
    for item in str(value).split(","):
        stripped = item.strip()
        if not stripped:
            continue
        try:
            bug_id = int(stripped)
        except ValueError:
            continue
        if bug_id >= 0:
            ids.add(bug_id)
    return ",".join(str(bug_id) for bug_id in sorted(ids))


def truncate_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def nonzero_exit_reason(returncode: int, error: str | None, last_error: str | None, last_message: str) -> str:
    fragments = [item.strip() for item in (error, last_error, last_message) if item and item.strip()]
    if not fragments:
        return f"Codex 返回非零状态 {returncode}"
    return f"Codex 返回非零状态 {returncode}: {truncate_text(fragments[0], 1000)}"


def set_default_setting(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT OR IGNORE INTO settings(key, value, updated_at) VALUES (?, ?, ?)",
        (key, value, now_iso()),
    )


def get_settings(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    return {str(row["key"]): str(row["value"]) for row in rows}


def set_setting(key: str, value: str) -> None:
    with connect_db() as conn:
        conn.execute(
            """
            INSERT INTO settings(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, value, now_iso()),
        )


def row_to_dict(row: sqlite3.Row) -> RowDict:
    result: RowDict = {}
    for key, value in dict(row).items():
        result[key] = value if value is None or isinstance(value, (str, int, float)) else str(value)
    return result


def next_color_index(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT COALESCE(MAX(color_index), -1) + 1 AS next_index FROM targets").fetchone()
    return int(row["next_index"]) % len(TARGET_COLORS) if row else 0


def get_target(target_id: int) -> RowDict | None:
    with connect_db() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
    return row_to_dict(row) if row else None


def get_existing_target(target_id: int) -> RowDict:
    target = get_target(target_id)
    if not target:
        raise KeyError("目标不存在")
    return target


def get_session(session_id: int) -> RowDict | None:
    with connect_db() as conn:
        row = conn.execute(
            """
            SELECT s.*, t.name AS target_name, t.note AS target_note,
                   t.workspace_path AS target_workspace_path, t.color_index AS target_color_index
            FROM sessions s
            JOIN targets t ON t.id = s.target_id
            WHERE s.id = ?
            """,
            (session_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


def get_existing_session(session_id: int) -> RowDict:
    session = get_session(session_id)
    if not session:
        raise KeyError("会话不存在")
    return session


def list_state_tree() -> list[RowDict]:
    with connect_db() as conn:
        targets = [
            row_to_dict(row)
            for row in conn.execute(
                """
                SELECT id, name, note, workspace_path, color_index, auto_mining_state,
                       consecutive_nonzero_exit_count, last_nonzero_exit_reason, intervention_required,
                       intervention_reason, intervention_notice_read, created_at, updated_at
                FROM targets
                ORDER BY datetime(updated_at) DESC, id DESC
                """,
            ).fetchall()
        ]
        sessions = [
            row_to_dict(row)
            for row in conn.execute(
                """
                SELECT id, target_id, name, session_type, prompt, bug_ids, codex_session_id, status,
                       last_error, created_at, updated_at
                FROM sessions
                ORDER BY target_id ASC, id ASC
                """,
            ).fetchall()
        ]
    by_target: dict[int, list[RowDict]] = {}
    for session in sessions:
        by_target.setdefault(row_int(session, "target_id"), []).append(session)
    for target in targets:
        target["sessions"] = cast(list[JsonValue], by_target.get(row_int(target, "id"), []))
        target["color"] = TARGET_COLORS[row_int(target, "color_index") % len(TARGET_COLORS)]
    return targets


def create_target_with_default_session(name: str, note: str, workspace_path: Path) -> tuple[RowDict, RowDict]:
    validated_name = validate_target_name(name)
    created_at = now_iso()
    with connect_db() as conn:
        if conn.execute("SELECT 1 FROM targets WHERE name = ?", (validated_name,)).fetchone():
            raise ValueError("目标名已存在")
        if conn.execute("SELECT 1 FROM targets WHERE workspace_path = ?", (str(workspace_path),)).fetchone():
            raise ValueError("目标工作区目录已被其他目标使用")
        color_index = next_color_index(conn)
        cur = conn.execute(
            """
            INSERT INTO targets(name, note, workspace_path, color_index, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (validated_name, note.strip(), str(workspace_path), color_index, created_at, created_at),
        )
        target_id = int(cur.lastrowid or 0)
        if not target_id:
            raise RuntimeError("目标创建后没有返回 id")
        prompt = "开始自动漏洞挖掘任务"
        session_cur = conn.execute(
            """
            INSERT INTO sessions(target_id, name, session_type, prompt, created_at, updated_at)
            VALUES (?, ?, 'mining', ?, ?, ?)
            """,
            (target_id, f"{validated_name} mining", prompt, created_at, created_at),
        )
        session_id = int(session_cur.lastrowid or 0)
        if not session_id:
            raise RuntimeError("默认 mining session 创建后没有返回 id")
        set_selected(conn, target_id, session_id, created_at)
    return get_existing_target(target_id), get_existing_session(session_id)


def create_mining_session(target_id: int, prompt: str, *, name: str | None = None) -> RowDict:
    target = get_existing_target(target_id)
    created_at = now_iso()
    session_name = name or f"{row_str(target, 'name')} mining"
    with connect_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO sessions(target_id, name, session_type, prompt, created_at, updated_at)
            VALUES (?, ?, 'mining', ?, ?, ?)
            """,
            (target_id, session_name, prompt, created_at, created_at),
        )
        session_id = int(cur.lastrowid or 0)
        if not session_id:
            raise RuntimeError("mining session 创建后没有返回 id")
    return get_existing_session(session_id)


def create_debug_session(target_id: int, payload: JsonObject) -> RowDict:
    target = get_existing_target(target_id)
    prompt = str(payload.get("prompt", "")).strip()
    name = str(payload.get("name", "")).strip() or "debug"
    created_at = now_iso()
    with connect_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO sessions(target_id, name, session_type, prompt, created_at, updated_at)
            VALUES (?, ?, 'debug', ?, ?, ?)
            """,
            (target_id, name, prompt, created_at, created_at),
        )
        session_id = int(cur.lastrowid or 0)
        if not session_id:
            raise RuntimeError("debug session 创建后没有返回 id")
        set_selected(conn, row_int(target, "id"), session_id, created_at)
    return get_existing_session(session_id)


def set_selected(conn: sqlite3.Connection, target_id: int, session_id: int, timestamp: str) -> None:
    for key, value in (("selected_target_id", target_id), ("selected_session_id", session_id)):
        conn.execute(
            """
            INSERT INTO settings(key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            (key, str(value), timestamp),
        )


def update_target_note(target_id: int, note: str) -> RowDict:
    get_existing_target(target_id)
    with connect_db() as conn:
        conn.execute(
            "UPDATE targets SET note = ?, updated_at = ? WHERE id = ?",
            (note.strip(), now_iso(), target_id),
        )
    return get_existing_target(target_id)


def update_target_auto_mining_state(target_id: int, state: str) -> RowDict:
    target = get_existing_target(target_id)
    normalized = normalize_auto_mining_state(state)
    with connect_db() as conn:
        timestamp = now_iso()
        if normalized == "running" and row_str(target, "auto_mining_state") == "frozen":
            conn.execute(
                """
                UPDATE targets
                SET auto_mining_state = ?, consecutive_nonzero_exit_count = 0,
                    last_nonzero_exit_reason = '', updated_at = ?
                WHERE id = ?
                """,
                (normalized, timestamp, target_id),
            )
        else:
            conn.execute(
                "UPDATE targets SET auto_mining_state = ?, updated_at = ? WHERE id = ?",
                (normalized, timestamp, target_id),
            )
    return get_existing_target(target_id)


def mark_intervention_detected(target_id: int, reason: str) -> RowDict:
    target = get_existing_target(target_id)
    previous_required = row_int(target, "intervention_required")
    previous_reason = row_str(target, "intervention_reason")
    notice_read = row_int(target, "intervention_notice_read", 1)
    if not previous_required or reason != previous_reason:
        notice_read = 0
    timestamp = now_iso()
    with connect_db() as conn:
        conn.execute(
            """
            UPDATE targets
            SET auto_mining_state = 'frozen', intervention_required = 1, intervention_reason = ?,
                intervention_notice_read = ?, updated_at = ?
            WHERE id = ?
            """,
            (reason, notice_read, timestamp, target_id),
        )
    return get_existing_target(target_id)


def mark_intervention_notice_read(target_id: int) -> RowDict:
    get_existing_target(target_id)
    with connect_db() as conn:
        conn.execute(
            "UPDATE targets SET intervention_notice_read = 1, updated_at = ? WHERE id = ?",
            (now_iso(), target_id),
        )
    return get_existing_target(target_id)


def mark_target_mining_sessions_error(target_id: int, reason: str) -> None:
    get_existing_target(target_id)
    with connect_db() as conn:
        conn.execute(
            """
            UPDATE sessions
            SET status = 'error', last_error = ?, updated_at = ?
            WHERE target_id = ? AND session_type = 'mining'
            """,
            (reason, now_iso(), target_id),
        )


def delete_target(target_id: int) -> None:
    target = get_existing_target(target_id)
    workspace = Path(row_str(target, "workspace_path"))
    with connect_db() as conn:
        placeholders = ",".join("?" for _ in BUSY_STATUSES)
        busy = conn.execute(
            f"SELECT 1 FROM sessions WHERE target_id = ? AND status IN ({placeholders}) LIMIT 1",
            (target_id, *BUSY_STATUSES),
        ).fetchone()
        if busy:
            raise ValueError("目标下仍有 running session，请先停止")
        session_rows = conn.execute("SELECT id FROM sessions WHERE target_id = ?", (target_id,)).fetchall()
        selected_session_ids = {str(row["id"]) for row in session_rows}
        delete_target_workspace(workspace)
        conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        settings = get_settings(conn)
        timestamp = now_iso()
        if settings.get("selected_target_id") == str(target_id):
            set_setting_on_connection(conn, "selected_target_id", "", timestamp)
        if settings.get("selected_session_id") in selected_session_ids:
            set_setting_on_connection(conn, "selected_session_id", "", timestamp)


def delete_session(session_id: int) -> None:
    session = get_existing_session(session_id)
    if row_str(session, "status") in BUSY_STATUSES:
        raise ValueError("running session 不能删除，请先停止")
    with connect_db() as conn:
        settings = get_settings(conn)
        conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
        if settings.get("selected_session_id") == str(session_id):
            set_setting_on_connection(conn, "selected_session_id", "", now_iso())


def set_setting_on_connection(conn: sqlite3.Connection, key: str, value: str, timestamp: str) -> None:
    conn.execute(
        """
        INSERT INTO settings(key, value, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """,
        (key, value, timestamp),
    )


def add_message(session_id: int, role: str, content: str, kind: str = "message") -> None:
    content = content.strip()
    if not content:
        return
    timestamp = now_iso()
    with connect_db() as conn:
        conn.execute(
            "INSERT INTO messages(session_id, role, content, kind, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, role, content, kind, timestamp),
        )
        conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (timestamp, session_id))


def upsert_assistant_message(
    session_id: int,
    message_id: int | None,
    content: str,
    *,
    touch_created_at: bool = False,
) -> int | None:
    content = content.strip()
    if not content:
        return message_id
    timestamp = now_iso()
    with connect_db() as conn:
        if message_id is not None:
            row = conn.execute(
                "SELECT 1 FROM messages WHERE id = ? AND session_id = ? AND role = 'assistant'",
                (message_id, session_id),
            ).fetchone()
            if row:
                if touch_created_at:
                    conn.execute(
                        "UPDATE messages SET content = ?, created_at = ? WHERE id = ?",
                        (content, timestamp, message_id),
                    )
                else:
                    conn.execute(
                        "UPDATE messages SET content = ? WHERE id = ?",
                        (content, message_id),
                    )
                conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (timestamp, session_id))
                return message_id
        cur = conn.execute(
            "INSERT INTO messages(session_id, role, content, kind, created_at) VALUES (?, 'assistant', ?, 'message', ?)",
            (session_id, content, timestamp),
        )
        conn.execute("UPDATE sessions SET updated_at = ? WHERE id = ?", (timestamp, session_id))
        inserted_id = int(cur.lastrowid or 0)
    return inserted_id or None


def list_messages(session_id: int, after_id: int = 0, limit: int = 300) -> list[RowDict]:
    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT id, session_id, role, content, kind, created_at
            FROM messages
            WHERE session_id = ? AND id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (session_id, after_id, limit),
        ).fetchall()
    return [row_to_dict(row) for row in rows]


def target_has_occupied_mining_session(target_id: int) -> bool:
    with connect_db() as conn:
        row = conn.execute(
            """
            SELECT 1
            FROM sessions
            WHERE target_id = ? AND session_type = 'mining' AND status IN ('running', 'pause')
            LIMIT 1
            """,
            (target_id,),
        ).fetchone()
    return row is not None


def target_has_running_mining_session(target_id: int) -> bool:
    return target_has_occupied_mining_session(target_id)


def find_recoverable_mining_session(target_id: int) -> RowDict | None:
    with connect_db() as conn:
        row = conn.execute(
            """
            SELECT s.*
            FROM sessions s
            WHERE s.target_id = ?
              AND s.session_type = 'mining'
              AND s.status = 'interrupted'
              AND s.codex_session_id IS NOT NULL
            ORDER BY datetime(s.updated_at) ASC, s.id ASC
            LIMIT 1
            """,
            (target_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


def find_pending_mining_session(target_id: int) -> RowDict | None:
    with connect_db() as conn:
        row = conn.execute(
            """
            SELECT s.*
            FROM sessions s
            WHERE s.target_id = ?
              AND s.session_type = 'mining'
              AND s.status = 'finished'
              AND s.codex_session_id IS NULL
              AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.session_id = s.id)
            ORDER BY s.id ASC
            LIMIT 1
            """,
            (target_id,),
        ).fetchone()
    return row_to_dict(row) if row else None


def running_auto_mining_session_ids(target_id: int) -> list[int]:
    with connect_db() as conn:
        rows = conn.execute(
            """
            SELECT DISTINCT s.id
            FROM sessions s
            JOIN runs r ON r.session_id = s.id AND r.status = 'running'
            WHERE s.target_id = ?
              AND s.session_type = 'mining'
              AND s.status = 'running'
              AND r.source IN ('scheduler', 'system')
            ORDER BY s.id ASC
            """,
            (target_id,),
        ).fetchall()
    return [int(row["id"]) for row in rows]


def create_run(
    *,
    session_id: int,
    source: str,
    prompt: str,
    model: str,
    started_at: str,
    codex_session_id_before: str | None,
) -> int:
    with connect_db() as conn:
        cur = conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, started_at, codex_session_id_before)
            VALUES (?, ?, ?, ?, 'running', ?, ?)
            """,
            (session_id, source, prompt, model, started_at, codex_session_id_before),
        )
        conn.execute(
            "UPDATE sessions SET status = 'running', last_error = NULL, updated_at = ? WHERE id = ?",
            (started_at, session_id),
        )
        run_id = int(cur.lastrowid or 0)
        if not run_id:
            raise RuntimeError("运行记录创建后没有返回 id")
        return run_id


def set_run_event_log_path(run_id: int, event_log_path: Path) -> None:
    with connect_db() as conn:
        conn.execute("UPDATE runs SET event_log_path = ? WHERE id = ?", (str(event_log_path), run_id))


def append_session_bug_ids(session_id: int, bug_ids: set[int]) -> None:
    normalized_new = {bug_id for bug_id in bug_ids if bug_id >= 0}
    if not normalized_new:
        return
    timestamp = now_iso()
    with connect_db() as conn:
        row = conn.execute("SELECT bug_ids FROM sessions WHERE id = ?", (session_id,)).fetchone()
        if not row:
            return
        existing = normalize_bug_ids(row["bug_ids"])
        merged = {int(item) for item in existing.split(",") if item}
        merged.update(normalized_new)
        conn.execute(
            "UPDATE sessions SET bug_ids = ?, updated_at = ? WHERE id = ?",
            (",".join(str(bug_id) for bug_id in sorted(merged)), timestamp, session_id),
        )


def update_run_result(
    *,
    session_id: int,
    run_id: int,
    status: str,
    returncode: int,
    ended_at: str,
    codex_session_id_after: str | None,
    last_message: str,
    error: str | None,
    last_error: str | None,
    session_status: str | None = None,
) -> None:
    with connect_db() as conn:
        target_row = conn.execute("SELECT target_id FROM sessions WHERE id = ?", (session_id,)).fetchone()
        target_id = int(target_row["target_id"]) if target_row else None
        normalized_status = normalize_run_status(status)
        next_session_status = session_status or normalized_status
        if codex_session_id_after:
            conn.execute(
                "UPDATE sessions SET codex_session_id = ? WHERE id = ?",
                (codex_session_id_after, session_id),
            )
        conn.execute(
            """
            UPDATE runs
            SET status = ?, returncode = ?, ended_at = ?, codex_session_id_after = ?,
                last_message = ?, error = ?
            WHERE id = ?
            """,
            (normalized_status, returncode, ended_at, codex_session_id_after, last_message, error, run_id),
        )
        conn.execute(
            "UPDATE sessions SET status = ?, last_error = ?, updated_at = ? WHERE id = ?",
            (next_session_status, last_error, ended_at, session_id),
        )
        if target_id is not None:
            update_target_exit_streak(
                conn,
                target_id=target_id,
                status=normalized_status,
                returncode=returncode,
                ended_at=ended_at,
                reason=nonzero_exit_reason(returncode, error, last_error, last_message),
            )


def update_target_exit_streak(
    conn: sqlite3.Connection,
    *,
    target_id: int,
    status: str,
    returncode: int,
    ended_at: str,
    reason: str,
) -> None:
    if status == "error" and returncode > 0:
        row = conn.execute(
            "SELECT consecutive_nonzero_exit_count FROM targets WHERE id = ?",
            (target_id,),
        ).fetchone()
        next_count = (int(row["consecutive_nonzero_exit_count"]) if row else 0) + 1
        if next_count >= 3:
            conn.execute(
                """
                UPDATE targets
                SET consecutive_nonzero_exit_count = ?, last_nonzero_exit_reason = ?,
                    auto_mining_state = 'frozen', updated_at = ?
                WHERE id = ?
                """,
                (next_count, reason, ended_at, target_id),
            )
        else:
            conn.execute(
                """
                UPDATE targets
                SET consecutive_nonzero_exit_count = ?, last_nonzero_exit_reason = ?, updated_at = ?
                WHERE id = ?
                """,
                (next_count, reason, ended_at, target_id),
            )
    elif status == "finished" and returncode == 0:
        conn.execute(
            """
            UPDATE targets
            SET consecutive_nonzero_exit_count = 0, last_nonzero_exit_reason = '', updated_at = ?
            WHERE id = ?
            """,
            (ended_at, target_id),
        )
