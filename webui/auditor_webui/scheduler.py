"""Native WebUI automatic mining scheduler."""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path
from typing import cast

from .codex_runner import start_agent_run, truncate
from .database import (
    create_mining_session,
    find_pending_mining_session,
    find_recoverable_mining_session,
    list_state_tree,
    target_has_occupied_mining_session,
)
from .schema import JsonValue, RowDict, row_int, row_str

NEW_MINING_PROMPT = "开始自动漏洞挖掘任务"
RESUME_MINING_PROMPT = "请从上次中断处恢复该目标的自动漏洞挖掘任务，继续推进最有价值的审计路径。"

_SCHEDULER_THREAD: threading.Thread | None = None
_SCHEDULER_LOCK = threading.Lock()


def intervention_path(target: RowDict) -> Path:
    return Path(row_str(target, "workspace_path")) / "human_intervention.json"


def read_intervention_reason(path: Path) -> str:
    text = path.read_text(encoding="utf-8", errors="ignore").strip()
    if not text:
        return "未提供原因"
    try:
        payload = cast(JsonValue, json.loads(text))
    except json.JSONDecodeError:
        return truncate(text, 1000)
    if isinstance(payload, dict):
        reason = payload.get("reason")
        if isinstance(reason, str) and reason.strip():
            return truncate(reason.strip(), 1000)
    return truncate(text, 1000)


def scheduler_tick() -> list[int]:
    started_sessions: list[int] = []
    for target in list_state_tree():
        target_id = row_int(target, "id")
        if row_str(target, "auto_mining_state", "running") != "running":
            continue
        if target_has_occupied_mining_session(target_id):
            continue

        session = find_recoverable_mining_session(target_id)
        prompt = RESUME_MINING_PROMPT if session else NEW_MINING_PROMPT
        if session is None:
            session = find_pending_mining_session(target_id)
        if session is None:
            session = create_mining_session(target_id, prompt)

        session_id = row_int(session, "id")
        if start_agent_run(session_id, prompt, source="scheduler"):
            started_sessions.append(session_id)
    return started_sessions


def scheduler_loop(interval: float) -> None:
    while True:
        try:
            scheduler_tick()
        except Exception:
            # Keep the WebUI alive; individual failures remain visible through session/run state.
            pass
        time.sleep(interval)


def start_scheduler() -> None:
    global _SCHEDULER_THREAD
    interval = float(os.environ.get("AUDITOR_SCHEDULER_INTERVAL", "5"))
    with _SCHEDULER_LOCK:
        if _SCHEDULER_THREAD and _SCHEDULER_THREAD.is_alive():
            return
        _SCHEDULER_THREAD = threading.Thread(target=scheduler_loop, args=(interval,), daemon=True)
        _SCHEDULER_THREAD.start()
