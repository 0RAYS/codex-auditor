from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest


WEBUI_ROOT = Path(__file__).resolve().parents[1]
VENV_SITE_PACKAGES = WEBUI_ROOT / ".venv" / "lib" / "python3.14" / "site-packages"
if VENV_SITE_PACKAGES.exists():
    sys.path.insert(0, str(VENV_SITE_PACKAGES))


@pytest.fixture()
def app_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AUDITOR_DATA_ROOT", str(tmp_path / "data"))
    monkeypatch.setenv("AUDITOR_WORKSPACE", str(tmp_path / "workspace"))
    monkeypatch.setenv("AUDITOR_AUDIT_DIR", str(tmp_path / "workspace" / "audit"))
    monkeypatch.setenv("AUDITOR_TEMP_DIR", str(tmp_path / "workspace" / "temp"))
    monkeypatch.setenv("AUDITOR_WEBUI_DB", str(tmp_path / "workspace" / "audit" / "webui.sqlite3"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    monkeypatch.syspath_prepend(str(WEBUI_ROOT))
    for name in list(sys.modules):
        if name == "auditor_webui" or name.startswith("auditor_webui."):
            del sys.modules[name]
    db = importlib.import_module("auditor_webui.database")
    workspace = importlib.import_module("auditor_webui.workspace")
    scheduler = importlib.import_module("auditor_webui.scheduler")
    web = importlib.import_module("auditor_webui.web")
    runner = importlib.import_module("auditor_webui.codex_runner")
    vulnerabilities = importlib.import_module("auditor_webui.vulnerabilities")
    db.init_db()
    return {
        "db": db,
        "workspace": workspace,
        "scheduler": scheduler,
        "web": web,
        "runner": runner,
        "vulnerabilities": vulnerabilities,
    }


def create_target(mods: dict[str, object], name: str = "target1"):
    db = mods["db"]
    workspace = mods["workspace"]
    workspace_path = workspace.prepare_target_workspace(name, "")
    return db.create_target_with_default_session(name, "", workspace_path)


def insert_run(db, session_id: int, status: str, *, source: str = "scheduler") -> None:
    timestamp = db.now_iso()
    with db.connect_db() as conn:
        conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, returncode, started_at, ended_at)
            VALUES (?, ?, 'prompt', 'model', ?, 0, ?, ?)
            """,
            (session_id, source, status, timestamp, timestamp if status != "running" else None),
        )


class NoopThread:
    def __init__(self, *, target, args, daemon: bool = False):
        self.target = target
        self.args = args
        self.daemon = daemon

    def start(self) -> None:
        return None


def finish_run(
    db,
    session_id: int,
    status: str,
    *,
    returncode: int,
    source: str = "scheduler",
    error: str | None = None,
    last_message: str = "",
) -> None:
    started_at = db.now_iso()
    run_id = db.create_run(
        session_id=session_id,
        source=source,
        prompt="prompt",
        model="model",
        started_at=started_at,
        codex_session_id_before=None,
    )
    if status == "finished":
        last_error = None
    elif status in {"interrupted", "pause"}:
        last_error = error
    else:
        last_error = error or f"Codex 返回状态 {returncode}"
    db.update_run_result(
        session_id=session_id,
        run_id=run_id,
        status=status,
        returncode=returncode,
        ended_at=db.now_iso(),
        codex_session_id_after=None,
        last_message=last_message,
        error=error,
        last_error=last_error,
    )


def test_target_defaults_running_and_api_starts_default_mining(app_modules, monkeypatch: pytest.MonkeyPatch):
    web = app_modules["web"]
    started: list[int] = []
    stopped: list[int] = []
    monkeypatch.setattr(web, "start_agent_run", lambda session_id, prompt, *, source: started.append(session_id) or True)
    monkeypatch.setattr(web, "stop_agent_run", lambda session_id: stopped.append(session_id) or True)

    app = web.create_app()
    client = app.test_client()
    response = client.post("/api/targets", json={"name": "openssl", "note": ""})
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["target"]["auto_mining_state"] == "running"
    assert payload["target"]["consecutive_nonzero_exit_count"] == 0
    assert payload["target"]["last_nonzero_exit_reason"] == ""
    assert started == [payload["session"]["id"]]
    assert stopped == []

    target_id = payload["target"]["id"]
    response = client.patch(f"/api/targets/{target_id}/scheduler-state", json={"state": "frozen"})
    assert response.status_code == 200
    assert response.get_json()["target"]["auto_mining_state"] == "frozen"
    response = client.patch(f"/api/targets/{target_id}/scheduler-state", json={"state": "running"})
    assert response.status_code == 200
    assert response.get_json()["target"]["auto_mining_state"] == "running"
    assert response.get_json()["target"]["consecutive_nonzero_exit_count"] == 0
    assert response.get_json()["target"]["last_nonzero_exit_reason"] == ""
    assert started == [payload["session"]["id"]]
    assert stopped == []


def test_init_db_marks_dirty_running_sessions_and_runs_interrupted(app_modules):
    db = app_modules["db"]
    _, session = create_target(app_modules)
    session_id = int(session["id"])
    timestamp = db.now_iso()
    with db.connect_db() as conn:
        conn.execute("UPDATE sessions SET status = 'running' WHERE id = ?", (session_id,))
        conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, started_at)
            VALUES (?, 'scheduler', 'p', 'm', 'running', ?)
            """,
            (session_id, timestamp),
        )

    db.init_db()

    assert db.get_existing_session(session_id)["status"] == "interrupted"
    with db.connect_db() as conn:
        run = conn.execute("SELECT status, ended_at FROM runs WHERE session_id = ?", (session_id,)).fetchone()
    assert run["status"] == "interrupted"
    assert run["ended_at"]


def test_three_consecutive_nonzero_exits_freeze_target(app_modules):
    db = app_modules["db"]
    target, session = create_target(app_modules)
    target_id = int(target["id"])
    session_id = int(session["id"])

    finish_run(db, session_id, "error", returncode=2, error="first failure")
    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "running"
    assert updated["consecutive_nonzero_exit_count"] == 1
    assert "2" in updated["last_nonzero_exit_reason"]

    finish_run(db, session_id, "error", returncode=3, error="second failure")
    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "running"
    assert updated["consecutive_nonzero_exit_count"] == 2

    finish_run(db, session_id, "error", returncode=4, error="third failure")
    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "frozen"
    assert updated["consecutive_nonzero_exit_count"] == 3
    assert "4" in updated["last_nonzero_exit_reason"]
    assert "third failure" in updated["last_nonzero_exit_reason"]
    assert updated["intervention_required"] == 0


def test_successful_run_clears_nonzero_exit_streak(app_modules):
    db = app_modules["db"]
    target, session = create_target(app_modules)
    target_id = int(target["id"])
    session_id = int(session["id"])

    finish_run(db, session_id, "error", returncode=2)
    assert db.get_existing_session(session_id)["status"] == "error"
    finish_run(db, session_id, "error", returncode=3)
    assert db.get_existing_target(target_id)["consecutive_nonzero_exit_count"] == 2

    finish_run(db, session_id, "finished", returncode=0)
    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "running"
    assert updated["consecutive_nonzero_exit_count"] == 0
    assert updated["last_nonzero_exit_reason"] == ""
    assert db.get_existing_session(session_id)["status"] == "finished"


def test_interrupted_run_does_not_change_nonzero_exit_streak(app_modules):
    db = app_modules["db"]
    target, session = create_target(app_modules)
    target_id = int(target["id"])
    session_id = int(session["id"])

    finish_run(db, session_id, "error", returncode=2, error="kept")
    finish_run(db, session_id, "interrupted", returncode=143, error="manual stop")

    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "running"
    assert updated["consecutive_nonzero_exit_count"] == 1
    assert "kept" in updated["last_nonzero_exit_reason"]
    assert db.get_existing_session(session_id)["status"] == "interrupted"


def test_user_stop_writes_pause_without_changing_nonzero_exit_streak(app_modules, tmp_path: Path):
    db = app_modules["db"]
    runner = app_modules["runner"]
    target, session = create_target(app_modules)
    target_id = int(target["id"])
    session_id = int(session["id"])

    finish_run(db, session_id, "error", returncode=2, error="kept")
    run_id = db.create_run(
        session_id=session_id,
        source="user",
        prompt="prompt",
        model="model",
        started_at=db.now_iso(),
        codex_session_id_before=None,
    )
    output_file = tmp_path / "last.txt"
    log_file = tmp_path / "events.jsonl"
    runner.finalize_agent_run(
        session_id=session_id,
        run_id=run_id,
        output_file=output_file,
        assistant_messages=[],
        assistant_message_id=None,
        discovered_session_id=None,
        start_time=0,
        log_file=log_file,
        returncode=-15,
        error=None,
        stop_requested=True,
    )

    updated = db.get_existing_target(target_id)
    assert updated["consecutive_nonzero_exit_count"] == 1
    assert "kept" in updated["last_nonzero_exit_reason"]
    assert db.get_existing_session(session_id)["status"] == "pause"
    with db.connect_db() as conn:
        run = conn.execute("SELECT status FROM runs WHERE id = ?", (run_id,)).fetchone()
    assert run["status"] == "pause"


def test_debug_session_nonzero_exits_count_toward_freeze(app_modules):
    db = app_modules["db"]
    target, _ = create_target(app_modules)
    debug = db.create_debug_session(int(target["id"]), {"name": "dbg", "prompt": ""})
    debug_id = int(debug["id"])

    finish_run(db, debug_id, "error", returncode=9, source="user")
    finish_run(db, debug_id, "error", returncode=9, source="user")
    finish_run(db, debug_id, "error", returncode=9, source="user")

    updated = db.get_existing_target(int(target["id"]))
    assert updated["auto_mining_state"] == "frozen"
    assert updated["consecutive_nonzero_exit_count"] == 3


def test_auto_freeze_does_not_stop_running_sessions(app_modules):
    db = app_modules["db"]
    target, failed_session = create_target(app_modules)
    target_id = int(target["id"])
    failed_session_id = int(failed_session["id"])

    finish_run(db, failed_session_id, "error", returncode=2)
    finish_run(db, failed_session_id, "error", returncode=3)

    debug = db.create_debug_session(target_id, {"name": "dbg", "prompt": ""})
    debug_id = int(debug["id"])
    mining = db.create_mining_session(target_id, "keep running")
    mining_id = int(mining["id"])
    timestamp = db.now_iso()
    debug_run_id = db.create_run(
        session_id=debug_id,
        source="user",
        prompt="debug",
        model="model",
        started_at=timestamp,
        codex_session_id_before=None,
    )
    mining_run_id = db.create_run(
        session_id=mining_id,
        source="scheduler",
        prompt="mine",
        model="model",
        started_at=timestamp,
        codex_session_id_before=None,
    )

    finish_run(db, failed_session_id, "error", returncode=4)

    updated = db.get_existing_target(target_id)
    assert updated["auto_mining_state"] == "frozen"
    assert db.get_existing_session(debug_id)["status"] == "running"
    assert db.get_existing_session(mining_id)["status"] == "running"
    with db.connect_db() as conn:
        run_statuses = {
            int(row["id"]): row["status"]
            for row in conn.execute(
                "SELECT id, status FROM runs WHERE id IN (?, ?)",
                (debug_run_id, mining_run_id),
            ).fetchall()
        }
    assert run_statuses == {debug_run_id: "running", mining_run_id: "running"}


def test_webui_manual_restore_running_clears_nonzero_exit_streak(app_modules):
    db = app_modules["db"]
    web = app_modules["web"]
    target, session = create_target(app_modules)
    target_id = int(target["id"])
    session_id = int(session["id"])

    finish_run(db, session_id, "error", returncode=2)
    finish_run(db, session_id, "error", returncode=3)
    finish_run(db, session_id, "error", returncode=4, error="freeze me")
    assert db.get_existing_target(target_id)["auto_mining_state"] == "frozen"

    response = web.create_app().test_client().patch(
        f"/api/targets/{target_id}/scheduler-state",
        json={"state": "running"},
    )
    assert response.status_code == 200
    updated = response.get_json()["target"]
    assert updated["auto_mining_state"] == "running"
    assert updated["consecutive_nonzero_exit_count"] == 0
    assert updated["last_nonzero_exit_reason"] == ""


def test_scheduler_resumes_recoverable_mining_before_creating_new(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    scheduler = app_modules["scheduler"]
    _, session = create_target(app_modules)
    session_id = int(session["id"])
    with db.connect_db() as conn:
        conn.execute("UPDATE sessions SET codex_session_id = ? WHERE id = ?", ("00000000-0000-0000-0000-000000000001", session_id))
        conn.execute("UPDATE sessions SET status = 'interrupted' WHERE id = ?", (session_id,))
    insert_run(db, session_id, "interrupted")

    started: list[int] = []
    monkeypatch.setattr(scheduler, "start_agent_run", lambda sid, prompt, *, source: started.append(sid) or True)

    assert scheduler.scheduler_tick() == [session_id]
    assert started == [session_id]
    with db.connect_db() as conn:
        count = conn.execute("SELECT COUNT(*) AS c FROM sessions WHERE session_type = 'mining'").fetchone()["c"]
    assert count == 1


def test_paused_mining_session_occupies_target_and_scheduler_does_not_resume(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    scheduler = app_modules["scheduler"]
    target, session = create_target(app_modules)
    session_id = int(session["id"])
    with db.connect_db() as conn:
        conn.execute(
            "UPDATE sessions SET status = 'pause', codex_session_id = ? WHERE id = ?",
            ("00000000-0000-0000-0000-000000000002", session_id),
        )
        conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, returncode, started_at, ended_at)
            VALUES (?, 'scheduler', 'prompt', 'model', 'pause', -15, ?, ?)
            """,
            (session_id, db.now_iso(), db.now_iso()),
        )

    started: list[int] = []
    monkeypatch.setattr(scheduler, "start_agent_run", lambda sid, prompt, *, source: started.append(sid) or True)

    assert scheduler.scheduler_tick() == []
    assert started == []
    with db.connect_db() as conn:
        count = conn.execute(
            "SELECT COUNT(*) AS c FROM sessions WHERE target_id = ? AND session_type = 'mining'",
            (int(target["id"]),),
        ).fetchone()["c"]
    assert count == 1


def test_scheduler_start_rejects_paused_session_but_user_can_continue(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    runner = app_modules["runner"]
    _, session = create_target(app_modules)
    session_id = int(session["id"])
    with db.connect_db() as conn:
        conn.execute("UPDATE sessions SET status = 'pause' WHERE id = ?", (session_id,))

    assert not runner.start_agent_run(session_id, "resume", source="scheduler")
    monkeypatch.setattr(runner.threading, "Thread", NoopThread)
    assert runner.start_agent_run(session_id, "resume", source="user")
    assert db.get_existing_session(session_id)["status"] == "running"


def test_scheduler_creates_new_mining_after_recoverable_sessions_end(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    scheduler = app_modules["scheduler"]
    _, session = create_target(app_modules)
    insert_run(db, int(session["id"]), "finished")

    started: list[int] = []
    monkeypatch.setattr(scheduler, "start_agent_run", lambda sid, prompt, *, source: started.append(sid) or True)

    result = scheduler.scheduler_tick()
    assert result == started
    assert len(started) == 1
    assert started[0] != int(session["id"])


def test_frozen_target_does_not_start_new_mining(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    scheduler = app_modules["scheduler"]
    target, _ = create_target(app_modules)
    db.update_target_auto_mining_state(int(target["id"]), "frozen")

    started: list[int] = []
    monkeypatch.setattr(scheduler, "start_agent_run", lambda sid, prompt, *, source: started.append(sid) or True)

    assert scheduler.scheduler_tick() == []
    assert started == []


def test_scheduler_ignores_human_intervention_file_without_patch(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    scheduler = app_modules["scheduler"]
    target, _ = create_target(app_modules)
    Path(target["workspace_path"], "human_intervention.json").write_text(
        json.dumps({"reason": "need credentials"}),
        encoding="utf-8",
    )

    started: list[int] = []
    stopped: list[int] = []
    monkeypatch.setattr(scheduler, "start_agent_run", lambda sid, prompt, *, source: started.append(sid) or True)

    assert scheduler.scheduler_tick() == started
    updated = db.get_existing_target(int(target["id"]))
    assert updated["auto_mining_state"] == "running"
    assert updated["intervention_required"] == 0
    assert stopped == []


def test_patch_intervention_freezes_and_pauses_auto_mining_only(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    web = app_modules["web"]
    target, mining = create_target(app_modules)
    debug = db.create_debug_session(int(target["id"]), {"name": "dbg", "prompt": ""})
    timestamp = db.now_iso()
    with db.connect_db() as conn:
        conn.execute(
            """
            UPDATE targets
            SET consecutive_nonzero_exit_count = 2, last_nonzero_exit_reason = 'previous codex failure'
            WHERE id = ?
            """,
            (int(target["id"]),),
        )
        conn.execute("UPDATE sessions SET status = 'running' WHERE id IN (?, ?)", (int(mining["id"]), int(debug["id"])))
        conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, started_at)
            VALUES (?, 'scheduler', 'p', 'm', 'running', ?)
            """,
            (int(mining["id"]), timestamp),
        )
        conn.execute(
            """
            INSERT INTO runs(session_id, source, prompt, model, status, started_at)
            VALUES (?, 'user', 'p', 'm', 'running', ?)
            """,
            (int(debug["id"]), timestamp),
        )
    Path(target["workspace_path"], "human_intervention.json").write_text(
        json.dumps({"reason": "need credentials"}),
        encoding="utf-8",
    )

    stopped: list[int] = []
    monkeypatch.setattr(web, "stop_agent_run", lambda sid, *, mark_error=False: stopped.append((sid, mark_error)) or True)

    response = web.create_app().test_client().patch(f"/api/targets/{target['id']}/intervention")
    assert response.status_code == 200
    updated = db.get_existing_target(int(target["id"]))
    assert updated["auto_mining_state"] == "frozen"
    assert updated["intervention_required"] == 1
    assert updated["intervention_notice_read"] == 0
    assert updated["intervention_reason"] == "need credentials"
    assert updated["consecutive_nonzero_exit_count"] == 2
    assert updated["last_nonzero_exit_reason"] == "previous codex failure"
    assert stopped == [(int(mining["id"]), True)]
    assert db.get_existing_session(int(mining["id"]))["status"] == "error"
    assert db.get_existing_session(int(debug["id"]))["status"] == "running"


def test_patch_intervention_uses_default_reason_without_file(app_modules):
    db = app_modules["db"]
    web = app_modules["web"]
    target, mining = create_target(app_modules)

    response = web.create_app().test_client().patch(f"/api/targets/{target['id']}/intervention")
    assert response.status_code == 200
    updated = db.get_existing_target(int(target["id"]))
    assert updated["intervention_reason"] == "未提供原因"
    assert db.get_existing_session(int(mining["id"]))["status"] == "error"


def test_intervention_ack_marks_notice_read_once(app_modules):
    db = app_modules["db"]
    web = app_modules["web"]
    target, _ = create_target(app_modules)
    db.mark_intervention_detected(int(target["id"]), "manual check")

    client = web.create_app().test_client()
    response = client.post(f"/api/targets/{target['id']}/intervention/ack")
    assert response.status_code == 200
    assert response.get_json()["target"]["intervention_notice_read"] == 1


def test_prompt_rendering_rules(app_modules):
    db = app_modules["db"]
    target, session = create_target(app_modules)
    db.update_target_note(int(target["id"]), "重点关注 parser 边界")
    prompts = importlib.import_module("auditor_webui.prompts")
    session_row = db.get_existing_session(int(session["id"]))

    scheduler_prompt = prompts.base_prompt(session_row, "开始自动漏洞挖掘任务", source="scheduler")
    assert f"目标 ID: {target['id']}" in scheduler_prompt
    assert "目标补充说明:" in scheduler_prompt
    assert "重点关注 parser 边界" in scheduler_prompt
    assert "如果以下任务未完成" in scheduler_prompt
    assert "## 目录结构与协议" in scheduler_prompt
    assert "$AUDITOR_TARGET_ID/intervention" in scheduler_prompt

    user = prompts.base_prompt(session_row, "用户原文", source="user")
    assert user == "用户原文"
    assert "重点关注 parser 边界" not in user

    for rendered in (scheduler_prompt, user):
        assert "Session 类型" not in rendered
        assert "init.md" not in rendered
        assert "127.0.0.1" not in rendered
        assert "AUDITOR_WEBUI_PORT" not in rendered


def test_prompt_env_exports_target_id(app_modules):
    runner = app_modules["runner"]
    target, _ = create_target(app_modules)

    assert runner.codex_env(int(target["id"]))["AUDITOR_TARGET_ID"] == str(target["id"])


def test_start_agent_run_stores_rendered_scheduler_prompt(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    runner = app_modules["runner"]
    scheduler = app_modules["scheduler"]
    target, session = create_target(app_modules)
    db.update_target_note(int(target["id"]), "补充说明来自 DB")
    monkeypatch.setattr(runner.threading, "Thread", NoopThread)

    assert scheduler.scheduler_tick() == [int(session["id"])]
    messages = db.list_messages(int(session["id"]))
    assert len(messages) == 1
    stored_prompt = messages[0]["content"]
    assert stored_prompt != scheduler.NEW_MINING_PROMPT
    assert "你正在执行 codex-auditor 自动化二进制安全审计会话" in stored_prompt
    assert "如果以下任务未完成" in stored_prompt
    assert "补充说明来自 DB" in stored_prompt

    with db.connect_db() as conn:
        run = conn.execute(
            "SELECT prompt, source FROM runs WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (int(session["id"]),),
        ).fetchone()
    assert run["source"] == "scheduler"
    assert run["prompt"] == stored_prompt


def test_start_agent_run_stores_manual_user_prompt_only(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    runner = app_modules["runner"]
    target, _ = create_target(app_modules)
    debug = db.create_debug_session(int(target["id"]), {"name": "dbg", "prompt": ""})
    monkeypatch.setattr(runner.threading, "Thread", NoopThread)

    content = "只检查 crash 日志"
    assert runner.start_agent_run(int(debug["id"]), content, source="user")
    messages = db.list_messages(int(debug["id"]))
    assert [message["content"] for message in messages] == [content]
    with db.connect_db() as conn:
        run_prompt = conn.execute(
            "SELECT prompt FROM runs WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (int(debug["id"]),),
        ).fetchone()["prompt"]
    assert run_prompt == content
    assert "你正在执行 codex-auditor" not in run_prompt
    assert "目标补充说明" not in run_prompt


def test_subsequent_scheduler_prompt_keeps_checklist(app_modules, monkeypatch: pytest.MonkeyPatch):
    db = app_modules["db"]
    runner = app_modules["runner"]
    scheduler = app_modules["scheduler"]
    target, session = create_target(app_modules)
    insert_run(db, int(session["id"]), "finished")
    monkeypatch.setattr(runner.threading, "Thread", NoopThread)

    assert runner.start_agent_run(int(session["id"]), scheduler.NEW_MINING_PROMPT, source="scheduler")
    messages = db.list_messages(int(session["id"]))
    assert len(messages) == 1
    assert "## 目录结构与协议" in messages[0]["content"]
    assert "如果以下任务未完成" in messages[0]["content"]


def test_workspace_no_longer_creates_or_updates_init_md(app_modules):
    web = app_modules["web"]
    client = web.create_app().test_client()

    response = client.post("/api/targets", json={"name": "noinit", "note": "初始说明"})
    assert response.status_code == 201
    payload = response.get_json()
    target = payload["target"]
    init_path = Path(target["workspace_path"], "init.md")
    assert not init_path.exists()
    assert not (WEBUI_ROOT / "templates" / "init.md").exists()

    response = client.patch(f"/api/targets/{target['id']}", json={"note": "更新说明"})
    assert response.status_code == 200
    assert response.get_json()["target"]["note"] == "更新说明"
    assert not init_path.exists()


def test_delete_session_allows_finished_error_and_rejects_running(app_modules):
    db = app_modules["db"]
    web = app_modules["web"]
    target, finished_session = create_target(app_modules)
    error_session = db.create_debug_session(int(target["id"]), {"name": "err", "prompt": ""})
    running_session = db.create_debug_session(int(target["id"]), {"name": "run", "prompt": ""})
    with db.connect_db() as conn:
        conn.execute("UPDATE sessions SET status = 'error' WHERE id = ?", (int(error_session["id"]),))
        conn.execute("UPDATE sessions SET status = 'running' WHERE id = ?", (int(running_session["id"]),))
        conn.execute(
            "INSERT INTO messages(session_id, role, content, kind, created_at) VALUES (?, 'user', 'hello', 'message', ?)",
            (int(finished_session["id"]), db.now_iso()),
        )
        conn.execute(
            "INSERT INTO runs(session_id, source, prompt, model, status, started_at) VALUES (?, 'user', 'p', 'm', 'finished', ?)",
            (int(finished_session["id"]), db.now_iso()),
        )

    client = web.create_app().test_client()
    assert client.delete(f"/api/sessions/{finished_session['id']}").status_code == 200
    assert db.get_session(int(finished_session["id"])) is None
    with db.connect_db() as conn:
        assert conn.execute("SELECT COUNT(*) AS c FROM messages WHERE session_id = ?", (int(finished_session["id"]),)).fetchone()["c"] == 0
        assert conn.execute("SELECT COUNT(*) AS c FROM runs WHERE session_id = ?", (int(finished_session["id"]),)).fetchone()["c"] == 0

    assert client.delete(f"/api/sessions/{error_session['id']}").status_code == 200
    response = client.delete(f"/api/sessions/{running_session['id']}")
    assert response.status_code == 400
    assert db.get_existing_session(int(running_session["id"]))["status"] == "running"


def test_nonzero_exit_message_contains_error_fragments(app_modules, tmp_path: Path):
    runner = app_modules["runner"]
    log_file = tmp_path / "events.jsonl"
    log_file.write_text(
        json.dumps({"type": "error", "message": "stderr exploded", "stderr": "trace line"}) + "\n",
        encoding="utf-8",
    )

    message = runner.nonzero_exit_message(
        returncode=7,
        error=None,
        output_message="output failure",
        log_file=log_file,
    )
    assert "非零状态 7" in message
    assert "output failure" in message
    assert "stderr exploded" in message
    assert "trace line" in message


def test_vulnerability_list_filters_reference_rows(app_modules, tmp_path: Path):
    vulnerabilities = app_modules["vulnerabilities"]
    target = {"name": "t", "workspace_path": str(tmp_path)}
    archives = tmp_path / "archives"
    archives.mkdir()
    (archives / "known_findings.md").write_text(
        """| 总结 | 漏洞类型 | 安全评分 | 源文件 |
| --- | --- | --- | --- |
| 参考示例，不应展示 | crash | medium | ref.c |
| 真实越界写 | memory corruption | high | src/a.c |
""",
        encoding="utf-8",
    )
    payload = vulnerabilities.read_vulnerabilities(target)
    assert payload["count"] == 1
    assert payload["findings"][0]["summary"] == "真实越界写"
