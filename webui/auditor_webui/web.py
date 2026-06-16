"""Flask application factory and HTTP routes."""

# mypy: disable-error-code="import-not-found,untyped-decorator"

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from pathlib import Path
from typing import cast

from flask import Flask, Response, jsonify, request
from flask.typing import ResponseReturnValue
from werkzeug.exceptions import HTTPException

from .codex_runner import expand_note_sync, start_agent_run, stop_agent_run
from .config import CONFIG
from .database import (
    connect_db,
    create_debug_session,
    create_target_with_default_session,
    delete_session,
    delete_target,
    get_existing_session,
    get_existing_target,
    get_settings,
    init_db,
    list_messages,
    list_state_tree,
    mark_intervention_detected,
    mark_intervention_notice_read,
    mark_target_mining_sessions_error,
    running_auto_mining_session_ids,
    set_setting,
    update_target_auto_mining_state,
    update_target_note,
)
from .schema import BUSY_STATUSES, JsonObject, JsonValue, row_int, row_str
from .scheduler import intervention_path, read_intervention_reason, start_scheduler
from .vulnerabilities import read_vulnerabilities, unavailable_payload, update_vulnerability_rating
from .workspace import delete_target_workspace, prepare_target_workspace, validate_target_name


def json_response(payload: Mapping[str, object], status: int = 200) -> tuple[Response, int]:
    return jsonify(dict(payload)), status


def request_json() -> JsonObject:
    payload = cast(object, request.get_json(silent=True))
    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise ValueError("请求体必须是 JSON 对象")
    result: JsonObject = {}
    for key, value in payload.items():
        if not isinstance(key, str):
            raise ValueError("请求体 JSON 对象的 key 必须是字符串")
        result[key] = cast(JsonValue, value)
    return result


def current_theme() -> str:
    try:
        with connect_db() as conn:
            settings = get_settings(conn)
    except sqlite3.Error:
        return "light"
    return "dark" if settings.get("theme") == "dark" else "light"


def render_index() -> Response:
    target = CONFIG.static_dir / "index.html"
    html = target.read_text(encoding="utf-8")
    theme = current_theme()
    body_class = ' class="dark"' if theme == "dark" else ""
    html = html.replace("<body>", f'<body{body_class} data-theme="{theme}">', 1)
    return Response(html, mimetype="text/html")


def create_app() -> Flask:
    app = Flask(__name__, static_folder=str(CONFIG.static_dir), static_url_path="/static")

    @app.after_request
    def add_no_cache(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def handle_value_error(exc: ValueError) -> ResponseReturnValue:
        return json_response({"ok": False, "error": str(exc)}, 400)

    @app.errorhandler(KeyError)
    def handle_key_error(exc: KeyError) -> ResponseReturnValue:
        message = str(exc.args[0]) if exc.args else str(exc)
        return json_response({"ok": False, "error": message}, 404)

    @app.errorhandler(404)
    def handle_not_found(_: Exception) -> ResponseReturnValue:
        return json_response({"ok": False, "error": "未知 API"}, 404)

    @app.errorhandler(Exception)
    def handle_exception(exc: Exception) -> ResponseReturnValue:
        if isinstance(exc, HTTPException):
            return json_response({"ok": False, "error": exc.description}, exc.code or 500)
        return json_response({"ok": False, "error": str(exc)}, 500)

    @app.get("/")
    def index() -> Response:
        return render_index()

    @app.get("/api/state")
    def api_state() -> ResponseReturnValue:
        with connect_db() as conn:
            settings = get_settings(conn)
        return json_response({"ok": True, "settings": settings, "targets": list_state_tree()})

    @app.patch("/api/settings")
    def api_update_settings() -> ResponseReturnValue:
        payload = request_json()
        theme = payload.get("theme")
        if theme is not None:
            if theme not in {"light", "dark"}:
                raise ValueError("theme 只能是 light 或 dark")
            set_setting("theme", str(theme))
        for key in ("selected_target_id", "selected_session_id"):
            value = payload.get(key)
            if value is not None:
                set_setting(key, str(value))
        return json_response({"ok": True})

    @app.post("/api/targets")
    def api_create_target() -> ResponseReturnValue:
        payload = request_json()
        unexpected = set(payload) - {"name", "note"}
        if unexpected:
            raise ValueError(f"不支持的字段: {', '.join(sorted(unexpected))}")
        raw_name = payload.get("name")
        if not isinstance(raw_name, str):
            raise ValueError("目标名必须是字符串")
        name = validate_target_name(raw_name)
        note = str(payload.get("note", "")).strip()
        with connect_db() as conn:
            if conn.execute("SELECT 1 FROM targets WHERE name = ?", (name,)).fetchone():
                raise ValueError("目标名已存在")
        workspace_path = prepare_target_workspace(name, note)
        try:
            target, session = create_target_with_default_session(name, note, workspace_path)
        except Exception:
            delete_target_workspace(workspace_path)
            raise
        session_id = row_int(session, "id")
        start_agent_run(session_id, row_str(session, "prompt"), source="scheduler")
        session = get_existing_session(session_id)
        return json_response({"ok": True, "target": target, "session": session}, 201)

    @app.get("/api/targets/<int:target_id>")
    def api_get_target(target_id: int) -> ResponseReturnValue:
        return json_response({"ok": True, "target": get_existing_target(target_id)})

    @app.patch("/api/targets/<int:target_id>")
    def api_update_target(target_id: int) -> ResponseReturnValue:
        target = get_existing_target(target_id)
        payload = request_json()
        unexpected = set(payload) - {"note"}
        if unexpected:
            raise ValueError(f"不支持的字段: {', '.join(sorted(unexpected))}")
        note = str(payload.get("note", row_str(target, "note"))).strip()
        updated = update_target_note(target_id, note)
        return json_response({"ok": True, "target": updated})

    @app.patch("/api/targets/<int:target_id>/scheduler-state")
    def api_update_target_scheduler_state(target_id: int) -> ResponseReturnValue:
        payload = request_json()
        state = str(payload.get("state", "")).strip()
        if state not in {"running", "frozen"}:
            raise ValueError("state 只能是 running 或 frozen")
        return json_response({"ok": True, "target": update_target_auto_mining_state(target_id, state)})

    @app.patch("/api/targets/<int:target_id>/intervention")
    def api_trigger_intervention(target_id: int) -> ResponseReturnValue:
        target = get_existing_target(target_id)
        path = intervention_path(target)
        reason = read_intervention_reason(path) if path.exists() else "未提供原因"
        running_session_ids = running_auto_mining_session_ids(target_id)
        updated = mark_intervention_detected(target_id, reason)
        mark_target_mining_sessions_error(target_id, reason)
        for session_id in running_session_ids:
            stop_agent_run(session_id, mark_error=True)
        return json_response({"ok": True, "target": updated})

    @app.post("/api/targets/<int:target_id>/intervention/ack")
    def api_ack_intervention(target_id: int) -> ResponseReturnValue:
        return json_response({"ok": True, "target": mark_intervention_notice_read(target_id)})

    @app.delete("/api/targets/<int:target_id>")
    def api_delete_target(target_id: int) -> ResponseReturnValue:
        delete_target(target_id)
        return json_response({"ok": True})

    @app.post("/api/targets/expand-note")
    def api_expand_note_new_target() -> ResponseReturnValue:
        payload = request_json()
        target_name = str(payload.get("name", "")).strip() or "未命名目标"
        note = str(payload.get("note", "")).strip()
        return json_response({"ok": True, "expanded": expand_note_sync(target_name, note)})

    @app.post("/api/targets/<int:target_id>/expand-note")
    def api_expand_note_target(target_id: int) -> ResponseReturnValue:
        target = get_existing_target(target_id)
        payload = request_json()
        note = str(payload.get("note", row_str(target, "note"))).strip()
        expanded = expand_note_sync(
            row_str(target, "name"),
            note,
            workspace=Path(row_str(target, "workspace_path")),
        )
        return json_response({"ok": True, "expanded": expanded})

    @app.post("/api/targets/<int:target_id>/sessions")
    def api_create_debug_session(target_id: int) -> ResponseReturnValue:
        payload = request_json()
        session = create_debug_session(target_id, payload)
        prompt = row_str(session, "prompt")
        start = bool(payload.get("start", bool(prompt)))
        if prompt and start:
            session_id = row_int(session, "id")
            start_agent_run(session_id, prompt, source="user")
        return json_response({"ok": True, "session": session}, 201)

    @app.get("/api/targets/<int:target_id>/vulnerabilities")
    def api_target_vulnerabilities(target_id: int) -> ResponseReturnValue:
        target = get_existing_target(target_id)
        try:
            return json_response(read_vulnerabilities(target))
        except Exception as exc:
            return json_response(unavailable_payload(target, str(exc)))

    @app.patch("/api/targets/<int:target_id>/vulnerabilities/<row_id>")
    def api_update_vulnerability(target_id: int, row_id: str) -> ResponseReturnValue:
        target = get_existing_target(target_id)
        payload = request_json()
        fingerprint = str(payload.get("fingerprint", "")).strip()
        if not fingerprint:
            raise ValueError("缺少漏洞行 fingerprint")
        rating = str(payload.get("security_rating", "")).strip()
        return json_response(update_vulnerability_rating(target, row_id, fingerprint, rating))

    @app.get("/api/sessions/<int:session_id>/messages")
    def api_messages(session_id: int) -> ResponseReturnValue:
        get_existing_session(session_id)
        after = int(request.args.get("after", "0"))
        return json_response({"ok": True, "messages": list_messages(session_id, after_id=after)})

    @app.delete("/api/sessions/<int:session_id>")
    def api_delete_session(session_id: int) -> ResponseReturnValue:
        delete_session(session_id)
        return json_response({"ok": True})

    @app.post("/api/sessions/<int:session_id>/messages")
    def api_send_message(session_id: int) -> ResponseReturnValue:
        session = get_existing_session(session_id)
        if row_str(session, "status") in BUSY_STATUSES:
            raise ValueError("当前会话已有运行中的任务")
        payload = request_json()
        content = str(payload.get("content", "")).strip()
        if not content:
            raise ValueError("消息不能为空")
        started = start_agent_run(session_id, content, source="user")
        if not started:
            raise ValueError("当前会话已有运行中的 Codex 任务")
        return json_response({"ok": True})

    @app.post("/api/sessions/<int:session_id>/stop")
    def api_stop(session_id: int) -> ResponseReturnValue:
        get_existing_session(session_id)
        return json_response({"ok": True, "stopped": stop_agent_run(session_id)})

    @app.post("/api/sessions/<int:session_id>/repair-vulnerabilities")
    def api_repair_vulnerabilities(session_id: int) -> ResponseReturnValue:
        session = get_existing_session(session_id)
        if row_str(session, "status") in BUSY_STATUSES:
            raise ValueError("当前会话已有运行中的任务")
        prompt = "请检查并修复 ./archives/known_findings.md，使其符合固定五列 Markdown 表格协议：Bug ID / 总结 / 漏洞类型 / 安全评分 / 源文件。"
        start_agent_run(session_id, prompt, source="user")
        return json_response({"ok": True})

    return app


def create_wsgi_app() -> Flask:
    init_db()
    start_scheduler()
    return create_app()


def main() -> None:
    print(f"codex-auditor webui listening on http://{CONFIG.host}:{CONFIG.port}/", flush=True)
    app = create_wsgi_app()
    app.run(host=CONFIG.host, port=CONFIG.port, threaded=True, use_reloader=False)
