"""Codex process orchestration for WebUI sessions."""

from __future__ import annotations

import json
import os
import shlex
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path
from typing import cast

from .config import CONFIG, UUID_RE
from .database import (
    add_message,
    append_session_bug_ids,
    create_run,
    get_session,
    now_iso,
    set_run_event_log_path,
    update_run_result,
    upsert_assistant_message,
)
from .prompts import base_prompt
from .schema import (
    BUSY_STATUSES,
    JsonObject,
    JsonValue,
    row_int,
    row_optional_str,
    row_str,
)
from .vulnerabilities import read_finding_bug_ids

ACTIVE_RUNS: dict[int, subprocess.Popen[str]] = {}
STOP_REQUESTS: set[int] = set()
ERROR_STOP_REQUESTS: set[int] = set()
ACTIVE_LOCK = threading.Lock()


def truncate(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "..."


def load_env_file(path: Path = Path("/etc/audit-env")) -> dict[str, str]:
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line.startswith("export ") or "=" not in line:
            continue
        try:
            token = shlex.split(line[len("export ") :], posix=True)[0]
        except (IndexError, ValueError):
            continue
        key, value = token.split("=", 1)
        if key:
            env[key] = value
    return env


def codex_env(target_id: int | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env.update({key: value for key, value in load_env_file().items() if value})
    env["CODEX_HOME"] = str(CONFIG.codex_home)
    if target_id is not None:
        env["AUDITOR_TARGET_ID"] = str(target_id)
    return env


def build_codex_command(
    *,
    model: str,
    output_file: Path,
    workspace: Path,
    resume_session_id: str | None,
    json_events: bool = True,
    ephemeral: bool = False,
) -> list[str]:
    cmd = ["codex", "exec", "resume"] if resume_session_id else ["codex", "exec"]
    if json_events:
        cmd.append("--json")
    if ephemeral:
        cmd.append("--ephemeral")
    cmd.append("--dangerously-bypass-approvals-and-sandbox")
    cmd.append("--skip-git-repo-check")
    if not resume_session_id:
        cmd.extend(["-C", str(workspace)])
    cmd.extend(["-m", model, "-o", str(output_file)])
    if resume_session_id:
        cmd.extend([resume_session_id, "-"])
    else:
        cmd.append("-")
    return cmd


def recursive_find_uuid(value: JsonValue) -> str | None:
    if isinstance(value, str):
        match = UUID_RE.search(value)
        return match.group(0) if match else None
    if isinstance(value, dict):
        for key in ("session_id", "conversation_id", "thread_id", "id"):
            if key in value:
                found = recursive_find_uuid(value[key])
                if found:
                    return found
        for item in value.values():
            found = recursive_find_uuid(item)
            if found:
                return found
    if isinstance(value, list):
        for item in value:
            found = recursive_find_uuid(item)
            if found:
                return found
    return None


def extract_assistant_message(event: JsonObject) -> str | None:
    event_type = str(event.get("type", ""))
    if event_type in {"agent_message", "assistant_message"}:
        for key in ("message", "text", "content"):
            value = event.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    item = event.get("item")
    if isinstance(item, dict) and str(item.get("type", "")) in {"agent_message", "assistant_message"}:
        for key in ("text", "message", "content"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
    return None


def write_json_event_log(log_file: Path, line: str) -> None:
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(line)
        if not line.endswith("\n"):
            handle.write("\n")


def tail_lines(path: Path, limit: int = 80) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="utf-8", errors="ignore").splitlines()[-limit:]


def extract_event_error_strings(value: JsonValue, *, event_is_error: bool = False) -> list[tuple[str, str]]:
    fragments: list[tuple[str, str]] = []
    if isinstance(value, dict):
        value_type = str(value.get("type", "")).lower()
        nested_is_error = event_is_error or any(marker in value_type for marker in ("error", "fail", "stderr"))
        for key, item in value.items():
            lowered = key.lower()
            if isinstance(item, str) and item.strip():
                if lowered in {"stderr", "stdout", "error", "output"} or (nested_is_error and lowered == "message"):
                    fragments.append((lowered, item.strip()))
            elif isinstance(item, dict | list):
                fragments.extend(extract_event_error_strings(cast(JsonValue, item), event_is_error=nested_is_error))
    elif isinstance(value, list):
        for item in value:
            fragments.extend(extract_event_error_strings(item, event_is_error=event_is_error))
    return fragments


def nonzero_exit_message(
    *,
    returncode: int,
    error: str | None,
    output_message: str,
    log_file: Path,
) -> str:
    fragments: list[tuple[str, str]] = []
    if error:
        fragments.append(("error", error))
    if output_message:
        fragments.append(("output", output_message))
    for line in tail_lines(log_file):
        try:
            event = cast(JsonValue, json.loads(line))
        except json.JSONDecodeError:
            if line.strip():
                fragments.append(("event", line.strip()))
            continue
        fragments.extend(extract_event_error_strings(event))

    seen: set[tuple[str, str]] = set()
    deduped: list[tuple[str, str]] = []
    for source, text in fragments:
        item = (source, truncate(text, 600))
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
        if len(deduped) >= 6:
            break

    lines = [f"Codex 主 agent 返回非零状态 {returncode}。"]
    if deduped:
        lines.append("可提取的错误片段:")
        lines.extend(f"- {source}: {text}" for source, text in deduped)
    else:
        lines.append("未提取到 stderr/stdout/event/output 错误片段。")
    return "\n".join(lines)


def discover_latest_session_id(start_time: float) -> str | None:
    sessions_dir = CONFIG.codex_home / "sessions"
    if not sessions_dir.exists():
        return None
    candidates: list[tuple[float, Path]] = []
    for path in sessions_dir.rglob("*.jsonl"):
        try:
            mtime = path.stat().st_mtime
        except OSError:
            continue
        if mtime >= start_time - 5:
            candidates.append((mtime, path))
    candidates.sort(reverse=True)
    for _, path in candidates[:10]:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for _ in range(80):
                    line = handle.readline()
                    if not line:
                        break
                    match = UUID_RE.search(line)
                    if match:
                        return match.group(0)
        except OSError:
            continue
    return None


def run_subprocess(cmd: list[str], prompt: str, *, env: dict[str, str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run(
        cmd,
        input=prompt,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=str(cwd),
        env=env,
        timeout=120,
        check=False,
    )
    return proc.returncode, proc.stdout


def is_session_active(session_id: int) -> bool:
    with ACTIVE_LOCK:
        proc = ACTIVE_RUNS.get(session_id)
    return bool(proc and proc.poll() is None)


def safe_read_finding_bug_ids(session: JsonObject) -> set[int] | None:
    try:
        return read_finding_bug_ids(session)
    except Exception:
        return None


def start_agent_run(session_id: int, prompt: str, *, source: str) -> bool:
    with ACTIVE_LOCK:
        if session_id in ACTIVE_RUNS:
            return False
        STOP_REQUESTS.discard(session_id)
        ERROR_STOP_REQUESTS.discard(session_id)
    session = get_session(session_id)
    if not session:
        raise KeyError("会话不存在")
    if row_str(session, "status") in BUSY_STATUSES:
        return False
    if source == "scheduler" and row_str(session, "status") == "pause":
        return False

    rendered_prompt = base_prompt(
        session,
        prompt,
        source=source,
    ).strip()
    if not rendered_prompt:
        raise ValueError("prompt 不能为空")

    pre_run_bug_ids = safe_read_finding_bug_ids(session)
    started_at = now_iso()
    run_id = create_run(
        session_id=session_id,
        source=source,
        prompt=rendered_prompt,
        model=CONFIG.main_model,
        started_at=started_at,
        codex_session_id_before=row_optional_str(session, "codex_session_id"),
    )
    add_message(session_id, "user", rendered_prompt)

    thread = threading.Thread(target=agent_worker, args=(session_id, run_id, rendered_prompt, pre_run_bug_ids), daemon=True)
    thread.start()
    return True


def agent_worker(session_id: int, run_id: int, prompt: str, pre_run_bug_ids: set[int] | None = None) -> None:
    session = get_session(session_id)
    if not session:
        return
    start_time = time.time()
    workspace = Path(row_str(session, "target_workspace_path", str(CONFIG.workspace)))
    output_file = CONFIG.temp_dir / f"last-{run_id}.txt"
    log_file = CONFIG.temp_dir / f"events-{run_id}.jsonl"
    set_run_event_log_path(run_id, log_file)
    cmd = build_codex_command(
        model=CONFIG.main_model,
        output_file=output_file,
        workspace=workspace,
        resume_session_id=row_optional_str(session, "codex_session_id"),
    )
    returncode = 1
    error: str | None = None
    discovered_session_id: str | None = None
    assistant_messages: list[str] = []
    assistant_message_id: int | None = None
    stop_requested = False
    error_stop_requested = False
    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(workspace),
            env=codex_env(row_int(session, "target_id")),
            bufsize=1,
        )
        with ACTIVE_LOCK:
            ACTIVE_RUNS[session_id] = proc
        if proc.stdin is None or proc.stdout is None:
            raise RuntimeError("Codex 子进程管道未创建")
        proc.stdin.write(prompt)
        proc.stdin.close()

        for line in proc.stdout:
            write_json_event_log(log_file, line)
            try:
                event = cast(JsonValue, json.loads(line))
            except json.JSONDecodeError:
                continue
            found_uuid = recursive_find_uuid(event)
            if found_uuid:
                discovered_session_id = found_uuid
            if isinstance(event, dict):
                message = extract_assistant_message(event)
                if message:
                    assistant_messages.append(message)
                    running_message = "\n\n".join(assistant_messages)
                    assistant_message_id = upsert_assistant_message(session_id, assistant_message_id, running_message)
        returncode = proc.wait()
    except OSError as exc:
        error = f"无法启动 codex: {exc}"
        returncode = 127
    except Exception as exc:
        error = f"Codex 执行异常: {exc}"
        returncode = 1
    finally:
        with ACTIVE_LOCK:
            ACTIVE_RUNS.pop(session_id, None)
            stop_requested = session_id in STOP_REQUESTS
            error_stop_requested = session_id in ERROR_STOP_REQUESTS
            STOP_REQUESTS.discard(session_id)
            ERROR_STOP_REQUESTS.discard(session_id)

    finalize_agent_run(
        session_id=session_id,
        run_id=run_id,
        output_file=output_file,
        assistant_messages=assistant_messages,
        assistant_message_id=assistant_message_id,
        discovered_session_id=discovered_session_id,
        start_time=start_time,
        log_file=log_file,
        returncode=returncode,
        error=error,
        stop_requested=stop_requested,
        error_stop_requested=error_stop_requested,
        pre_run_bug_ids=pre_run_bug_ids,
    )


def finalize_agent_run(
    *,
    session_id: int,
    run_id: int,
    output_file: Path,
    assistant_messages: list[str],
    assistant_message_id: int | None,
    discovered_session_id: str | None,
    start_time: float,
    log_file: Path,
    returncode: int,
    error: str | None,
    stop_requested: bool,
    error_stop_requested: bool = False,
    pre_run_bug_ids: set[int] | None = None,
) -> None:
    output_message = ""
    if output_file.exists():
        output_message = output_file.read_text(encoding="utf-8", errors="ignore").strip()
    running_message = "\n\n".join(assistant_messages)
    final_message = output_message or running_message
    last_message = final_message
    if not discovered_session_id:
        discovered_session_id = discover_latest_session_id(start_time)

    ended_at = now_iso()
    if final_message:
        if assistant_message_id is not None:
            upsert_assistant_message(session_id, assistant_message_id, final_message, touch_created_at=True)
        else:
            add_message(session_id, "assistant", final_message)
    interrupted = returncode < 0
    if error and not stop_requested and not interrupted:
        add_message(
            session_id,
            "system",
            nonzero_exit_message(
                returncode=returncode,
                error=error,
                output_message=output_message,
                log_file=log_file,
            ),
            "error",
        )
    elif returncode and returncode != 0 and not stop_requested and not interrupted:
        add_message(
            session_id,
            "system",
            nonzero_exit_message(
                returncode=returncode,
                error=error,
                output_message=output_message,
                log_file=log_file,
            ),
            "error",
        )

    if error_stop_requested:
        status = "error"
        last_error = error or "运行被系统停止"
    elif stop_requested:
        status = "pause"
        last_error = None
    elif returncode == 0:
        status = "finished"
        last_error = None
    elif interrupted:
        status = "interrupted"
        last_error = error or "Codex 运行被异常中断"
    else:
        status = "error"
        last_error = error or f"Codex 返回状态 {returncode}"
    if pre_run_bug_ids is not None:
        session = get_session(session_id)
        post_run_bug_ids = safe_read_finding_bug_ids(session) if session else None
        if post_run_bug_ids is not None:
            append_session_bug_ids(session_id, post_run_bug_ids - pre_run_bug_ids)
    update_run_result(
        session_id=session_id,
        run_id=run_id,
        status=status,
        returncode=returncode,
        ended_at=ended_at,
        codex_session_id_after=discovered_session_id,
        last_message=last_message,
        error=error,
        last_error=last_error,
    )


def stop_agent_run(session_id: int, *, mark_error: bool = False) -> bool:
    with ACTIVE_LOCK:
        proc = ACTIVE_RUNS.get(session_id)
    if not proc or proc.poll() is not None:
        return False
    with ACTIVE_LOCK:
        STOP_REQUESTS.add(session_id)
        if mark_error:
            ERROR_STOP_REQUESTS.add(session_id)
    proc.send_signal(signal.SIGTERM)
    return True


def expand_note_sync(target_name: str, note: str, *, workspace: Path | None = None) -> str:
    output_file = CONFIG.temp_dir / f"expand-note-{uuid.uuid4()}.txt"
    prompt = f"""以下内容为用户对{target_name}漏洞挖掘的补充说明, \
补充扩写来更加明确用户的补充说明边界和用户可能遗漏的问题, 不要落地文件
{note.strip()}"""
    run_workspace = workspace or CONFIG.workspace
    cmd = build_codex_command(
        model=CONFIG.main_model,
        output_file=output_file,
        workspace=run_workspace,
        resume_session_id=None,
        json_events=True,
        ephemeral=True,
    )
    returncode, stdout = run_subprocess(cmd, prompt, env=codex_env(), cwd=run_workspace)
    expanded = output_file.read_text(encoding="utf-8", errors="ignore").strip() if output_file.exists() else ""
    if not expanded:
        expanded = stdout.strip()
    if returncode != 0:
        raise RuntimeError(f"AI 扩写失败，Codex 返回状态 {returncode}: {truncate(expanded or stdout, 500)}")
    return expanded
