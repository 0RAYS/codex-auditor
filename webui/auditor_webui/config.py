"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Final


@dataclass(frozen=True)
class Config:
    workspace: Path
    templates_dir: Path
    audit_dir: Path
    temp_dir: Path
    db_path: Path
    static_dir: Path
    codex_home: Path
    agents_path: Path
    host: str
    port: int
    main_model: str


def _env_path(name: str, default: Path) -> Path:
    return Path(os.environ.get(name, str(default)))


def _env_int(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None:
        return default
    return int(raw_value)


def load_config() -> Config:
    app_dir = Path(__file__).resolve().parents[1]
    data_root = _env_path("AUDITOR_DATA_ROOT", Path("/data"))
    workspace = _env_path("AUDITOR_WORKSPACE", data_root / "workspace")
    audit_dir = _env_path("AUDITOR_AUDIT_DIR", workspace / "audit")
    temp_dir = _env_path("AUDITOR_TEMP_DIR", workspace / "temp" / "codex-auditor-webui")
    db_path = _env_path("AUDITOR_WEBUI_DB", audit_dir / "webui.sqlite3")
    static_dir = _env_path("AUDITOR_WEBUI_STATIC", app_dir / "static")
    templates_dir = _env_path("AUDITOR_WORKSPACE_TEMPLATE", app_dir / "templates")
    codex_home = _env_path("CODEX_HOME", data_root / "codex")
    return Config(
        workspace=workspace,
        templates_dir=templates_dir,
        audit_dir=audit_dir,
        temp_dir=temp_dir,
        db_path=db_path,
        static_dir=static_dir,
        codex_home=codex_home,
        agents_path=_env_path("AUDITOR_AGENTS_PATH", codex_home / "AGENTS.md"),
        host=os.environ.get("AUDITOR_WEBUI_HOST", "127.0.0.1"),
        port=_env_int("AUDITOR_WEBUI_PORT", 8983),
        main_model=os.environ.get("AUDITOR_MAIN_MODEL", "gpt-5.5"),
    )


CONFIG: Final = load_config()

UUID_RE: Final = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
)
TARGET_NAME_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def target_workspace(name: str) -> Path:
    return CONFIG.workspace / name
