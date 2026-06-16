"""Target workspace preparation and atomic file updates."""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import suppress
from pathlib import Path

from .config import CONFIG, TARGET_NAME_RE, target_workspace


def validate_target_name(value: str) -> str:
    name = value
    if not TARGET_NAME_RE.fullmatch(name):
        raise ValueError("目标名必须以字母或数字开头，只能包含字母、数字、点、下划线和短横线，长度不超过 64")
    if name in {".", "..", "audit", "temp", "templates"}:
        raise ValueError("目标名与系统目录冲突")
    return name


def prepare_target_workspace(name: str, _note: str) -> Path:
    workspace = target_workspace(validate_target_name(name))
    if workspace.exists():
        raise ValueError("目标工作区目录已存在")
    if not CONFIG.templates_dir.exists():
        raise FileNotFoundError(f"模板目录不存在: {CONFIG.templates_dir}")
    shutil.copytree(CONFIG.templates_dir, workspace)
    return workspace


def validate_workspace_for_delete(workspace: Path) -> Path:
    root = CONFIG.workspace.resolve()
    resolved = workspace.resolve()
    if resolved == root or not resolved.is_relative_to(root):
        raise ValueError("目标工作区路径不在配置的 workspace 根目录内")
    return resolved


def delete_target_workspace(workspace: Path) -> None:
    resolved = validate_workspace_for_delete(workspace)
    if resolved.exists():
        if not resolved.is_dir():
            raise ValueError("目标工作区路径不是目录")
        shutil.rmtree(resolved)


def atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        with suppress(FileNotFoundError):
            os.unlink(tmp_name)
