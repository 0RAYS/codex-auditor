"""Read and update target vulnerability summaries from Markdown tables."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TypedDict

from .schema import SECURITY_RATINGS, JsonObject, JsonValue, RowDict, row_str
from .workspace import atomic_write_text

HEADERS = ("Bug ID", "总结", "漏洞类型", "安全评分", "源文件")


class FindingRow(TypedDict):
    row_id: str
    line_no: int
    fingerprint: str
    cells: list[str]
    raw: str


def known_findings_path(target: RowDict) -> Path:
    workspace = Path(row_str(target, "workspace_path", row_str(target, "target_workspace_path")))
    return workspace / "archives" / "known_findings.md"


def read_vulnerabilities(target: RowDict) -> JsonObject:
    path = known_findings_path(target)
    if not path.exists():
        return empty_payload(target, path)
    text = path.read_text(encoding="utf-8", errors="ignore")
    if not text.strip():
        return empty_payload(target, path)
    rows = parse_findings_table(text)
    findings: list[JsonValue] = []
    for row in rows:
        if is_reference_finding(row["cells"]):
            continue
        rating = row["cells"][3].strip().lower()
        findings.append(
            {
                "row_id": row["row_id"],
                "line_no": row["line_no"],
                "fingerprint": row["fingerprint"],
                "bug_id": row["cells"][0],
                "summary": row["cells"][1],
                "bug_type": row["cells"][2],
                "security_rating": rating if rating in SECURITY_RATINGS else "unknown",
                "raw_security_rating": row["cells"][3],
                "source_files": row["cells"][4],
            },
        )
    return {
        "ok": True,
        "available": True,
        "path": str(path),
        "target": row_str(target, "name", row_str(target, "target_name")),
        "count": len(findings),
        "findings": findings,
    }


def empty_payload(target: RowDict, path: Path) -> JsonObject:
    return {
        "ok": True,
        "available": True,
        "path": str(path),
        "target": row_str(target, "name", row_str(target, "target_name")),
        "count": 0,
        "findings": [],
    }


def unavailable_payload(target: RowDict, error: str) -> JsonObject:
    path = known_findings_path(target)
    return {
        "ok": True,
        "available": False,
        "error": error,
        "requested_update": False,
        "path": str(path),
        "target": row_str(target, "name", row_str(target, "target_name")),
        "count": 0,
        "findings": [],
    }


def parse_findings_table(text: str) -> list[FindingRow]:
    lines = text.splitlines()
    table_start = -1
    for index, line in enumerate(lines):
        if parse_row(line) == list(HEADERS):
            table_start = index
            break
    if table_start < 0:
        raise ValueError("known_findings.md 缺少固定表头")
    if table_start + 1 >= len(lines) or not is_separator_row(lines[table_start + 1]):
        raise ValueError("known_findings.md 表头下方缺少分隔行")

    rows: list[FindingRow] = []
    for index in range(table_start + 2, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        if not line.lstrip().startswith("|"):
            break
        cells = parse_row(line)
        if len(cells) != len(HEADERS):
            raise ValueError(f"known_findings.md 第 {index + 1} 行列数错误")
        fingerprint = row_fingerprint(line)
        rows.append(
            {
                "row_id": f"line-{index + 1}-{fingerprint[:10]}",
                "line_no": index + 1,
                "fingerprint": fingerprint,
                "cells": cells,
                "raw": line,
            },
        )
    return rows


def read_finding_bug_ids(target: RowDict) -> set[int]:
    path = known_findings_path(target)
    if not path.exists():
        raise FileNotFoundError(f"未找到 {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    rows = parse_findings_table(text)
    bug_ids: set[int] = set()
    for row in rows:
        if is_reference_finding(row["cells"]):
            continue
        raw_bug_id = row["cells"][0].strip()
        try:
            bug_id = int(raw_bug_id)
        except ValueError as exc:
            raise ValueError(f"known_findings.md 第 {row['line_no']} 行 Bug ID 不是整数") from exc
        if bug_id < 0:
            raise ValueError(f"known_findings.md 第 {row['line_no']} 行 Bug ID 不能为负数")
        bug_ids.add(bug_id)
    return bug_ids


def is_reference_finding(cells: list[str]) -> bool:
    marker_text = " ".join(cells).lower()
    return any(
        marker in marker_text
        for marker in (
            "仅作编写表格的参考",
            "参考示例",
            "示例行",
            "example finding",
            "reference finding",
        )
    )


def parse_row(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped.startswith("|") or not stripped.endswith("|"):
        return []
    body = stripped[1:-1]
    cells: list[str] = []
    current: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            cells.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    cells.append("".join(current).strip())
    return cells


def is_separator_row(line: str) -> bool:
    cells = parse_row(line)
    if len(cells) != len(HEADERS):
        return False
    return all(cell.replace(":", "").replace("-", "").strip() == "" and "-" in cell for cell in cells)


def row_fingerprint(line: str) -> str:
    return hashlib.sha256(line.strip().encode("utf-8")).hexdigest()


def update_vulnerability_rating(
    target: RowDict,
    row_id: str,
    old_fingerprint: str,
    rating: str,
) -> JsonObject:
    normalized = rating.strip().lower()
    if normalized not in SECURITY_RATINGS:
        raise ValueError("漏洞等级只能是 low、medium、high")
    path = known_findings_path(target)
    if not path.exists():
        raise FileNotFoundError(f"未找到 {path}")
    text = path.read_text(encoding="utf-8", errors="ignore")
    rows = parse_findings_table(text)
    matched = [row for row in rows if row["row_id"] == row_id]
    if len(matched) != 1:
        raise ValueError("漏洞行已变化，请刷新后重试")
    row = matched[0]
    if row["fingerprint"] != old_fingerprint:
        raise ValueError("漏洞行已被修改，请刷新后重试")

    lines = text.splitlines()
    line_index = row["line_no"] - 1
    cells = list(row["cells"])
    cells[3] = normalized
    lines[line_index] = format_row(cells)
    atomic_write_text(path, "\n".join(lines).rstrip() + "\n")
    return read_vulnerabilities(target)


def format_row(cells: list[str]) -> str:
    escaped = [cell.replace("|", "\\|").strip() for cell in cells]
    return "| " + " | ".join(escaped) + " |"
