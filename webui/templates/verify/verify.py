#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import shlex
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path


def input_path(value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (Path.cwd() / path).resolve()


def split_env(raw: list[str]) -> dict[str, str]:
    env = {}
    for item in raw:
        if "=" not in item:
            raise SystemExit(f"无效 --env 值 {item!r}；期望格式为 KEY=VALUE")
        key, value = item.split("=", 1)
        env[key] = value
    return env


def parse_command_template(raw: str, input_file: Path) -> list[str]:
    text = raw.replace("{input}", shlex.quote(str(input_file)))
    try:
        return shlex.split(text)
    except ValueError as exc:
        raise SystemExit(f"无效命令模板 {raw!r}: {exc}") from exc


def status_from_returncode(code: int | None, timeout: float | None = None) -> str:
    if code is None:
        return f"超时 {timeout:g}s"
    if code == 0:
        return "正常"
    if code < 0:
        signum = -code
        try:
            name = signal.Signals(signum).name
        except ValueError:
            name = f"信号-{signum}"
        return f"信号 {name}"
    return f"退出 {code}"


def digest(stdout: str, stderr: str) -> str:
    return hashlib.sha256((stdout + "\0" + stderr).encode("utf-8", "replace")).hexdigest()[:12]


def run_one(command_template: str, input_file: Path, timeout: float, cwd: Path, extra_env: dict[str, str]):
    argv = parse_command_template(command_template, input_file)
    env = os.environ.copy()
    env.update(extra_env)
    start = time.monotonic()
    try:
        proc = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
        seconds = time.monotonic() - start
        return {
            "input": str(input_file),
            "template": command_template,
            "command": argv,
            "status": status_from_returncode(proc.returncode),
            "returncode": proc.returncode,
            "seconds": seconds,
            "output_hash": digest(proc.stdout, proc.stderr),
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    except subprocess.TimeoutExpired as exc:
        seconds = time.monotonic() - start
        stdout = exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return {
            "input": str(input_file),
            "template": command_template,
            "command": argv,
            "status": status_from_returncode(None, timeout),
            "returncode": None,
            "seconds": seconds,
            "output_hash": digest(stdout, stderr),
            "stdout": stdout,
            "stderr": stderr,
        }


def render_output(text: str, mode: str, limit: int) -> str:
    if mode == "none":
        return ""
    if mode == "full" or len(text) <= limit:
        return text
    return text[:limit] + f"\n... 已截断 {len(text) - limit} 个字符 ..."


def main():
    parser = argparse.ArgumentParser(
        description="运行命令/输入验证矩阵。",
        epilog=(
            "注意：本工具退出码只表示矩阵命令是否全部返回 0；"
            "候选漏洞复现 oracle 应由 repro.sh wrapper 映射为 exit 1/0。"
        ),
    )
    parser.add_argument("inputs", nargs="+", help="PoC 或输入文件。")
    parser.add_argument("--cmd", action="append", required=True, help="命令模板；用 {input} 表示输入路径。")
    parser.add_argument("--cwd", type=Path, default=Path.cwd(), help="命令工作目录。")
    parser.add_argument("--env", action="append", default=[], help="额外环境变量 KEY=VALUE，可重复。")
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--stdout", choices=("full", "truncated", "none"), default="truncated")
    parser.add_argument("--stderr", choices=("full", "truncated", "none"), default="truncated")
    parser.add_argument("--max-output-chars", type=int, default=4000)
    args = parser.parse_args()

    inputs = [input_path(value) for value in args.inputs]
    env = split_env(args.env)
    cwd = args.cwd.expanduser().resolve()
    results = []
    for input_file in inputs:
        for command_template in args.cmd:
            result = run_one(command_template, input_file, args.timeout, cwd, env)
            results.append(result)
            print("== 命令 ==")
            print(" ".join(shlex.quote(part) for part in result["command"]))
            print(f"状态={result['status']} 秒={result['seconds']:.3f} 输出={result['output_hash']}")
            stdout = render_output(result["stdout"], args.stdout, args.max_output_chars)
            stderr = render_output(result["stderr"], args.stderr, args.max_output_chars)
            if stdout:
                print("-- stdout --")
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print("-- stderr --")
                print(stderr, end="" if stderr.endswith("\n") else "\n")

    print("== 摘要 ==")
    for result in results:
        print(f"{Path(result['input']).name} | {result['status']} | {result['output_hash']} | {result['template']}")

    if args.json_out:
        payload = {
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "cwd": str(cwd),
            "results": results,
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"json输出={args.json_out}")

    raise SystemExit(0 if all(result["returncode"] == 0 for result in results) else 1)


if __name__ == "__main__":
    main()
