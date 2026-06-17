"""Prompt templates used by the automation worker."""

from __future__ import annotations

from textwrap import dedent

from .schema import RowDict, row_int, row_str


def base_prompt(
    session: RowDict,
    user_prompt: str,
    *,
    source: str = "user",
) -> str:
    if source == "user":
        return user_prompt

    target_name = row_str(session, "target_name")
    target_id = row_int(session, "target_id")
    workspace_path = row_str(session, "target_workspace_path")
    note = row_str(session, "target_note")

    general = dedent(
        f"""
        你正在执行 codex-auditor 自动化二进制安全审计会话。

        目标: {target_name}
        目标 ID: {target_id}
        目标工作区: {workspace_path}

        - 需要人工介入时，先写 ./human_intervention.json 说明 reason，再调用 WebUI PATCH API: PATCH /api/targets/$AUDITOR_TARGET_ID/intervention。
        - 如果任务没有完成，不要只做泛泛总结；继续推进最有价值的审计路径。

        目标补充说明:
        {note or "无"}
        """,
    ).strip()

    checklist = dedent(
        """
        如果以下任务未完成, 则你是项目初始化负责人, 以下是你的checklist。

        1. 拉取目标程序完整源码并编译，要求 asan、release 和 debug 三个版本，配置好尽可能可用的调试环境。
        2. 使用 `xref` 命令为目标工作区建立 `xref.db` 索引，配置好 verify，确保 pytest 通过且工具可用。
        3. `xref` 构建数据库时要有完整的commit历史和所有的TU数据，但编译和构建是长任务，将其放在后台定期检查.
        """,
    ).strip()

    structure = dedent(
        """
        ## 目录结构与协议

        - `xref`：全局源码索引和查询命令，数据库位于目标工作区根目录的 `xref.db`。
        - `verify/`：PoC、输入文件、harness 和目标二进制的命令矩阵验证器。
        - `report_template/`：候选漏洞产物模板。
        - `archives/known_findings.md`：整理的全部发现集合，固定五列为 `Bug ID / 总结 / 漏洞类型 / 安全评分 / 源文件`。
        - `archives/known_fails.md`：整理的全部失败集合。
        - `archives/{id}-{description}`：候选漏洞产物目录。
        - `vuln.md`：记录攻击面和后续审计结果。
        - `$bug-confirming`：候选漏洞落地指南。
        - `$bug-hunting`：漏洞挖掘指导。
        - 使用 $bug-hunting 指导漏洞挖掘，候选漏洞落地时使用 $bug-confirming。
        """,
    ).strip()

    blocks = [general]
    blocks.append(checklist)
    blocks.append(structure)
    return "\n\n".join(blocks)
