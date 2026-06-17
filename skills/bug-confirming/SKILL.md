---
name: bug-confirming
description: 验证、定级、复现并打包二进制漏洞候选。用于已有可疑 bug、崩溃、sanitizer 发现、可利用性问题或候选报告需要确认的场景，也用于决定是否归档发现或返回漏洞挖掘。
---

# 漏洞确认

## 漏洞标准

1. 将高危发现限定为内存破坏、可作为内存破坏前置条件的信息泄露、条件竞争等问题。报告必须证明在不使用 ASAN 的情况下，漏洞能造成真实破坏并带来可能的 RCE 风险，而不仅是崩溃。漏洞严重程度和报告质量应达到项目安全团队可接受并可能分配 CVE 的标准。

2. 将中危发现限定为任意文件读、正常构建下的真实崩溃等问题。不要依赖只在 ASAN 下出现的崩溃；必须确认普通构建可以崩溃或展示实际影响。例如堆溢出 1 个字节时，如果堆布局无法让该字节破坏有价值的相邻状态，则视为无效。

3. 只可能导致dos，不可能存在进一步利用风险的bug、实现问题、与文档或标准不一致的问题，以及其他低影响缺陷归类为 低危。

## 漏洞分类

当前漏洞分类标准为 "overflow", "oob", "uaf", "race", "crash", "fuzz", "sanitize", "other"

## 漏洞落地流程

1. 在 `./archives/` 下创建候选目录：`./archives/{id}-{description}/`。

2. 从本 skill 的 `assets/report_template/` 复制候选产物模板到 `./archives/{id}-{description}/`，并按实际目标填写：
   - `report.md`：中文漏洞报告。
   - `candidate.json`：结构化候选摘要。
   - `repro.sh`：稳定复现 oracle wrapper。
   - `notes.md`：失败假设、最小化、调试 trace、重复检查和未来放大思路记录。

3. 用中文将本次发现追加到 `./archives/known_findings.md`。

4. 不要止步于不可利用的低危漏洞。优先推进可能导致 RCE 的高价值漏洞。

5. 如果没有确认有价值漏洞，返回 `$bug-hunting` 继续挖掘新候选。

## 候选产物模板

模板源文件在 `assets/report_template/`。归档时保留这些文件名，替换模板占位内容，不要删除用于复核的字段。

- `report.md` 必须包含：标题、结论、环境、复现方法、实际现象、预期行为、根因分析、影响判断。报告用中文说明置信度、安全相关性、目标 commit 或版本、构建类型、二进制、sanitizer/debug 事实、关键 flag、复现命令、复现判定、重复次数、源码路径、函数、分支、输入或状态来源、边界条件、状态改变、危险使用点、缺失检查、影响版本和影响类型。
- `candidate.json` 必须填写核心 bug 摘要、`bug_type`、目标组件、源码位置、置信度、测试过的二进制、复现命令、实际结果、预期结果、安全相关性和重复检查结论。`bug_type` 使用模板中的候选枚举，无法归类时才使用 `other`。
- `repro.sh` 必须把目标专用复现判定映射为唯一 oracle：`exit 1` 表示复现 bug，`exit 0` 表示未复现 bug，其他退出码表示 harness 无效或不稳定。不要直接透传目标二进制退出码；crash、sanitizer、timeout、错误输出或语义差异都应在 wrapper 内解析后再返回 1/0。
- `notes.md` 用于记录报告外的工作日志：失败假设、最小化尝试、构建 flag、调试器 trace、备选根因解释、重复检查和未来放大思路。

## `known_findings.md` 填写参考

`./archives/known_findings.md` 保持为仅含表头的固定五列表格；不要在模板或实际归档中保留参考行。追加确认结果时使用如下格式。`Bug ID` 使用本目标内递增的非负整数，选择当前表中最大 Bug ID 加一；如果表中还没有漏洞，从 `0` 开始。

```markdown
| Bug ID | 总结 | 漏洞类型 | 安全评分 | 源文件 |
| --- | --- | --- | --- | --- |
| 0 | 在默认浅层校验下，RESTORE 接受了损坏的哈希 listpack，随后 HGETALL 在 lpAssertValidEntry 中中止崩溃。(该条仅作编写表格的参考) | crash | medium | src/rdb.c#L3254::rdbLoadObject. src/listpack.c#L1697::lpAssertValidEntry |
```
