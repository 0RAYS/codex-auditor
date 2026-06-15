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

2. 按照 `./report_template` 的格式，在 `./archives/{id}-{description}/` 中编写中文漏洞报告和 PoC。

3. 用中文将本次发现追加到 `./archives/known_findings.md`。

4. 不要止步于不可利用的低危漏洞。优先推进可能导致 RCE 的高价值漏洞。

5. 如果没有确认有价值漏洞，返回 `$bug-hunting` 继续挖掘新候选。

## `known_findings.md` 填写参考

`./archives/known_findings.md` 保持为仅含表头的固定四列表格；不要在模板或实际归档中保留参考行。追加确认结果时使用如下格式：

```markdown
| 总结 | 漏洞类型 | 安全评分 | 源文件 |
| --- | --- | --- | --- |
| 在默认浅层校验下，RESTORE 接受了损坏的哈希 listpack，随后 HGETALL 在 lpAssertValidEntry 中中止崩溃。(该条仅作编写表格的参考) | crash | medium | src/rdb.c#L3254::rdbLoadObject. src/listpack.c#L1697::lpAssertValidEntry |
```
