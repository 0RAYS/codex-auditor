# 通用验证器

对一个或多个 PoC/输入运行一个或多个命令模板，通常用于调用目标二进制、库 harness、测试程序或服务 wrapper。

```sh
python3 verify/verify.py \
  --cmd "/path/to/bin/tool {input}" \
  --cmd "/path/to/asan/bin/tool {input}" \
  /tmp/poc.bin
```

当命令需要插入输入路径时，模板里必须包含 `{input}`。工具会报告退出状态、信号、超时、输出 hash、stdout 和 stderr。

注意：`verify.py` 的自身退出码只表示命令矩阵是否全部返回 0。它不是漏洞复现 oracle。候选报告中的稳定复现应通过 `repro.sh` 或其他 wrapper 明确映射：

```text
exit 1 = 已复现 bug
exit 0 = 未复现 bug
其他   = harness 无效、不稳定或环境错误
```

写出 JSON：

```sh
python3 verify/verify.py \
  --cmd "./build/debug/target-tool {input}" \
  --cmd "./build/asan/target-tool {input}" \
  --json-out /tmp/verify.json \
  /tmp/poc.dat
```

控制终端输出：

```sh
python3 verify/verify.py \
  --cmd "./build/debug/target-tool {input}" \
  --stdout truncated \
  --stderr none \
  --max-output-chars 4000 \
  /tmp/poc.dat
```

这个工具不判断漏洞是否有效，只提供目标二进制或 harness 的机械行为差异，供 agent 解释。
