#!/bin/sh
set -eu

# 将目标专用复现判定映射为唯一 oracle：
#   exit 1 = 复现 bug
#   exit 0 = 未复现 bug
#   其他   = harness 无效或不稳定
#
# 不要直接把目标二进制的退出码透传给上层验证器。对于 crash、sanitizer、
# timeout、错误输出或语义差异，应在本 wrapper 内解析后再返回 1/0。

echo "请用目标命令替换这个 wrapper" >&2
exit 0
