# Codex Pwner

基于 [Codex](https://github.com/openai/codex) 的二进制（闭源）代码审计 / CTF Docker 镜像

这是一个**基础镜像**，预装了通用 Pwn 工具和运行环境。

## 快速开始

```bash
docker run -d \
  --name pwner \
  -p 8981:8981 \
  -p 8982:8982 \
  -e OPENAI_API_KEY="sk-xxx" \
  -e OPENAI_BASE_URL="https://your.api.dist/v1" \
  -e PASSWORD="yourpassword" \
  -v codex-data:/data \
  ghcr.io/0rays/codex-auditor-pwn:latest
```

需要注意的是, 如果/data如果不挂载, 存储的配置会丢失.

## 访问方式

| 方式 | 地址 |
|---|---|
| Web 终端 (ttyd) | `http://<host>:8981` |
| 文件浏览器 | `http://<host>:8981/files/` |
| 监控 ttyd (给codex用的，不要随意操作，避免影响ai判断) | `http://<host>:8981/monitor/` |
| SSH | `ssh root@<host> -p 8982` |

默认密码通过 `PASSWORD` 环境变量设置，未设置时为 `0raysnb`。

## 环境变量

环境中预装了tui版的cc-switch, 并且持久化到/data目录下, 也不一定需要使用环境变量传递APIKEY. 

如果通过docker启动时的环境变量传递, 且同时设置了`OPENAI_API_KEY`和`OPENAI_BASE_URL`, 则会自动填充到codex的config.toml, 具体逻辑可以参考 `scripts/start.sh`

| 变量 | 说明 |
|---|---|
| `OPENAI_API_KEY` | Codex 使用的 APIKey |
| `OPENAI_BASE_URL` | API 地址, 格式为https://placeholder.com/v1 |
| `PASSWORD` | SSH 和终端的 root 密码 (默认为0raysnb) |
| `PROXY` | HTTP/HTTPS 代理地址 (可选) |
| `GLOBAL_MIRROR` | 运行时是否使用自带 mirrorlist (默认换成国内源；海外建议设置以恢复官方mirrorlist) |
| `PACMAN_NEW_KEYRING` | 设置后每次启动都生成新本地密钥，需要启用不安全的源时设置 |
| `IDA_MCP_URL` | IDA Pro MCP Streamable HTTP URL |
| `GHIDRA_MCP_URL` | Ghidra MCP Streamable HTTP URL |

## 目录结构

```
/data/                  # 持久化卷
├── workspace/          # 主工作目录
├── tools/              # 预置安全工具
├── codex/              # Codex 配置持久化
├── cc-switch/          # cc-switch 配置持久化
└── custom.sh           # 用户自定义启动脚本（自动 source）
```

## 预装环境

- Python + uv
- C/C++ 编译环境（`base-devel` + `cmake` 等）

## 自定义扩展

基于此镜像构建专属环境：

```dockerfile
FROM ghcr.io/0rays/codex-auditor-pwn:latest

RUN pacman -Syu --noconfirm python-angr
```

为控制镜像体积，不要预装过大的工具，按需现场安装

注意动调需要给docker**加上特权**
