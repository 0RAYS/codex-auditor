# Codex Weber

基于 [Codex](https://github.com/openai/codex) 的代码审计 / CTF 工作站 Docker 镜像

这是一个专用镜像, 目前打算给代码审计使用, 直接把源码通过filebrowser传上去以后, 启动codex, 描述项目结构等, 达到开箱即用的目的

## 快速开始

```bash
docker run -d \
  -p 8981:8981 \
  -p 8982:8982 \
  -e OPENAI_API_KEY="sk-xxx" \
  -e OPENAI_BASE_URL="https://your.api.dist/v1" \
  -e PASSWORD="yourpassword" \
  -v codex-data:/data \
  ghcr.io/0rays/codex-auditor-web:latest
```

需要注意的是, 如果/data如果不挂载, 存储的配置会丢失.

如需本地构建并确保重新获取 Ubuntu 基础镜像和动态安装的最新依赖，请禁用构建缓存：

```bash
docker build --pull --no-cache -t codex-auditor-web .
```

## 访问方式

| 方式 | 地址 |
|---|---|
| Web 终端 | `http://<host>:8981` |
| SSH | `ssh root@<host> -p 8982` |

默认密码通过 `PASSWORD` 环境变量设置，未设置时为 `0raysnb`。

## 环境变量 

启动时同时传入 `OPENAI_API_KEY` 和 `OPENAI_BASE_URL` 后，`scripts/start.sh` 会根据 `scripts/config.toml.template` 生成 `/data/codex/config.toml`。API Key 不写入 TOML，而是由自定义 provider 通过 `env_key` 引用 `OPENAI_API_KEY`；Base URL 会写入 provider 的 `base_url`。如果配置文件已经存在，启动脚本只更新其中的 Base URL。

| 变量 | 说明 |
|---|---|
| `OPENAI_API_KEY` | Codex 使用的 APIKey |
| `OPENAI_BASE_URL` | API 地址, 格式为https://placeholder.com/v1 |
| `PASSWORD` | SSH 和终端的 root 密码 (默认为0raysnb) |
| `PROXY` | HTTP/HTTPS 代理地址 (可选) |

`PROXY` 会同时设置大小写形式的 HTTP/HTTPS 代理环境变量，并为 Git 配置代理。镜像不预设 Codex 模型，用户启动 Codex 时自行选择。默认配置关闭 analytics 和 feedback，并启用 multi-agent 功能。

## 目录结构

```
/data/                  # 持久化卷
├── workspace/          # 主工作目录
├── tools/              # 预置安全工具
├── skills/             # 基础 Skills，可由用户持久化修改
├── codex/              # Codex 配置持久化
└── custom.sh           # 用户自定义启动脚本（自动 source）
```

构建镜像时，仓库中的 `skills/` 会复制到 `/data/skills/`。Codex 通过 `/etc/codex/skills` 软链接自动发现其中包含有效 `SKILL.md` 的 Skill，不需要在 `config.toml` 中显式启用。使用持久化卷后，用户可以直接修改 `/data/skills/` 中的内容。

已有的 `/data` 持久化卷不会被新镜像中的文件覆盖。因此，镜像新增或更新基础 Skills 后，旧容器需要手动同步对应目录，或者使用新的数据卷。

## 预装环境

- Python 3 + pip（Requests、Beautiful Soup、Semgrep、pip-audit）
- Node.js + npm + Codex CLI
- Ubuntu 26.04
- Ubuntu 26.04 默认 OpenJDK + CFR 0.152
- Ubuntu 26.04 默认 PHP
- File Browser、ttyd、tmux、ripgrep、jq 等常用审计与终端工具

为减小镜像体积和构建时间，镜像不再预装 Composer 和 ysoserial。Codex CLI、File Browser 以及未固定版本的 Python 工具会在构建时安装当时的最新版本；Tini 固定为 0.19.0，CFR 固定为 0.152。
