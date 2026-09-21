# 0RAYS Codex Auditor

基于 [Codex](https://github.com/openai/codex) 的二进制（开源）代码审计 Docker 镜像

这是一个**基础镜像**，预装了通用编译工具和运行环境。

## 快速开始

推荐自己从仓库build
```bash
docker build . -t codex-auditor
docker volume create codex-data

docker run -d \
  --name binary-audit \
  -p 8981:8981 \
  -p 8982:8982 \
  -e OPENAI_API_KEY="sk-xxx" \
  -e OPENAI_BASE_URL="https://your.api.dist/v1" \
  -e PASSWORD="yourpassword" \
  -e OMNIGENT_WS_ALLOWED_ORIGINS="https://codex.example.com" \
  -v codex-data:/data \
  codex-auditor
```

需要注意的是, 如果/data如果不挂载, 存储的配置会丢失.

## 访问方式

| 方式 | 地址 |
|---|---|
| Web 终端 (ttyd) | `http://<host>:8981` |
| Omnigent Codex Web UI | `http://<host>:8981/codex-ui/` |
| SSH | `ssh root@<host> -p 8982` |

默认密码通过 `PASSWORD` 环境变量设置，未设置时为 `0raysnb`。

Omnigent 与终端共用此镜像内已经登录的 Codex CLI 和 `/data/codex`
配置；它的会话数据库与上传附件保存在 `/data/omnigent`。该服务只监听
容器回环地址 `127.0.0.1:6767`，通过现有 Nginx 的 `/codex-ui/`
路径对外提供访问，不需要 Postgres 或额外容器。

通过公网 HTTPS 反代访问 Omnigent 时，必须设置
`OMNIGENT_WS_ALLOWED_ORIGINS` 为用户浏览器实际访问的**源**，例如
`https://codex.example.com`；多个源以英文逗号分隔。它不包含路径，也不带
结尾 `/`。若 HTTPS 运行在非默认端口，端口也必须写入，例如
`https://codex.example.com:8443`。该变量会由 supervisord 继承并传给
Omnigent server，用于放行 WebSocket 和图片/文件上传的 Origin 校验。

## 环境变量

环境中预装了tui版的cc-switch, 并且持久化到/data目录下, 也不一定需要使用环境变量传递APIKEY. 

如果通过docker启动时的环境变量传递, 且同时设置了`OPENAI_API_KEY`和`OPENAI_BASE_URL`, 则会自动填充到codex的config.toml, 具体逻辑可以参考 `scripts/start.sh`

| 变量 | 说明 |
|---|---|
| `OPENAI_API_KEY` | Codex 使用的 APIKey |
| `OPENAI_BASE_URL` | API 地址, 格式为https://placeholder.com/v1 |
| `PASSWORD` | SSH 和终端的 root 密码 (默认为0raysnb) |
| `OMNIGENT_WS_ALLOWED_ORIGINS` | Omnigent Web UI 的公网 Origin 白名单；例如 `https://codex.example.com`，多个值用逗号分隔 |
| `PROXY` | HTTP/HTTPS 代理地址 (可选) |
| `GLOBAL_MIRROR` | 是否使用自带海外 mirrorlist (默认禁用海外源；运行时可设置环境变量，构建时可设置同名 build arg，build arg 仅影响构建期) |
| `PACMAN_NEW_KEYRING` | 设置后每次启动都生成新本地密钥，需要启用不安全的源时设置 |

## 目录结构

```
/data/                  # 持久化卷
├── workspace/          # 主工作目录
├── tools/              # 预置安全工具
├── codex/              # Codex 配置持久化
├── omnigent/           # Omnigent SQLite 会话、附件和 host 状态
├── cc-switch/          # cc-switch 配置持久化
└── custom.sh           # 用户自定义启动脚本（自动 source）
```

## 预装环境

- Python + uv
- C/C++ 编译环境（`base-devel` + `cmake` 等）

## 自定义扩展

基于此镜像构建专属环境：

```dockerfile
FROM rocketdev/0rays-codex-auditor:latest

RUN pacman -Syu --noconfirm python-pwntools
```

构建本镜像时如需启用海外源：

```bash
docker build --build-arg GLOBAL_MIRROR=1 -t 0rays-codex-auditor .
```

构建结束后会恢复默认源配置，最终镜像运行时仍默认禁用海外源。

为控制镜像体积，不要预装过大的工具，按需现场安装

注意动调需要给docker**加上特权**
