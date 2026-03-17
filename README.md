# 0RAYS codex web codeaudit

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
  christarcher/0rays-codex-client:latest
```

需要注意的是, 如果/data如果不挂载, 存储的配置会丢失.

## 访问方式

| 方式 | 地址 |
|---|---|
| Web 终端 | `http://<host>:8981` |
| SSH | `ssh root@<host> -p 8982` |

默认密码通过 `PASSWORD` 环境变量设置，未设置时为 `0raysnb`。

## 环境变量 

如果通过docker启动时的环境变量传递, 且同时设置了`OPENAI_API_KEY`和`OPENAI_BASE_URL`, 则会自动填充到codex的config.toml, 具体逻辑可以参考 `scripts/start.sh`

| 变量 | 说明 |
|---|---|
| `OPENAI_API_KEY` | Codex 使用的 APIKey |
| `OPENAI_BASE_URL` | API 地址, 格式为https://placeholder.com/v1 |
| `PASSWORD` | SSH 和终端的 root 密码 (默认为0raysnb) |
| `PROXY` | HTTP/HTTPS 代理地址 (可选) |

## 目录结构

```
/data/                  # 持久化卷
├── workspace/          # 主工作目录
├── tools/              # 预置安全工具
├── codex/              # Codex 配置持久化
└── custom.sh           # 用户自定义启动脚本（自动 source）
```

## 预装环境

- Python 3 + pip（pycryptodome, gmpy2, sympy, requests, bs4）
- Node.js + npm
- OpenJDK 8
- C/C++ 编译环境（build-essential, cmake）
- 包管理源已配置国内镜像（npm → npmmirror, pip → 清华源）
