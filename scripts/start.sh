#!/bin/bash

# ---- 1. 密码 ----
PASSWORD="${PASSWORD:-0raysnb}"
echo "root:${PASSWORD}" | chpasswd 2>/dev/null

# ---- 2. 把当前所有需要的环境变量写成静态 KV 文件 ----
ENV_FILE="/etc/audit-env"
cat > "$ENV_FILE" << EOF
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8
export CODEX_HOME="/data/codex/"
EOF

# 如果启动时设置了OPENAI_API_KEY, 则写入env文件, bash启动时可以使用
if [ -n "${OPENAI_API_KEY}" ]; then
    echo "export OPENAI_API_KEY=\"${OPENAI_API_KEY}\"" >> "$ENV_FILE"
fi

# 如果设置了OPENAI_BASE_URL, 并且为首次启动, 则填充, 否则替换
CODEX_CFG="/data/codex/config.toml"
if [ -n "${OPENAI_BASE_URL}" ]; then
    if [ ! -f "$CODEX_CFG" ]; then
        cat > "$CODEX_CFG" << TOML
model_provider = "docker-env"
model = "gpt-5.4"
model_reasoning_effort = "high"

[model_providers.docker-env]
name = "docker-env"
base_url = "${OPENAI_BASE_URL}"
env_key = "OPENAI_API_KEY"
wire_api = "responses"

[features]
multi_agent = true

[[skills.config]]
path = "/data/skills"
enabled = true
TOML
        echo "[+] Generated $CODEX_CFG"
    else
        sed -i "s|^base_url = .*|base_url = \"${OPENAI_BASE_URL}\"|" "$CODEX_CFG"
        echo "[+] Updated base_url in $CODEX_CFG"
    fi
fi

# 代理（只在非空时写入）
if [ -n "${PROXY}" ]; then
    cat >> "$ENV_FILE" << EOF
export PROXY="${PROXY}"
export HTTP_PROXY="${PROXY}"
export HTTPS_PROXY="${PROXY}"
export http_proxy="${PROXY}"
export https_proxy="${PROXY}"
export NO_PROXY="${NO_PROXY:-localhost,127.0.0.1,172.16.0.0/12,10.0.0.0/8}"
export no_proxy="\${NO_PROXY}"
EOF
    git config --global http.proxy "${PROXY}" 2>/dev/null
fi

chmod 644 "$ENV_FILE"

# HTTP端认证
echo "root:$(openssl passwd -6 "$PASSWORD")" > /etc/nginx/.htpasswd
echo "[+] htpasswd file generated"

# ---- 3. 用户自定义 ----
[ -f /data/custom.sh ] && source /data/custom.sh || echo "[!] custom.sh failed, continuing..."

# ---- 4. 启动服务 ----
export LANG=zh_CN.UTF-8
export LC_ALL=zh_CN.UTF-8

/usr/sbin/nginx && echo "[+] nginx started on :8981"
/usr/sbin/sshd && echo "[+] sshd started on :8982"

FB_DB="/data/.filebrowser.db"
if [ ! -f "$FB_DB" ]; then
    echo "[+] filebrowser: first run, initializing..."
    filebrowser config init -d "$FB_DB"
    filebrowser users add root "0raysnb-default" -d "$FB_DB" --perm.admin
    filebrowser config set -d "$FB_DB" --baseURL /files --root /data/ --auth.method=noauth
else
    echo "[+] filebrowser: using existing database"
fi

filebrowser -d "$FB_DB" &
echo "[+] filebrowser started on :8080/files/"

echo "[+] ttyd started on :7681"
exec ttyd --writable -c "root:${PASSWORD}" -t 'unicodeVersion=11' /tmux.sh
