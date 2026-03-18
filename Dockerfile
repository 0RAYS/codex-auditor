FROM ubuntu:24.04

LABEL maintainer="int_barbituric"
LABEL description="Codex-based code audit / CTF workstation"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    # 基础
    ca-certificates wget curl git openssh-server tmux locales xxd ttyd nginx \
    # 编辑器
    vim \
    # 搜索 & 文本
    ripgrep fd-find tree jq bat less file \
    # 网络
    net-tools netcat-openbsd socat \
    # 压缩
    unzip p7zip-full xz-utils bzip2 tar zip \
    # Python
    python3 python3-pip \
    # Java
    openjdk-17-jre-headless \
    # PHP
    php8.3-cli php8.3-curl php8.3-xml php8.3-mbstring \
    # Node.js
    nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# 3. 基础环境
ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64 /usr/bin/tini
ADD https://github.com/filebrowser/filebrowser/releases/latest/download/linux-amd64-filebrowser.tar.gz /tmp/fb.tar.gz
RUN tar -xzf /tmp/fb.tar.gz -C /usr/bin filebrowser && rm /tmp/fb.tar.gz
RUN chmod +x /usr/bin/ttyd /usr/bin/tini /usr/bin/filebrowser

RUN locale-gen zh_CN.UTF-8 && update-locale LANG=zh_CN.UTF-8

COPY scripts/nginx.conf /etc/nginx/nginx.conf

# 4. Codex
RUN npm i -g @openai/codex@latest

# 5. Python 常用库 & 审计工具
RUN pip install --break-system-packages --no-cache-dir \
    requests \
    beautifulsoup4 \
    semgrep

# 6. 目录结构
# 根据官方文档, /etc/codex/skills用来存储skills
RUN mkdir -p /data/workspace /data/codex /data/tools /data/skills /etc/codex
RUN ln -sfn /data/codex/ /root/.codex
RUN ln -sfn /data/skills/ /etc/codex/skills

# 7a. 下载审计工具
ADD https://github.com/frohoff/ysoserial/releases/download/v0.0.6/ysoserial-all.jar \
    /data/tools/ysoserial.jar

# 7b. 安装 PHP Composer
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/bin --filename=composer

# 7c. 手动构建完工具目录后复制进容器
COPY tools/ /data/tools/
COPY skills/ /data/skills/

# 8. SSH 配置
RUN mkdir -p /run/sshd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*Port .*/Port 8982/' /etc/ssh/sshd_config && \
    ssh-keygen -A

# 9. 脚本 & 配置文件
COPY scripts/start.sh /start.sh
COPY scripts/tmux.sh /tmux.sh
COPY AGENTS.md /data/codex/AGENTS.md
RUN chmod +x /start.sh /tmux.sh

# 10. .bashrc 注入
RUN sed -i '1i\# Auto-attach tmux\nif [[ $- == *i* ]] && [ -z "${TMUX}" ]; then\n    exec /tmux.sh\nfi\n' /root/.bashrc && \
    echo '[ -f /etc/audit-env ] && source /etc/audit-env' >> /root/.bashrc && \
    echo '[ -f /data/custom.sh ] && source /data/custom.sh' >> /root/.bashrc

# 11. 清理
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* && history -c 2>/dev/null; true

# 12. 写入history便于使用
RUN echo 'codex --dangerously-bypass-approvals-and-sandbox' > /root/.bash_history

# 元数据
EXPOSE 8981 8982
WORKDIR /data/workspace
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
