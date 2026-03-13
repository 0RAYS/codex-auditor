FROM archlinux:base-devel

LABEL maintainer="RocketDev"
LABEL description="Codex-based binary code audit"

# 1) pacman 镜像
COPY mirrorlist /etc/pacman.d/mirrorlist
COPY archlinuxcn-mirrorlist /etc/pacman.d/archlinuxcn-mirrorlist

# 2) 基础软件（尽量使用官方源）
RUN pacman -Syu --noconfirm \
    ca-certificates wget curl git openssh ttyd supervisor nginx openssl shadow \
    vim ripgrep tree jq bat less file starship util-linux \
    cmake pkgconf meson ninja abseil-cpp go qemu-full \
    unzip p7zip xz bzip2 tar zip libarchive tmux lrzsz \
    binutils strace lsof clang llvm-libs cppcheck patchelf \
    python python-pip uv openai-codex procps-ng ipython \
    afl++ bear boost-libs debuginfod pwndbg libc++ \
    zsh zsh-syntax-highlighting zsh-autosuggestions \
    net-tools iproute2 openbsd-netcat sudo rsync \
    && pacman -Scc --noconfirm

RUN sed -i 's/#\(Color\)/\1/;s/^\(NoProgressBar\)/#\1/' /etc/pacman.conf && \
    sed -i 's/^MAKEFLAGS=.*/MAKEFLAGS="-j"/' /etc/makepkg.conf && \
    printf '[archlinuxcn]\nInclude = /etc/pacman.d/archlinuxcn-mirrorlist\n' >> /etc/pacman.conf

RUN pacman-key --init && \
    pacman -Sy archlinuxcn-keyring archlinux-keyring --noconfirm && \
    pacman -Syu --noconfirm yay filebrowser && \
    pacman -Scc --noconfirm
RUN useradd -m builder && \
    echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
COPY scripts/yay.sh /usr/local/sbin/yay
RUN chmod +x /usr/local/sbin/yay

# 3) 额外二进制工具
ADD https://github.com/SaladDay/cc-switch-cli/releases/download/v4.7.0/cc-switch-cli-linux-x64-musl.tar.gz /tmp/ccs.tar.gz
ADD https://github.com/krallin/tini/releases/download/v0.19.0/tini-amd64 /usr/bin/tini
RUN tar -xzf /tmp/ccs.tar.gz -C /usr/bin cc-switch && rm /tmp/ccs.tar.gz && chmod +x /usr/bin/tini

# 4) 目录结构
RUN mkdir -p /data/workspace /data/codex /data/tools /data/cc-switch && \
    ln -sfn /data/codex/ /root/.codex && \
    ln -sfn /data/cc-switch/ /root/.cc-switch

COPY skills/ /data/skills/

# 5) SSH 配置
RUN mkdir -p /run/sshd && \
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/^#*Port .*/Port 8982/' /etc/ssh/sshd_config && \
    ssh-keygen -A

# 6) 脚本 & 配置文件
COPY configs/supervisord.conf /etc/supervisord.conf
COPY configs/nginx.conf /etc/nginx/nginx.conf
COPY scripts/init /init
COPY scripts/tmux.sh /tmux.sh
COPY scripts/sudo.zsh /root/.sudo.zsh
COPY configs/zshrc /root/.zshrc
COPY configs/tmux.conf /root/.tmux.conf
COPY configs/vimrc /root/.vimrc
COPY configs/gdbinit /root/.gdbinit
COPY vim-plugins.tar.zst /tmp/vim-plugins.tar.zst
COPY AGENTS.md /data/codex/AGENTS.md
RUN chmod +x /init /tmux.sh && touch /root/.bash_profile && chsh -s /usr/bin/zsh root && \
    bsdtar -xf /tmp/vim-plugins.tar.zst -C /root

# 7) 清理
RUN rm -rf /tmp/* /var/tmp/* && history -c 2>/dev/null; true

# 8) 写入history便于使用
RUN echo 'codex --dangerously-bypass-approvals-and-sandbox -m gpt-5.4' > /root/.histfile

EXPOSE 8981 8982
WORKDIR /data/workspace
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/init"]
