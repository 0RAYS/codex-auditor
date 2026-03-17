FROM rocketdev/0rays-codex-auditor:latest

RUN sed -i '/^#\\[multilib\\]$/,/^$/{s/^#//}' /etc/pacman.conf && \
    pacman -Syu --noconfirm \
    python-pwntools python-redis python-protobuf python-paho-mqtt protobuf-c \
    paho-mqtt-c msgpack-c python-lief lib32-glibc lib32-gcc-libs json-c \
    json-glib jsoncpp ceccomp boost-libs && \
    pacman -Scc --noconfirm

RUN git clone https://github.com/matrix1001/glibc-all-in-one.git /root/glibc-all-in-one --depth 1

COPY configs/nginx.conf /etc/nginx/nginx.conf
COPY configs/supervisord.conf /etc/supervisord.conf
COPY configs/debian.urls /etc/debuginfod/
COPY scripts/tmux.sh /tmux.sh
COPY scripts/init /init
COPY configs/pwn.conf /root/.pwn.conf
RUN chmod +x /tmux.sh /init
