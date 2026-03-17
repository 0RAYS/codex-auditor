#!/bin/bash
SESSION_NAME="audit"

# 已经在 tmux 里了，直接给 shell
if [ -n "${TMUX}" ]; then
    exec bash --login
fi

# 清理 dead session 并 attach 或新建
if tmux has-session -t "${SESSION_NAME}" 2>/dev/null; then
    if ! tmux list-sessions 2>/dev/null | grep -q "^${SESSION_NAME}:"; then
        tmux kill-session -t "${SESSION_NAME}" 2>/dev/null
        exec tmux new-session -s "${SESSION_NAME}" -c /data/workspace
    fi
    exec tmux attach-session -t "${SESSION_NAME}"
else
    exec tmux new-session -s "${SESSION_NAME}" -c /data/workspace
fi
