const state = {
  targets: [],
  selectedTargetId: null,
  selectedSessionId: null,
  messages: [],
  theme: document.body.dataset.theme || (document.body.classList.contains("dark") ? "dark" : "light"),
  polling: null,
  thinkingTimer: null,
};

const els = {
  themeToggle: document.getElementById("themeToggle"),
  newTargetButton: document.getElementById("newTargetButton"),
  targetTree: document.getElementById("targetTree"),
  vulnerabilityMeta: document.getElementById("vulnerabilityMeta"),
  vulnerabilityRows: document.getElementById("vulnerabilityRows"),
  refreshVulnerabilities: document.getElementById("refreshVulnerabilities"),
  messages: document.getElementById("messages"),
  messageForm: document.getElementById("messageForm"),
  messageInput: document.getElementById("messageInput"),
  sendButton: document.getElementById("sendButton"),
  stopButton: document.getElementById("stopButton"),
  targetModal: document.getElementById("targetModal"),
  targetForm: document.getElementById("targetForm"),
  targetName: document.getElementById("targetName"),
  targetNote: document.getElementById("targetNote"),
  targetExpandBox: document.getElementById("targetExpandBox"),
  targetExpanded: document.getElementById("targetExpanded"),
  expandTargetNote: document.getElementById("expandTargetNote"),
  copyTargetExpanded: document.getElementById("copyTargetExpanded"),
  noteModal: document.getElementById("noteModal"),
  noteForm: document.getElementById("noteForm"),
  noteModalTitle: document.getElementById("noteModalTitle"),
  noteText: document.getElementById("noteText"),
  noteExpandBox: document.getElementById("noteExpandBox"),
  noteExpanded: document.getElementById("noteExpanded"),
  expandExistingNote: document.getElementById("expandExistingNote"),
  copyNoteExpanded: document.getElementById("copyNoteExpanded"),
  debugModal: document.getElementById("debugModal"),
  debugForm: document.getElementById("debugForm"),
  debugModalTitle: document.getElementById("debugModalTitle"),
  debugName: document.getElementById("debugName"),
  debugPrompt: document.getElementById("debugPrompt"),
  debugStart: document.getElementById("debugStart"),
  toast: document.getElementById("toast"),
};

const acknowledgingInterventions = new Set();

function api(path, options = {}) {
  const headers = options.headers || {};
  if (options.body && !(options.body instanceof FormData)) headers["Content-Type"] = "application/json";
  return fetch(`api${path}`, {
    ...options,
    headers,
    body: options.body && !(options.body instanceof FormData) ? JSON.stringify(options.body) : options.body,
  }).then(async (response) => {
    const payload = await response.json().catch(() => ({}));
    if (!response.ok || payload.ok === false) throw new Error(payload.error || `${response.status} ${response.statusText}`);
    return payload;
  });
}

function showToast(message) {
  els.toast.textContent = message;
  els.toast.classList.remove("hidden");
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => els.toast.classList.add("hidden"), 4200);
}

function applyTheme(theme) {
  state.theme = theme === "dark" ? "dark" : "light";
  document.body.classList.toggle("dark", state.theme === "dark");
  const label = state.theme === "dark" ? "切换到亮色" : "切换到暗色";
  els.themeToggle.title = label;
  els.themeToggle.setAttribute("aria-label", label);
  els.themeToggle.innerHTML = iconSvg(state.theme === "dark" ? "sun" : "moon");
}

function allSessions() {
  return state.targets.flatMap((target) => target.sessions || []);
}

function currentTarget() {
  return state.targets.find((target) => Number(target.id) === Number(state.selectedTargetId)) || null;
}

function currentSession() {
  return allSessions().find((session) => Number(session.id) === Number(state.selectedSessionId)) || null;
}

function isBusySession(session) {
  return session?.status === "running";
}

function sessionDisplayTitle(session) {
  const name = (session.name || "").trim();
  if (!name || name === session.session_type) return session.session_type;
  return `${session.session_type} · ${name}`;
}

function sessionSidebarTitle(session) {
  return session.session_type === "mining" ? "M" : "D";
}

function sessionSidebarText(session) {
  const bugIds = (session.bug_ids || "").trim();
  return bugIds ? `${sessionSidebarTitle(session)} ${bugIds}` : sessionSidebarTitle(session);
}

function setSelected(targetId, sessionId, persist = true) {
  state.selectedTargetId = targetId ? Number(targetId) : null;
  state.selectedSessionId = sessionId ? Number(sessionId) : null;
  renderTree();
  renderChatShell();
  loadMessages();
  resetVulnerabilities();
  loadVulnerabilities();
  if (persist) {
    api("/settings", {
      method: "PATCH",
      body: {
        selected_target_id: state.selectedTargetId || "",
        selected_session_id: state.selectedSessionId || "",
      },
    }).catch((error) => showToast(error.message));
  }
}

function renderTree() {
  els.targetTree.innerHTML = "";
  if (!state.targets.length) {
    const empty = document.createElement("div");
    empty.className = "tree-empty";
    empty.textContent = "暂无目标";
    els.targetTree.appendChild(empty);
    return;
  }
  state.targets.forEach((target) => {
    const group = document.createElement("section");
    group.className = `target-group color-${target.color || "green"}${Number(target.id) === Number(state.selectedTargetId) ? " active" : ""}`;

    const row = document.createElement("div");
    row.className = "target-row";
    const select = document.createElement("button");
    select.type = "button";
    select.className = "target-select";
    select.addEventListener("click", () => {
      const firstSession = (target.sessions || [])[0];
      setSelected(target.id, firstSession?.id || null);
    });
    select.innerHTML = `<span class="target-dot"></span><span class="target-title"></span><span class="target-meta"></span>`;
    select.querySelector(".target-title").textContent = target.name;
    const sessionCount = (target.sessions || []).length;
    const schedulerLabel = target.auto_mining_state === "frozen" ? "冻结" : "运行";
    select.querySelector(".target-meta").textContent = `${schedulerLabel} · ${sessionCount} session${sessionCount === 1 ? "" : "s"}`;

    const scheduler = document.createElement("button");
    scheduler.type = "button";
    const frozen = target.auto_mining_state === "frozen";
    scheduler.className = `tree-icon${frozen ? " target-resume" : ""}`;
    scheduler.title = frozen ? "恢复自动挖掘" : "冻结自动挖掘";
    scheduler.setAttribute("aria-label", scheduler.title);
    scheduler.innerHTML = iconSvg(frozen ? "play" : "snowflake");
    scheduler.addEventListener("click", () => toggleTargetScheduler(target));

    const add = document.createElement("button");
    add.type = "button";
    add.className = "tree-icon";
    add.title = "新建 debug session";
    add.setAttribute("aria-label", "新建 debug session");
    add.innerHTML = iconSvg("plus");
    add.addEventListener("click", () => openDebugModal(target));

    const edit = document.createElement("button");
    edit.type = "button";
    edit.className = "tree-icon";
    edit.title = "更新补充说明";
    edit.setAttribute("aria-label", "更新补充说明");
    edit.innerHTML = iconSvg("settings");
    edit.addEventListener("click", () => openNoteModal(target));

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "tree-icon target-delete";
    remove.title = "删除目标";
    remove.setAttribute("aria-label", "删除目标");
    remove.innerHTML = iconSvg("x");
    remove.addEventListener("click", () => deleteTarget(target));

    row.append(select, scheduler, add, edit, remove);
    group.appendChild(row);

    const sessions = document.createElement("div");
    sessions.className = "session-children";
    (target.sessions || []).forEach((session) => {
      const item = document.createElement("div");
      item.className = `session-leaf${Number(session.id) === Number(state.selectedSessionId) ? " active" : ""}`;
      const selectSession = document.createElement("button");
      selectSession.type = "button";
      selectSession.className = "session-select";
      selectSession.addEventListener("click", () => setSelected(target.id, session.id));
      selectSession.innerHTML = '<span class="session-text"></span>';
      selectSession.querySelector(".session-text").textContent = sessionSidebarText(session);

      const status = document.createElement("button");
      status.type = "button";
      status.className = `session-status ${session.status || "finished"}`;
      const deletable = session.status !== "running";
      status.disabled = !deletable;
      status.title = deletable ? "删除 session" : "running session 不能删除";
      status.setAttribute("aria-label", status.title);
      if (deletable) status.addEventListener("click", () => deleteSession(session));

      item.append(selectSession, status);
      sessions.appendChild(item);
    });
    group.appendChild(sessions);
    els.targetTree.appendChild(group);
  });
}

function renderChatShell() {
  const session = currentSession();
  if (!session) {
    els.messageInput.disabled = true;
    els.sendButton.disabled = true;
    els.stopButton.disabled = true;
    els.messages.innerHTML = "";
    return;
  }
  const running = session.status === "running";
  const busy = isBusySession(session);
  els.messageInput.disabled = busy;
  els.sendButton.disabled = busy;
  els.stopButton.disabled = !running;
}

function renderMessages() {
  const nearBottom = els.messages.scrollTop + els.messages.clientHeight >= els.messages.scrollHeight - 80;
  els.messages.innerHTML = "";
  const session = currentSession();
  const visible = normalizeVisibleMessages(state.messages);
  if (!visible.length && session?.status !== "running") {
    const empty = document.createElement("div");
    empty.className = "message system";
    empty.innerHTML = '<div class="bubble">等待消息</div>';
    els.messages.appendChild(empty);
    return;
  }
  visible.forEach((message) => {
    const item = document.createElement("div");
    item.className = `message ${message.role}`;
    const bubble = document.createElement("div");
    bubble.className = "bubble";
    const kind = message.kind && message.kind !== "message" ? `[${message.kind}] ` : "";
    const content = document.createElement("div");
    content.textContent = `${kind}${message.content}`;
    bubble.appendChild(content);
    const timestamp = messageTimestamp(message);
    if (timestamp) {
      const meta = document.createElement("div");
      meta.className = "message-time";
      meta.textContent = timestamp;
      bubble.appendChild(meta);
    }
    item.appendChild(bubble);
    els.messages.appendChild(item);
  });
  if (session?.status === "running") appendThinkingMessage(session);
  if (nearBottom) els.messages.scrollTop = els.messages.scrollHeight;
}

function messageTimestamp(message) {
  if (!["user", "assistant"].includes(message.role) || !message.created_at) return "";
  return formatTimestamp(message.created_at);
}

function formatTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  const pad = (number) => String(number).padStart(2, "0");
  return [
    date.getFullYear(),
    pad(date.getMonth() + 1),
    pad(date.getDate()),
  ].join("-") + ` ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

function normalizeVisibleMessages(messages) {
  return messages.filter(
    (message) => ["user", "assistant", "system"].includes(message.role)
      && !["run", "vulnerability", "tool_call", "event"].includes(message.kind),
  );
}

function appendThinkingMessage(session) {
  const item = document.createElement("div");
  item.className = "message system thinking";
  const bubble = document.createElement("div");
  bubble.className = "bubble";
  const content = document.createElement("div");
  content.className = "thinking-content";
  content.textContent = thinkingText(session);
  bubble.appendChild(content);
  item.appendChild(bubble);
  els.messages.appendChild(item);
}

function updateThinkingMessage() {
  const session = currentSession();
  const content = els.messages.querySelector(".thinking-content");
  if (!content || session?.status !== "running") return;
  content.textContent = thinkingText(session);
}

function thinkingText(session) {
  const startedAt = latestUserMessageStartedAt() || new Date(session.updated_at || session.created_at || Date.now()).getTime();
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
  return `已运行 ${formatDuration(elapsedSeconds)}`;
}

function latestUserMessageStartedAt() {
  for (let index = state.messages.length - 1; index >= 0; index -= 1) {
    const message = state.messages[index];
    if (message.role !== "user" || !message.created_at) continue;
    const startedAt = new Date(message.created_at).getTime();
    if (!Number.isNaN(startedAt)) return startedAt;
  }
  return null;
}

function formatDuration(totalSeconds) {
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes >= 60) return `${Math.floor(minutes / 60)}h${minutes % 60}m${seconds}s`;
  if (minutes > 0) return `${minutes}m${seconds}s`;
  return `${seconds}s`;
}

function renderVulnerabilities(payload) {
  els.vulnerabilityRows.innerHTML = "";
  if (payload.available === false) {
    els.vulnerabilityMeta.textContent = `读取失败 · ${payload.path || ""}`;
    const row = emptyRow(payload.error || "known_findings.md 读取失败");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "icon-button repair-button";
    button.title = "请求 AI 修复汇总";
    button.setAttribute("aria-label", "请求 AI 修复汇总");
    button.innerHTML = repairWrenchSvg();
    button.addEventListener("click", repairVulnerabilities);
    row.firstChild.append(document.createElement("br"), button);
    els.vulnerabilityRows.appendChild(row);
    return;
  }
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const target = currentTarget();
  els.vulnerabilityMeta.textContent = target ? `${target.name} · ${findings.length} 条 · ${payload.path || ""}` : "未选择目标";
  if (!findings.length) {
    els.vulnerabilityRows.appendChild(emptyRow("暂无漏洞"));
    return;
  }
  findings.forEach((finding) => {
    const row = document.createElement("tr");
    row.append(
      textCell(finding.bug_id || ""),
      textCell(finding.summary || ""),
      textCell(finding.bug_type || ""),
      ratingCell(finding),
      textCell(finding.source_files || ""),
    );
    els.vulnerabilityRows.appendChild(row);
  });
}

function textCell(value) {
  const cell = document.createElement("td");
  cell.textContent = value;
  return cell;
}

function ratingCell(finding) {
  const cell = document.createElement("td");
  const value = finding.security_rating || "unknown";
  const badge = document.createElement("button");
  badge.type = "button";
  badge.className = `severity ${["low", "medium", "high"].includes(value) ? value : "unknown"}`;
  badge.textContent = value;
  badge.addEventListener("click", () => {
    const select = document.createElement("select");
    select.className = "rating-select";
    ["low", "medium", "high"].forEach((rating) => {
      const option = document.createElement("option");
      option.value = rating;
      option.textContent = rating;
      option.selected = rating === value;
      select.appendChild(option);
    });
    if (value === "unknown") select.value = "medium";
    select.addEventListener("change", () => saveVulnerabilityRating(finding, select.value));
    select.addEventListener("blur", () => {
      if (select.isConnected) select.replaceWith(badge);
    });
    badge.replaceWith(select);
    select.focus();
  });
  cell.appendChild(badge);
  return cell;
}

function emptyRow(message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = 5;
  cell.className = "empty-cell";
  cell.textContent = message;
  row.appendChild(cell);
  return row;
}

function resetVulnerabilities() {
  const target = currentTarget();
  if (!target) {
    els.vulnerabilityMeta.textContent = "未选择目标";
    els.vulnerabilityRows.innerHTML = '<tr><td colspan="5" class="empty-cell">暂无数据</td></tr>';
    return;
  }
  els.vulnerabilityMeta.textContent = `${target.name} · 正在读取 known_findings.md`;
  els.vulnerabilityRows.innerHTML = '<tr><td colspan="5" class="empty-cell">正在读取漏洞列表</td></tr>';
}

async function loadVulnerabilities() {
  const target = currentTarget();
  if (!target) return resetVulnerabilities();
  const targetId = Number(target.id);
  try {
    const payload = await api(`/targets/${targetId}/vulnerabilities`);
    if (Number(state.selectedTargetId) !== targetId) return;
    renderVulnerabilities(payload);
  } catch (error) {
    renderVulnerabilities({ available: false, error: error.message });
  }
}

async function loadMessages() {
  const session = currentSession();
  if (!session) {
    state.messages = [];
    renderMessages();
    return;
  }
  const payload = await api(`/sessions/${session.id}/messages`);
  state.messages = payload.messages || [];
  renderMessages();
}

async function loadState() {
  const payload = await api("/state");
  state.targets = payload.targets || [];
  applyTheme(payload.settings?.theme || "light");
  const selectedTarget = payload.settings?.selected_target_id;
  const selectedSession = payload.settings?.selected_session_id;
  if (state.targets.some((target) => String(target.id) === String(selectedTarget))) {
    state.selectedTargetId = Number(selectedTarget);
  } else if (!state.targets.some((target) => Number(target.id) === Number(state.selectedTargetId))) {
    state.selectedTargetId = state.targets.length ? Number(state.targets[0].id) : null;
  }
  const sessions = allSessions();
  if (sessions.some((session) => String(session.id) === String(selectedSession))) {
    state.selectedSessionId = Number(selectedSession);
  } else if (!sessions.some((session) => Number(session.id) === Number(state.selectedSessionId))) {
    const target = currentTarget();
    state.selectedSessionId = Number((target?.sessions || [])[0]?.id || sessions[0]?.id || 0) || null;
  }
  if (state.selectedSessionId) {
    const session = currentSession();
    if (session) state.selectedTargetId = Number(session.target_id);
  }
  renderTree();
  renderChatShell();
  showInterventionNotices();
  resetVulnerabilities();
  await loadVulnerabilities();
}

async function refreshStateOnly() {
  const previousSession = state.selectedSessionId;
  const payload = await api("/state");
  state.targets = payload.targets || [];
  if (state.selectedSessionId && !allSessions().some((session) => Number(session.id) === Number(state.selectedSessionId))) {
    const target = currentTarget() || state.targets[0];
    state.selectedTargetId = target ? Number(target.id) : null;
    state.selectedSessionId = Number((target?.sessions || [])[0]?.id || 0) || null;
  }
  renderTree();
  renderChatShell();
  showInterventionNotices();
  if (Number(previousSession) !== Number(state.selectedSessionId)) {
    resetVulnerabilities();
    await loadVulnerabilities();
  }
}

async function toggleTargetScheduler(target) {
  const next = target.auto_mining_state === "frozen" ? "running" : "frozen";
  try {
    await api(`/targets/${target.id}/scheduler-state`, { method: "PATCH", body: { state: next } });
    await refreshStateOnly();
  } catch (error) {
    showToast(error.message);
  }
}

function showInterventionNotices() {
  state.targets.forEach((target) => {
    if (!target.intervention_required || target.intervention_notice_read) return;
    if (acknowledgingInterventions.has(target.id)) return;
    acknowledgingInterventions.add(target.id);
    window.setTimeout(async () => {
      const reason = target.intervention_reason || "未提供原因";
      window.alert(`目标 ${target.name} 需要人为介入：\n${reason}`);
      try {
        await api(`/targets/${target.id}/intervention/ack`, { method: "POST" });
        await refreshStateOnly();
      } catch (error) {
        showToast(error.message);
      } finally {
        acknowledgingInterventions.delete(target.id);
      }
    }, 0);
  });
}

async function poll() {
  try {
    await refreshStateOnly();
    await loadMessages();
  } catch (error) {
    showToast(error.message);
  }
}

function openTargetModal() {
  els.targetForm.reset();
  els.targetExpandBox.classList.add("hidden");
  els.targetModal.showModal();
  els.targetName.focus();
}

function openNoteModal(target) {
  state.selectedTargetId = Number(target.id);
  els.noteModalTitle.textContent = `更新补充说明 · ${target.name}`;
  els.noteText.value = target.note || "";
  els.noteExpanded.value = "";
  els.noteExpandBox.classList.add("hidden");
  els.noteModal.showModal();
  els.noteText.focus();
}

function openDebugModal(target) {
  state.selectedTargetId = Number(target.id);
  els.debugForm.reset();
  els.debugStart.checked = true;
  els.debugModalTitle.textContent = `新建 debug session · ${target.name}`;
  els.debugModal.showModal();
  els.debugName.focus();
}

async function repairVulnerabilities() {
  const session = currentSession();
  if (!session || isBusySession(session)) return;
  try {
    await api(`/sessions/${session.id}/repair-vulnerabilities`, { method: "POST" });
    await poll();
  } catch (error) {
    showToast(error.message);
  }
}

async function saveVulnerabilityRating(finding, rating) {
  const target = currentTarget();
  if (!target) return;
  try {
    const payload = await api(`/targets/${target.id}/vulnerabilities/${encodeURIComponent(finding.row_id)}`, {
      method: "PATCH",
      body: { fingerprint: finding.fingerprint, security_rating: rating },
    });
    renderVulnerabilities(payload);
  } catch (error) {
    showToast(error.message);
    await loadVulnerabilities();
  }
}

async function deleteTarget(target) {
  const confirmed = window.confirm(
    `确定删除目标 ${target.name}？这会删除数据库记录和对应工作区目录，且无法撤销。`,
  );
  if (!confirmed) return;
  try {
    await api(`/targets/${target.id}`, { method: "DELETE" });
    if (Number(state.selectedTargetId) === Number(target.id)) {
      state.selectedTargetId = null;
      state.selectedSessionId = null;
      state.messages = [];
    }
    await loadState();
    await loadMessages();
  } catch (error) {
    showToast(error.message);
  }
}

async function deleteSession(session) {
  if (session.status === "running") return;
  const confirmed = window.confirm(`确定删除 session ${sessionDisplayTitle(session)}？这会删除该 session 的消息和运行记录。`);
  if (!confirmed) return;
  try {
    await api(`/sessions/${session.id}`, { method: "DELETE" });
    if (Number(state.selectedSessionId) === Number(session.id)) {
      state.selectedSessionId = null;
      state.messages = [];
    }
    await loadState();
    await loadMessages();
  } catch (error) {
    showToast(error.message);
  }
}

function iconSvg(name) {
  if (name === "snowflake") {
    return `
      <svg class="button-icon" xmlns="http://w3.org" viewBox="-70 -70 140 140" aria-hidden="true">
        <defs>
          <path id="branch" d="M 0,0 L 0,-60 M 0,-35 L 20,-52 M 0,-35 L -20,-52" />
        </defs>
        <style>
          .flake {
            stroke: #00b4d8;
            stroke-width: 4;
            stroke-linecap: round;
            fill: none;
          }
        </style>
        <g class="flake">
          <use href="#branch" transform="rotate(0)" />
          <use href="#branch" transform="rotate(60)" />
          <use href="#branch" transform="rotate(120)" />
          <use href="#branch" transform="rotate(180)" />
          <use href="#branch" transform="rotate(240)" />
          <use href="#branch" transform="rotate(300)" />
        </g>
      </svg>
    `;
  }
  const paths = {
    plus: '<path d="M12 5v14M5 12h14"></path>',
    play: '<path d="M8 5.5v13l10-6.5-10-6.5Z" fill="currentColor" stroke="none"></path>',
    settings: '<circle cx="12" cy="12" r="3"></circle><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6a1.7 1.7 0 0 0 1-1.6v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z"></path>',
    x: '<path d="m6 6 12 12M18 6 6 18"></path>',
    wrench: '<path d="M14.7 6.3a4 4 0 0 0-5-5L12 3.6 9.6 6 7.3 3.7a4 4 0 0 0 5 5L20 16.4a2.1 2.1 0 0 1-3 3l-7.7-7.7"></path>',
    moon: '<path d="M20.5 14.3A8.5 8.5 0 0 1 9.7 3.5 8.5 8.5 0 1 0 20.5 14.3Z"></path>',
    sun: '<circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path>',
  };
  return `<svg class="button-icon" viewBox="0 0 24 24" aria-hidden="true">${paths[name]}</svg>`;
}

function repairWrenchSvg() {
  return `
    <svg class="button-icon repair-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M15.4 5.1a5 5 0 0 0-5.8-1.2l3 3-3.1 3.1-3-3a5 5 0 0 0 6.4 6.4l5.8 5.8a2.1 2.1 0 0 0 3-3l-5.8-5.8a5 5 0 0 0-.5-5.3Z"></path>
      <path d="M18.4 17.6l1.2 1.2"></path>
    </svg>
  `;
}

els.themeToggle.addEventListener("click", async () => {
  const next = state.theme === "dark" ? "light" : "dark";
  applyTheme(next);
  try {
    await api("/settings", { method: "PATCH", body: { theme: next } });
  } catch (error) {
    showToast(error.message);
  }
});

els.newTargetButton.addEventListener("click", openTargetModal);

document.querySelectorAll("[data-close]").forEach((button) => {
  button.addEventListener("click", () => document.getElementById(button.dataset.close)?.close());
});

els.targetForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const payload = await api("/targets", {
      method: "POST",
      body: {
        name: els.targetName.value,
        note: els.targetNote.value,
      },
    });
    els.targetModal.close();
    await loadState();
    setSelected(payload.target.id, payload.session.id);
  } catch (error) {
    showToast(error.message);
  }
});

els.expandTargetNote.addEventListener("click", async () => {
  els.expandTargetNote.disabled = true;
  els.targetExpandBox.classList.remove("hidden");
  els.targetExpanded.value = "生成中...";
  try {
    const payload = await api("/targets/expand-note", {
      method: "POST",
      body: { name: els.targetName.value, note: els.targetNote.value },
    });
    els.targetExpanded.value = payload.expanded || "";
  } catch (error) {
    els.targetExpanded.value = `生成失败：${error.message}`;
  } finally {
    els.expandTargetNote.disabled = false;
  }
});

els.copyTargetExpanded.addEventListener("click", () => {
  els.targetNote.value = els.targetExpanded.value;
});

els.noteForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = currentTarget();
  if (!target) return;
  try {
    await api(`/targets/${target.id}`, { method: "PATCH", body: { note: els.noteText.value } });
    els.noteModal.close();
    await loadState();
  } catch (error) {
    showToast(error.message);
  }
});

els.expandExistingNote.addEventListener("click", async () => {
  const target = currentTarget();
  if (!target) return;
  els.expandExistingNote.disabled = true;
  els.noteExpandBox.classList.remove("hidden");
  els.noteExpanded.value = "生成中...";
  try {
    const payload = await api(`/targets/${target.id}/expand-note`, {
      method: "POST",
      body: { note: els.noteText.value },
    });
    els.noteExpanded.value = payload.expanded || "";
  } catch (error) {
    els.noteExpanded.value = `生成失败：${error.message}`;
  } finally {
    els.expandExistingNote.disabled = false;
  }
});

els.copyNoteExpanded.addEventListener("click", () => {
  els.noteText.value = els.noteExpanded.value;
});

els.debugForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = currentTarget();
  if (!target) return;
  try {
    const payload = await api(`/targets/${target.id}/sessions`, {
      method: "POST",
      body: {
        name: els.debugName.value,
        prompt: els.debugPrompt.value,
        start: els.debugStart.checked,
      },
    });
    els.debugModal.close();
    await loadState();
    setSelected(target.id, payload.session.id);
  } catch (error) {
    showToast(error.message);
  }
});

els.messageForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const session = currentSession();
  const content = els.messageInput.value.trim();
  if (!session || isBusySession(session) || !content) return;
  els.messageInput.value = "";
  try {
    await api(`/sessions/${session.id}/messages`, { method: "POST", body: { content } });
    await poll();
  } catch (error) {
    showToast(error.message);
  }
});

els.stopButton.addEventListener("click", async () => {
  const session = currentSession();
  if (!session || session.status !== "running") return;
  try {
    await api(`/sessions/${session.id}/stop`, { method: "POST" });
    await poll();
  } catch (error) {
    showToast(error.message);
  }
});

els.refreshVulnerabilities.addEventListener("click", loadVulnerabilities);

window.addEventListener("load", async () => {
  try {
    await loadState();
    await loadMessages();
    state.polling = window.setInterval(poll, 2500);
    state.thinkingTimer = window.setInterval(updateThinkingMessage, 1000);
  } catch (error) {
    showToast(error.message);
  }
});
