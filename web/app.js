"use strict";

const state = {
  authenticated: false,
  passwordConfigured: false,
  folders: [],
};

const elements = {
  connection: document.querySelector("#connection"),
  loginView: document.querySelector("#login-view"),
  loginForm: document.querySelector("#login-form"),
  loginPassword: document.querySelector("#login-password"),
  loginError: document.querySelector("#login-error"),
  workspace: document.querySelector("#workspace"),
  logoutButton: document.querySelector("#logout-button"),
  settingsForm: document.querySelector("#settings-form"),
  password: document.querySelector("#password"),
  passwordConfirm: document.querySelector("#password-confirm"),
  exemptIps: document.querySelector("#exempt-ips"),
  passwordState: document.querySelector("#password-state"),
  clearPasswordButton: document.querySelector("#clear-password-button"),
  folderForm: document.querySelector("#folder-form"),
  folderId: document.querySelector("#folder-id"),
  folderName: document.querySelector("#folder-name"),
  folderPath: document.querySelector("#folder-path"),
  folderInclude: document.querySelector("#folder-include"),
  folderExclude: document.querySelector("#folder-exclude"),
  folderLinkMode: document.querySelector("#folder-link-mode"),
  folderLinkField: document.querySelector("#folder-link-field"),
  folderLink: document.querySelector("#folder-link"),
  folderPeers: document.querySelector("#folder-peers"),
  folderAutoSync: document.querySelector("#folder-auto-sync"),
  folderSyncInterval: document.querySelector("#folder-sync-interval"),
  folderSubmitButton: document.querySelector("#folder-submit-button"),
  folderCancelButton: document.querySelector("#folder-cancel-button"),
  folderList: document.querySelector("#folder-list"),
  refreshFoldersButton: document.querySelector("#refresh-folders-button"),
  generateKeyForm: document.querySelector("#generate-key-form"),
  readWriteKey: document.querySelector("#read-write-key"),
  inspectKeyForm: document.querySelector("#inspect-key-form"),
  inspectKeyValue: document.querySelector("#inspect-key-value"),
  toolOutput: document.querySelector("#tool-output"),
  toast: document.querySelector("#toast"),
};

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers: {
      Accept: "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json")
    ? await response.json()
    : { error: { message: await response.text() } };
  if (!response.ok) {
    const error = new Error(payload.error?.message || `请求失败 (${response.status})`);
    error.status = response.status;
    error.code = payload.error?.code;
    throw error;
  }
  return payload;
}

function setConnection(text, kind = "") {
  elements.connection.textContent = text;
  elements.connection.className = `status-badge ${kind}`.trim();
}

function showLogin(message = "") {
  state.authenticated = false;
  elements.loginView.classList.remove("hidden");
  elements.workspace.classList.add("hidden");
  elements.logoutButton.classList.add("hidden");
  elements.loginError.textContent = message;
  elements.loginPassword.focus();
}

function showWorkspace() {
  state.authenticated = true;
  elements.loginView.classList.add("hidden");
  elements.workspace.classList.remove("hidden");
  elements.logoutButton.classList.remove("hidden");
}

function showToast(message, error = false) {
  elements.toast.textContent = message;
  elements.toast.className = `toast${error ? " error" : ""}`;
  window.clearTimeout(showToast.timer);
  showToast.timer = window.setTimeout(() => elements.toast.classList.add("hidden"), 4200);
}

async function loadStatus() {
  try {
    const status = await api("/api/v1/status");
    state.passwordConfigured = status.password_configured;
    setConnection(status.authenticated ? "已连接" : "需要登录", status.authenticated ? "ok" : "");
    if (status.authenticated) {
      showWorkspace();
      await Promise.all([loadSettings(), loadFolders()]);
    } else {
      showLogin();
    }
  } catch (error) {
    setConnection("连接失败", "error");
    showLogin(error.message);
  }
}

async function loadSettings() {
  const settings = await api("/api/v1/settings");
  state.passwordConfigured = settings.password_configured;
  elements.exemptIps.value = settings.password_exempt_ips.join("\n");
  elements.passwordState.textContent = settings.password_configured ? "密码已设置" : "未设置密码";
  elements.passwordState.className = `status-badge${settings.password_configured ? " ok" : ""}`;
  elements.clearPasswordButton.disabled = !settings.password_configured;
}

async function loadFolders() {
  const result = await api("/api/v1/folders");
  state.folders = result.folders;
  renderFolders();
}

function renderFolders() {
  if (!state.folders.length) {
    elements.folderList.innerHTML = '<div class="empty-state">还没有注册同步文件夹。</div>';
    return;
  }
  elements.folderList.innerHTML = "";
  for (const folder of state.folders) {
    const row = document.createElement("article");
    row.className = `folder-row${folder.enabled ? "" : " disabled"}`;

    const name = document.createElement("div");
    name.className = "folder-name";
    name.textContent = folder.name;

    const path = document.createElement("div");
    path.className = "folder-path";
    path.textContent = folder.path;

    const meta = document.createElement("div");
    meta.className = "folder-meta";
    const scanText = folder.last_scan
      ? `${folder.last_scan.file_count} 个文件 · ${formatBytes(folder.last_scan.total_file_size)}`
      : folder.enabled ? "尚未扫描" : "已停用";
    const syncText = folder.sync
      ? `${folder.sync.access === "read-write" ? "读写" : folder.sync.access === "encrypted-only" ? "加密" : "只读"} · ${folder.sync.peers.length} 个节点`
      : "仅扫描";
    const lastSyncText = folder.last_sync
      ? ` · 上次同步${folder.last_sync.status === "success" ? "成功" : folder.last_sync.status === "error" ? "失败" : folder.last_sync.status === "partial" ? "部分成功" : "中"}`
      : "";
    meta.textContent = `${scanText} · ${syncText}${lastSyncText}`;

    const keyList = document.createElement("div");
    keyList.className = "folder-keys";
    const derivedKeys = folder.sync?.keys || {};
    const keyRoles = [
      ["read_write", "读写密钥"],
      ["read_only", "只读密钥"],
      ["encrypted", "加密密钥"],
    ];
    for (const [role, label] of keyRoles) {
      const value = derivedKeys[role];
      if (!value) {
        continue;
      }
      const keyRow = document.createElement("div");
      keyRow.className = "folder-key";
      const keyLabel = document.createElement("span");
      keyLabel.textContent = label;
      const keyValue = document.createElement("code");
      keyValue.textContent = value;
      keyRow.append(keyLabel, keyValue, iconButton("⧉", `复制${label}`, () => copyKey(value)));
      keyList.append(keyRow);
    }

    if (folder.sync) {
      const autoLabel = document.createElement("label");
      autoLabel.className = "auto-toggle";
      const autoInput = document.createElement("input");
      autoInput.type = "checkbox";
      autoInput.checked = folder.sync.auto_sync;
      autoInput.title = "自动同步";
      autoInput.addEventListener("change", () => updateAutoSync(folder, autoInput.checked));
      const autoText = document.createElement("span");
      autoText.textContent = "自动";
      autoLabel.append(autoInput, autoText);
      meta.append(autoLabel);
    }

    const actions = document.createElement("div");
    actions.className = "row-actions";
    actions.append(
      iconButton("↻", "扫描", () => scanFolder(folder.id)),
      ...(folder.sync
        ? [
            iconButton("⇄", "立即同步", () => syncFolder(folder.id)),
          ]
        : []),
      iconButton(folder.enabled ? "Ⅱ" : "▶", folder.enabled ? "停用" : "启用", () =>
        toggleFolder(folder),
      ),
      iconButton("✎", "编辑", () => editFolder(folder)),
      iconButton("×", "删除", () => deleteFolder(folder)),
    );

    row.append(name, path, meta, keyList, actions);
    elements.folderList.append(row);
  }
}

function iconButton(symbol, label, action) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "icon-button";
  button.textContent = symbol;
  button.title = label;
  button.setAttribute("aria-label", label);
  button.addEventListener("click", action);
  return button;
}

async function copyKey(value) {
  if (!value) {
    return;
  }
  await navigator.clipboard?.writeText(value);
  elements.toolOutput.textContent = value;
  showToast("密钥已复制。");
}

function editFolder(folder) {
  elements.folderId.value = folder.id;
  elements.folderName.value = folder.name;
  elements.folderPath.value = folder.path;
  elements.folderInclude.value = folder.include || "";
  elements.folderExclude.value = folder.exclude || "";
  elements.folderLinkMode.value = folder.sync ? "import" : "generate-rw";
  elements.folderLinkMode.disabled = Boolean(folder.sync);
  elements.folderLinkField.classList.add("hidden");
  elements.folderLink.required = false;
  elements.folderLink.value = "";
  elements.folderPeers.value = folder.sync?.peers.join(", ") || "";
  elements.folderAutoSync.checked = folder.sync?.auto_sync || false;
  elements.folderSyncInterval.value = folder.sync?.sync_interval_seconds || 300;
  elements.folderSubmitButton.textContent = "保存文件夹";
  elements.folderCancelButton.classList.remove("hidden");
  elements.folderForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

function resetFolderForm() {
  elements.folderForm.reset();
  elements.folderId.value = "";
  elements.folderLinkMode.disabled = false;
  elements.folderLinkMode.value = "generate-rw";
  elements.folderLinkField.classList.add("hidden");
  elements.folderLink.required = false;
  elements.folderAutoSync.checked = false;
  elements.folderSyncInterval.value = 300;
  elements.folderSubmitButton.textContent = "添加文件夹";
  elements.folderCancelButton.classList.add("hidden");
}

async function scanFolder(id) {
  try {
    const result = await api(`/api/v1/folders/${id}/scan`, { method: "POST" });
    showToast(`扫描完成，共 ${result.scan.file_count} 个文件。`);
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function deleteFolder(folder) {
  if (!window.confirm(`确定删除文件夹“${folder.name}”吗？磁盘文件不会被删除。`)) {
    return;
  }
  try {
    await api(`/api/v1/folders/${folder.id}`, { method: "DELETE" });
    showToast("文件夹已删除。");
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function toggleFolder(folder) {
  try {
    await api(`/api/v1/folders/${folder.id}`, {
      method: "PUT",
      body: JSON.stringify({ enabled: !folder.enabled }),
    });
    showToast(folder.enabled ? "文件夹已停用。" : "文件夹已启用。");
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
}

async function syncFolder(id) {
  try {
    await api(`/api/v1/folders/${id}/sync`, { method: "POST" });
    showToast("手动同步已启动。");
    await pollSyncStatus(id);
  } catch (error) {
    showToast(error.message, true);
  }
}

async function pollSyncStatus(id) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    await new Promise((resolve) => window.setTimeout(resolve, 1000));
    try {
      const result = await api(`/api/v1/folders/${id}/sync`);
      if (!result.running) {
        const run = result.last_sync;
        showToast(run?.message || `同步${run?.status === "success" ? "完成" : "结束"}。`, run?.status === "error");
        await loadFolders();
        return;
      }
    } catch (error) {
      showToast(error.message, true);
      return;
    }
  }
  await loadFolders();
}

async function updateAutoSync(folder, enabled) {
  try {
    await api(`/api/v1/folders/${folder.id}/sync`, {
      method: "PUT",
      body: JSON.stringify({
        auto_sync: enabled,
        sync_interval_seconds: folder.sync?.sync_interval_seconds || 300,
        peers: folder.sync?.peers || [],
      }),
    });
    showToast(enabled ? "自动同步已启用。" : "自动同步已停用。");
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
    await loadFolders();
  }
}

async function generateFolderLink(id, access) {
  try {
    const result = await api(`/api/v1/folders/${id}/links/generate`, {
      method: "POST",
      body: JSON.stringify({ access }),
    });
    const link = result.folder.link;
    await navigator.clipboard?.writeText(link);
    elements.toolOutput.textContent = link;
    elements.toolOutput.scrollIntoView({ behavior: "smooth", block: "center" });
    showToast(`${access === "read-write" ? "读写" : "只读"}链接已生成并复制。`);
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
}

function formatBytes(value) {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
}

elements.loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  elements.loginError.textContent = "";
  try {
    await api("/api/v1/auth/login", {
      method: "POST",
      body: JSON.stringify({ password: elements.loginPassword.value }),
    });
    elements.loginPassword.value = "";
    await loadStatus();
  } catch (error) {
    elements.loginError.textContent = error.message;
  }
});

elements.logoutButton.addEventListener("click", async () => {
  try {
    await api("/api/v1/auth/logout", { method: "POST" });
  } finally {
    showLogin();
    setConnection("已退出", "");
  }
});

elements.settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const password = elements.password.value;
  if (password && password !== elements.passwordConfirm.value) {
    showToast("两次输入的新密码不一致。", true);
    return;
  }
  const payload = {
    password_exempt_ips: elements.exemptIps.value
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter(Boolean),
  };
  if (password) {
    payload.password = password;
  }
  try {
    await api("/api/v1/settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    });
    elements.password.value = "";
    elements.passwordConfirm.value = "";
    await loadSettings();
    showToast("访问设置已保存。");
  } catch (error) {
    showToast(error.message, true);
  }
});

elements.clearPasswordButton.addEventListener("click", async () => {
  if (!window.confirm("确定清除访问密码吗？免密 IP 之外的客户端也将可以访问。")) {
    return;
  }
  try {
    await api("/api/v1/password", { method: "DELETE" });
    await loadSettings();
    showToast("访问密码已清除。");
  } catch (error) {
    showToast(error.message, true);
  }
});

elements.folderForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const payload = {
    name: elements.folderName.value,
    path: elements.folderPath.value,
    include: elements.folderInclude.value,
    exclude: elements.folderExclude.value,
  };
  const id = elements.folderId.value;
  const peers = elements.folderPeers.value
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const sync = {
    peers,
    auto_sync: elements.folderAutoSync.checked,
    sync_interval_seconds: Number(elements.folderSyncInterval.value),
  };
  if (!id) {
    if (elements.folderLinkMode.value === "import") {
      sync.link = elements.folderLink.value.trim();
    } else {
      sync.access = "read-write";
    }
    payload.sync = sync;
  } else if (state.folders.some((folder) => folder.id === id && folder.sync)) {
    payload.sync = sync;
  }
  try {
    if (id) {
      await api(`/api/v1/folders/${id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      showToast("文件夹设置已更新。");
    } else {
      const result = await api("/api/v1/folders", {
        method: "POST",
        body: JSON.stringify({ ...payload, enabled: true }),
      });
      if (result.folder.link) {
        await navigator.clipboard?.writeText(result.folder.link);
        elements.toolOutput.textContent = result.folder.link;
        showToast("文件夹已添加，共享链接已生成并复制。");
      } else {
        showToast("文件夹已添加。");
      }
    }
    resetFolderForm();
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
});

elements.folderLinkMode.addEventListener("change", () => {
  const importing = elements.folderLinkMode.value === "import";
  elements.folderLinkField.classList.toggle("hidden", !importing);
  elements.folderLink.required = importing;
});

elements.folderCancelButton.addEventListener("click", resetFolderForm);
elements.refreshFoldersButton.addEventListener("click", loadFolders);

elements.generateKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/api/v1/operations/keys/generate", {
      method: "POST",
      body: JSON.stringify({ read_write: elements.readWriteKey.checked }),
    });
    elements.toolOutput.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    elements.toolOutput.textContent = error.message;
  }
});

elements.inspectKeyForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    const result = await api("/api/v1/operations/keys/inspect", {
      method: "POST",
      body: JSON.stringify({ key: elements.inspectKeyValue.value }),
    });
    elements.toolOutput.textContent = JSON.stringify(result, null, 2);
  } catch (error) {
    elements.toolOutput.textContent = error.message;
  }
});

loadStatus();
