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
    meta.textContent = folder.last_scan
      ? `${folder.last_scan.file_count} 个文件 · ${formatBytes(folder.last_scan.total_file_size)}`
      : folder.enabled
        ? "尚未扫描"
        : "已停用";

    const actions = document.createElement("div");
    actions.className = "row-actions";
    actions.append(
      iconButton("↻", "扫描", () => scanFolder(folder.id)),
      iconButton(folder.enabled ? "Ⅱ" : "▶", folder.enabled ? "停用" : "启用", () =>
        toggleFolder(folder),
      ),
      iconButton("✎", "编辑", () => editFolder(folder)),
      iconButton("×", "删除", () => deleteFolder(folder)),
    );

    row.append(name, path, meta, actions);
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

function editFolder(folder) {
  elements.folderId.value = folder.id;
  elements.folderName.value = folder.name;
  elements.folderPath.value = folder.path;
  elements.folderInclude.value = folder.include || "";
  elements.folderExclude.value = folder.exclude || "";
  elements.folderSubmitButton.textContent = "保存文件夹";
  elements.folderCancelButton.classList.remove("hidden");
  elements.folderForm.scrollIntoView({ behavior: "smooth", block: "start" });
}

function resetFolderForm() {
  elements.folderForm.reset();
  elements.folderId.value = "";
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
  try {
    if (id) {
      await api(`/api/v1/folders/${id}`, {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      showToast("文件夹设置已更新。");
    } else {
      await api("/api/v1/folders", {
        method: "POST",
        body: JSON.stringify({ ...payload, enabled: true }),
      });
      showToast("文件夹已添加。");
    }
    resetFolderForm();
    await loadFolders();
  } catch (error) {
    showToast(error.message, true);
  }
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
