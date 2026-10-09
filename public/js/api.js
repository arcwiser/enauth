// ─── API Base ─────────────────────────────────────────────────────────────────
const BASE = (() => {
  const origin = window.location.origin || "";
  if (origin && origin !== "null") return "";
  return localStorage.getItem("enauth_base_url") || "http://127.0.0.1:8080";
})();

function getToken() { return Object.keys(getUser()).length ? "cookie-session" : null; }
function getUser()  {
  const raw = localStorage.getItem("enauth_user");
  if (!raw) return {};
  try {
    return JSON.parse(raw);
  } catch (err) {
    localStorage.removeItem("enauth_user");
    console.warn("Discarded corrupt enauth_user state", err);
    return {};
  }
}
function getResellerToken() { return localStorage.getItem("enauth_reseller_token"); }
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>'"]/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[char]);
}
function fmtExpiry(value) {
  return value ? fmtDate(value) : "Lifetime";
}
function getTheme() { 
  const user = getUser();
  return user.theme || localStorage.getItem("enauth_theme") || "dark";
}
async function setTheme(theme, syncServer = true) {
  const next = theme === "light" ? "light" : "dark";
  localStorage.setItem("enauth_theme", next);
  document.documentElement.setAttribute("data-theme", next);
  // Sync with server only when we already have a valid logged-in user.
  if (!syncServer || !getToken()) return;
  try {
    const u = getUser();
    if (u.id && typeof API !== "undefined" && API.updateUser) {
      await API.updateUser(u.id, { theme: next });
      localStorage.setItem("enauth_user", JSON.stringify({ ...u, theme: next }));
    }
  } catch (err) {
    console.error("Failed to sync theme with server:", err);
  }
}
function toggleTheme() {
  setTheme(getTheme() === "dark" ? "light" : "dark");
}
setTheme(getTheme(), false);

function requireAuth() {
  if (!getToken()) { window.location.href = "/panel/index.html"; }
}

function requireOwner() {
  requireAuth();
  const u = getUser();
  if (u.role !== "owner") {
    alert("Owner access required.");
    window.location.href = "/panel/dashboard.html";
  }
}

async function api(method, path, body = null) {
  const opts = {
    method,
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
  };
  if (body) opts.body = JSON.stringify(body);

  let res;
  try {
    res = await fetch(BASE + path, opts);
  } catch (err) {
    throw new Error("Panel is not up or cannot be reached right now. Please try again in a moment.");
  }

  if (res.status === 401) {
    localStorage.removeItem("enauth_user");
    window.location.href = "/panel/index.html";
    return;
  }

  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.message || `HTTP ${res.status}`);
  return data;
}

async function apiWithToken(token, method, path, body = null) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json" },
  };
  if (token) opts.headers["Authorization"] = `Bearer ${token}`;
  if (body) opts.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch(BASE + path, opts);
  } catch (err) {
    throw new Error("Panel is not up or cannot be reached right now. Please try again in a moment.");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.detail || data.message || `HTTP ${res.status}`);
  return data;
}

const API = {
  // Auth
  login:   (u, p)     => api("POST", "/api/admin/auth/login",  { username: u, password: p }),
  logout:  ()          => api("POST", "/api/admin/auth/logout"),
  me:      ()          => api("GET",  "/api/admin/auth/me"),

  // Dashboard
  dashboard: ()        => api("GET",  "/api/admin/dashboard"),
  getControlCenter: () => api("GET", "/api/admin/security/control-center"),
  revokeScopedSessions: (body) => api("POST", "/api/admin/security/sessions/revoke", body),
  emergencyLockdown: (appId, body) => api("POST", `/api/admin/security/apps/${encodeURIComponent(appId)}/lockdown`, body),

  // Licenses
  getLicenses: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/licenses${qs ? "?" + qs : ""}`);
  },
  getLicense:    (id)  => api("GET",  `/api/admin/licenses/${encodeURIComponent(id)}`),
  createLicense: (b)   => api("POST", "/api/admin/licenses", b),
  updateLicense: (id, b) => api("PUT", `/api/admin/licenses/${encodeURIComponent(id)}`, b),
  deleteLicense: (id)  => api("DELETE", `/api/admin/licenses/${encodeURIComponent(id)}`),
  banLicense:    (id)  => api("POST", `/api/admin/licenses/${encodeURIComponent(id)}/ban`),
  unbanLicense:  (id)  => api("POST", `/api/admin/licenses/${encodeURIComponent(id)}/unban`),
  resetHwid:     (id)  => api("POST", `/api/admin/licenses/${encodeURIComponent(id)}/reset-hwid`),
  extendLicense: (b)   => api("POST", "/api/admin/licenses/extend", b),
  addEntitlement: (licenseId, b) => api("POST", `/api/admin/licenses/${licenseId}/products`, b),
  removeEntitlement: (licenseId, productId) => api("DELETE", `/api/admin/licenses/${licenseId}/products/${productId}`),
  pauseEntitlement: (licenseId, productId, reason) => api("POST", `/api/admin/licenses/${licenseId}/products/${productId}/pause`, { reason }),
  resumeEntitlement: (licenseId, productId, compensation_hours = 0) => api("POST", `/api/admin/licenses/${licenseId}/products/${productId}/resume`, { compensation_hours }),
  extendEntitlement: (licenseId, productId, hours) => api("POST", `/api/admin/licenses/${licenseId}/products/${productId}/extend`, { hours }),

  // Password Reset
  requestPasswordReset: (username) => api("POST", "/api/admin/auth/password-reset/request", { username }),
  verifyPasswordReset: (token, new_password) => api("POST", "/api/admin/auth/password-reset/verify", { token, new_password }),

  // API Keys
  getApiKeys: () => api("GET", "/api/admin/api-keys"),
  createApiKey: (body) => api("POST", "/api/admin/api-keys", body),
  updateApiKey: (id, body) => api("PUT", `/api/admin/api-keys/${encodeURIComponent(id)}`, body),
  rotateApiKey: (id) => api("POST", `/api/admin/api-keys/${encodeURIComponent(id)}/rotate`),
  deleteApiKey: (id) => api("DELETE", `/api/admin/api-keys/${encodeURIComponent(id)}`),
  getSecurityEvents: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v !== "" && v != null)).toString();
    return api("GET", `/api/admin/security/events${qs ? "?" + qs : ""}`);
  },
  previewSessionRevoke: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/security/sessions/revoke-preview?${qs}`);
  },

  // Reseller Analytics
  getResellerAnalytics: (resellerId) => apiWithToken(getResellerToken(), "GET", `/api/admin/resellers/${encodeURIComponent(resellerId)}/analytics`),
  bulkDeleteLicenses:(ids)=> api("POST", "/api/admin/licenses/bulk-delete", { ids }),
  bulkBanLicenses: (ids) => api("POST", "/api/admin/licenses/bulk-ban", { ids }),
  bulkUnbanLicenses:(ids)=> api("POST", "/api/admin/licenses/bulk-unban", { ids }),

  // Bans
  getBannedHwids: ()   => api("GET",    "/api/admin/banned-hwids"),
  banHwid:        (b)   => api("POST",   "/api/admin/banned-hwids", b),
  unbanHwid: (appId, hw) => api("DELETE", `/api/admin/banned-hwids/${encodeURIComponent(appId)}/${encodeURIComponent(hw)}`),

  // Variables
  getVariables:  ()    => api("GET",    "/api/admin/variables"),
  setVariable:   (b)   => api("POST",   "/api/admin/variables", b),
  deleteVariable: (n)   => api("DELETE", `/api/admin/variables/${encodeURIComponent(n)}`),

  // News
  getNews:       (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/news${qs ? "?" + qs : ""}`);
  },
  addNews:       (b)   => api("POST",   "/api/admin/news", b),
  deleteNews:    (id)  => api("DELETE", `/api/admin/news/${encodeURIComponent(id)}`),
  bulkDeleteNews:(ids)  => api("POST", "/api/admin/news/bulk-delete", { ids }),

  // Sessions
  getSessions: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/sessions${qs ? "?" + qs : ""}`);
  },
  killSession: (id)    => api("DELETE", `/api/admin/sessions/${id}`),
  killAllSessions: ()  => api("DELETE", "/api/admin/sessions"),
  bulkKillSessions: (ids) => api("POST", "/api/admin/sessions/bulk-kill", { ids }),

  // Logs
  getLogs: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/logs${qs ? "?" + qs : ""}`);
  },
  exportLogs: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return fetch(BASE + `/api/admin/logs/export${qs ? "?" + qs : ""}`, {
      headers: { "Authorization": `Bearer ${getToken()}` },
    });
  },
  clearLogs: () => api("DELETE", "/api/admin/logs"),
  getBackups: () => api("GET", "/api/admin/backups"),
  createBackup: () => api("POST", "/api/admin/backups"),
  deleteBackup: (name) => api("DELETE", `/api/admin/backups/${encodeURIComponent(name)}`),
  downloadBackup: (name) => fetch(BASE + `/api/admin/backups/${encodeURIComponent(name)}`, { credentials: "same-origin" }),
  getDiscordIntegrations: () => api("GET", "/api/admin/discord-integrations"),
  getResponseSigningPublicKey: () => api("GET", "/api/admin/response-signing-public-key"),
  getDeveloperOverview: () => api("GET", "/api/admin/developer/overview"),
  createDiscordIntegration: (app_id) => api("POST", "/api/admin/discord-integrations", { app_id }),
  revokeDiscordIntegration: (id) => api("DELETE", `/api/admin/discord-integrations/${id}`),

  // Apps
  getApps:       (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/apps${qs ? "?" + qs : ""}`);
  },
  createApp:     (b)       => api("POST",   "/api/admin/apps", b),
  updateApp:     (id, b)   => api("PUT",    `/api/admin/apps/${id}`, b),
  deleteApp:     (id)      => api("DELETE", `/api/admin/apps/${id}`),
  bulkDeleteApps:(ids)     => api("POST", "/api/admin/apps/bulk-delete", { ids }),
  regenSecret:   (id)      => api("POST",   `/api/admin/apps/${id}/regenerate-secret`),
  pauseApp:      (id, reason) => api("POST", `/api/admin/apps/${id}/pause`, { reason }),
  resumeApp:     (id, compensation_hours = 0) => api("POST", `/api/admin/apps/${id}/resume`, { compensation_hours }),
  previewAppResume:(id, compensation_hours = 0) => api("GET", `/api/admin/apps/${id}/resume-preview?compensation_hours=${encodeURIComponent(compensation_hours)}`),
  getProducts:   ()        => api("GET",    "/api/admin/products"),
  createProduct: (b)       => api("POST",   "/api/admin/products", b),
  pauseProduct:  (id, reason) => api("POST", `/api/admin/products/${id}/pause`, { reason }),
  resumeProduct: (id, compensation_hours = 0) => api("POST", `/api/admin/products/${id}/resume`, { compensation_hours }),
  previewProductResume:(id, compensation_hours = 0) => api("GET", `/api/admin/products/${id}/resume-preview?compensation_hours=${encodeURIComponent(compensation_hours)}`),
  updateProduct: (id, b) => api("PUT", `/api/admin/products/${id}`, b),
  getProductPricing:(id)   => api("GET",    `/api/admin/products/${id}/pricing`),
  addProductPricing:(id,b) => api("POST",   `/api/admin/products/${id}/pricing`, b),
  deleteProductPricing:(productId, pricingId) => api("DELETE", `/api/admin/products/${productId}/pricing/${pricingId}`),
  deleteProduct: (id)      => api("DELETE", `/api/admin/products/${id}`),

  // Users
  getUsers:     (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/users${qs ? "?" + qs : ""}`);
  },
  createUser:   (b)       => api("POST",   "/api/admin/users", b),
  updateUser:   (id, b)   => api("PUT",    `/api/admin/users/${id}`, b),
  deleteUser:   (id)      => api("DELETE", `/api/admin/users/${id}`),
  bulkDeleteUsers:(ids)    => api("POST",   "/api/admin/users/bulk-delete", { ids }),

  // Resellers
  getResellers: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/resellers${qs ? "?" + qs : ""}`);
  },
  createReseller:(b)      => api("POST",   "/api/admin/resellers", b),
  creditReseller:(id, b)  => api("POST",   `/api/admin/resellers/${id}/credit`, b),
  getResellerProducts:(id)=> api("GET",    `/api/admin/resellers/${id}/products`),
  grantResellerProduct:(id,b)=> api("POST", `/api/admin/resellers/${id}/products`, b),
  setResellerProductQuota:(id,productId,quota)=> api("PUT", `/api/admin/resellers/${id}/products/${productId}/quota`, {product_id:productId,monthly_quota:quota}),
  getResellerPricing:(id)=> api("GET",      `/api/admin/resellers/${id}/pricing`),
  grantResellerPricing:(id,b)=> api("POST", `/api/admin/resellers/${id}/pricing`, b),
  deleteReseller:(id)      => api("DELETE", `/api/admin/resellers/${id}`),
  bulkDeleteResellers:(ids)=> api("POST",   "/api/admin/resellers/bulk-delete", { ids }),
  bulkResellerStatus:(ids, is_active) => api("POST", "/api/admin/resellers/bulk-status", { ids, is_active }),
  getResellerLedger:(id)   => api("GET",    `/api/admin/resellers/${id}/ledger`),

  // Reseller auth + actions (for testing)
  resellerLogin: (u, p)    => apiWithToken(null, "POST", "/api/admin/reseller/auth/signin", { username: u, password: p }),
  resellerProducts: (token)=> apiWithToken(token, "GET",  "/api/admin/reseller/products"),
  resellerOverview: (token)=> apiWithToken(token, "GET",  "/api/admin/reseller/overview"),
  resellerBuyKey: (token,b)=> apiWithToken(token, "POST", "/api/admin/reseller/buy-key", b),
  resellerKeys: (token)    => apiWithToken(token, "GET",  "/api/admin/reseller/keys"),
  resellerBanKey: (token, licenseId) => apiWithToken(token, "POST", `/api/admin/reseller/keys/${licenseId}/ban`),
  resellerUnbanKey: (token, licenseId) => apiWithToken(token, "POST", `/api/admin/reseller/keys/${licenseId}/unban`),
  resellerDeleteKey: (token, licenseId) => apiWithToken(token, "DELETE", `/api/admin/reseller/keys/${licenseId}`),
  resellerBulkBan: (token, ids) => apiWithToken(token, "POST", `/api/admin/reseller/keys/bulk-ban`, { license_ids: ids }),
  resellerBulkUnban: (token, ids) => apiWithToken(token, "POST", `/api/admin/reseller/keys/bulk-unban`, { license_ids: ids }),
  resellerBulkDelete: (token, ids) => apiWithToken(token, "POST", `/api/admin/reseller/keys/bulk-delete`, { license_ids: ids }),

  // App Files
  getFiles: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/files${qs ? "?" + qs : ""}`);
  },
  searchFiles: (search, params = {}) => {
    const qs = new URLSearchParams(Object.entries({ ...params, search }).filter(([,v]) => v)).toString();
    return api("GET", `/api/admin/files${qs ? "?" + qs : ""}`);
  },
  uploadFile: (formData) => {
    return fetch(BASE + "/api/admin/files", {
      method: "POST",
      headers: { "Authorization": `Bearer ${getToken()}` },
      body: formData,
    }).then(async res => {
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.detail || "Upload failed");
      return data;
    });
  },
  getLoaders: (appId = "") => api("GET", `/api/admin/loaders${appId ? `?app_id=${encodeURIComponent(appId)}` : ""}`),
  uploadLoader: (formData) => fetch(BASE + "/api/admin/loaders", {
    method: "POST", credentials: "same-origin", body: formData,
  }).then(async res => {
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.detail || "Loader upload failed");
    return data;
  }),
  deleteFile: (id) => api("DELETE", `/api/admin/files/${id}`),
  updateFileVisibility: (id, b) => api("PUT", `/api/admin/files/${id}/visibility`, b),
  revokeFile: (id, reason, block_client_version = true) => api("POST", `/api/admin/files/${id}/revoke`, { reason, block_client_version }),
  restoreFile: (id) => api("POST", `/api/admin/files/${id}/restore`),
  bulkDeleteFiles: (ids) => api("POST", "/api/admin/files/bulk-delete", { ids }),

  // Panels
  getPanels:    ()    => api("GET",    "/api/admin/panels"),
  createPanel:  (b)   => api("POST",   "/api/admin/panels", b),
  deletePanel:  (id)  => api("DELETE", `/api/admin/panels/${id}`),

  // Public User Portal
  portalGetPanel:  (panelId) => apiWithToken(null, "GET", `/api/admin/portal/panel/${panelId}`),
  portalRegister:  (b)       => apiWithToken(null, "POST", "/api/admin/portal/register", b),
  portalLogin:     (b)       => apiWithToken(null, "POST", "/api/admin/portal/login", b),
  portalGetLicense:(token)   => apiWithToken(token, "GET", "/api/admin/portal/license"),
  portalResetHwid: (token)   => apiWithToken(token, "POST", "/api/admin/portal/reset-hwid"),
  portalGetDevices:(token)   => apiWithToken(token, "GET", "/api/admin/portal/devices"),
  portalNameDevice:(token,id,name) => apiWithToken(token, "PUT", `/api/admin/portal/devices/${encodeURIComponent(id)}`, {name}),
  portalGetHistory:(token)   => apiWithToken(token, "GET", "/api/admin/portal/history"),
  portalGetResetRequests:(token) => apiWithToken(token, "GET", "/api/admin/portal/hwid-reset-requests"),
  portalRequestHwidReset:(token,reason) => apiWithToken(token, "POST", "/api/admin/portal/hwid-reset-requests", {reason}),

  // SDK release management and operations
  getOperationsHealth: () => api("GET", "/api/admin/operations/health"),
  getSdkReleases: () => api("GET", "/api/admin/sdk/releases"),
  uploadSdkRelease: (formData) => fetch(BASE + "/api/admin/sdk/releases", {method:"POST", credentials:"same-origin", body:formData}).then(async r=>{const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.detail||"SDK upload failed");return d}),
  downloadSdkRelease: (id) => fetch(BASE + `/api/admin/sdk/releases/${encodeURIComponent(id)}/download`, {credentials:"same-origin"}),
  getSdkCompatibility: () => api("GET", "/api/admin/sdk/compatibility"),
  updateSdkCompatibility: (appId,b) => api("PUT", `/api/admin/sdk/compatibility/${encodeURIComponent(appId)}`, b),
  getHwidResetRequests: (status="pending") => api("GET", `/api/admin/hwid-reset-requests?status=${encodeURIComponent(status)}`),
  reviewHwidResetRequest: (id,decision) => api("POST", `/api/admin/hwid-reset-requests/${encodeURIComponent(id)}/${encodeURIComponent(decision)}`),

  // Search and Activity
  globalSearch: (params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v !== undefined && v !== null && v !== "")).toString();
    return api("GET", `/api/admin/search${qs ? "?" + qs : ""}`);
  },
  getActivityTimeline: (entityType, entityId, params = {}) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([,v]) => v !== undefined && v !== null && v !== "")).toString();
    return api("GET", `/api/admin/activity/${encodeURIComponent(entityType)}/${encodeURIComponent(entityId)}${qs ? "?" + qs : ""}`);
  },

  // Two-Factor Authentication (TOTP)
  twoFactorSetup:  ()        => api("POST", "/api/admin/auth/2fa/setup"),
  twoFactorEnable: (code)    => api("POST", "/api/admin/auth/2fa/enable", { code }),
  twoFactorDisable:(code)    => api("POST", "/api/admin/auth/2fa/disable", { code }),
  twoFactorVerify: (temp_token, code) => apiWithToken(null, "POST", "/api/admin/auth/2fa/verify", { temp_token, code }),

  // Portal Files
  portalGetFiles:  (token)   => apiWithToken(token, "GET", "/api/admin/portal/files"),
};

// ─── Toast ─────────────────────────────────────────────────────────────────────
function toast(msg, type = "info", duration = 3500) {
  let container = document.getElementById("toast-container");
  if (!container) {
    container = document.createElement("div");
    container.id = "toast-container";
    document.body.appendChild(container);
  }
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

// ─── Clipboard ────────────────────────────────────────────────────────────────
async function copyText(text) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      toast("Copied to clipboard", "success", 1800);
      return;
    }
  } catch (e) {
    console.warn("Clipboard API failed, trying fallback...", e);
  }

  // Robust Fallback Method for insecure contexts (HTTP / local IP)
  try {
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed"; // Prevents scrolling screen to bottom
    textarea.style.top = "0";
    textarea.style.left = "0";
    textarea.style.width = "2em";
    textarea.style.height = "2em";
    textarea.style.padding = "0";
    textarea.style.border = "none";
    textarea.style.outline = "none";
    textarea.style.boxShadow = "none";
    textarea.style.background = "transparent";
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    const success = document.execCommand("copy");
    document.body.removeChild(textarea);
    if (success) {
      toast("Copied to clipboard", "success", 1800);
    } else {
      throw new Error("execCommand copy returned false");
    }
  } catch (err) {
    console.error("Copy fallback failed", err);
    toast("Copy failed", "error");
  }
}

// ─── Modal helpers ────────────────────────────────────────────────────────────
function openModal(id)  { document.getElementById(id).classList.add("open"); }
function closeModal(id) { document.getElementById(id).classList.remove("open"); }

// ─── Sidebar builder ─────────────────────────────────────────────────────────
function buildSidebar(activePage) {
  if (!document.getElementById('navigation-styles')) {
    const stylesheet = document.createElement('link');
    stylesheet.id = 'navigation-styles';
    stylesheet.rel = 'stylesheet';
    stylesheet.href = 'css/navigation.css';
    document.head.append(stylesheet);
  }
  const el = document.getElementById("sidebar");
  if (!el) return;
  const user = getUser();
  const groups = [
    ["Workspace", [["dashboard", "Overview", "grid"], ["apps", "Applications", "box"], ["products", "Product levels", "layers"], ["licenses", "Licenses", "key"]]],
    ["Distribution", [["loaders", "Loader releases", "box"], ["files", "Files", "file"], ["news", "Announcements", "message"], ["panels", "Customer panels", "window"], ["resellers", "Resellers", "users"], ["discord", "Discord bot", "message", true]]],
    ["Security", [["control", "Control center", "shield"], ["sessions", "Active sessions", "pulse"], ["bans", "Blocklist", "shield"], ["logs", "Event logs", "list"], ["audit", "Audit trail", "search"]]],
    ["Operations", [["sdk", "SDK & documentation", "code"], ["health", "Server health", "pulse"], ["requests", "Customer requests", "message"]]],
    ["Administration", [["developer", "Developer API", "code"], ["users", "Team members", "users", true], ["api-keys", "API keys", "key"], ["variables", "Variables", "code", true], ["backups", "Backups", "shield", true], ["settings", "Settings", "settings"]]]
  ];
  const paths = {
    grid: '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    box: '<path d="m12 3 9 5v8l-9 5-9-5V8Z M3 8l9 5 9-5 M12 13v8 M7 5.8l9 5"/>',
    layers: '<path d="m12 3 10 5-10 5L2 8Z M2 12l10 5 10-5 M2 16l10 5 10-5"/>',
    key: '<circle cx="8" cy="9" r="5"/><path d="m12 13 8 8m-4-4 3-3m-6 0 3-3"/>',
    file: '<path d="M14 3H5v18h14V8Zm0 0v5h5 M8 13h8 M8 17h5"/>',
    message: '<path d="M4 4h16v12H9l-5 4Z M8 8h8 M8 12h5"/>',
    window: '<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18 M8 9v11"/>',
    users: '<circle cx="9" cy="8" r="3"/><path d="M3 21v-3a6 6 0 0 1 12 0v3 M16 5a3 3 0 0 1 0 6 M18 15a5 5 0 0 1 3 5"/>',
    pulse: '<path d="M2 12h5l3-8 4 16 3-8h5"/>',
    shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z M8 12h8"/>',
    list: '<path d="M9 5h12 M9 12h12 M9 19h12 M3 5h1 M3 12h1 M3 19h1"/>',
    search: '<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6"/>',
    code: '<path d="m8 6-6 6 6 6 M16 6l6 6-6 6 M14 3l-4 18"/>',
    settings: '<path d="M3 6h18 M3 12h18 M3 18h18"/><circle cx="8" cy="6" r="2"/><circle cx="16" cy="12" r="2"/><circle cx="8" cy="18" r="2"/>'
  };
  const icon = name => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + paths[name] + '</svg>';
  el.classList.add('workspace-sidebar');
  el.innerHTML = '<a class="workspace-brand" href="dashboard.html"><span class="brand-mark">e<span>.</span></span><span>enauth<small>CONTROL CENTER</small></span></a>' +
    '<div class="workspace-label"><span class="workspace-dot"></span> Management console<span class="workspace-tag">PRO</span></div>' +
    '<label class="nav-search">' + icon('search') + '<input type="search" placeholder="Find a page…" aria-label="Filter navigation" autocomplete="off"><kbd>/</kbd></label>' +
    '<nav class="workspace-nav" aria-label="Main navigation">' + groups.map(([label, items]) => '<section class="nav-group"><h2>' + label + '</h2>' + items.filter(item => !item[3] || user.role === 'owner').map(([page, label, glyph]) => '<a class="workspace-link' + (page === activePage ? ' is-current' : '') + '" href="' + page + '.html"' + (page === activePage ? ' aria-current="page"' : '') + '>' + icon(glyph) + '<span>' + label + '</span>' + (page === activePage ? '<span class="current-dot"></span>' : '') + '</a>').join('') + '</section>').join('') + '<p class="nav-empty" hidden>No matching pages</p></nav>' +
    '<footer class="workspace-footer"><div class="workspace-account"><span class="account-avatar"></span><span><strong class="account-name"></strong><small class="account-role"></small></span><a href="settings.html" aria-label="Account settings">' + icon('settings') + '</a></div><div class="workspace-actions"><button type="button" class="theme-action">◐ <span>Appearance</span></button><button type="button" class="signout-action">↗ <span>Sign out</span></button></div></footer>';
  el.querySelector('.account-name').textContent = user.username || 'Admin';
  el.querySelector('.account-role').textContent = user.role || 'admin';
  el.querySelector('.account-avatar').textContent = (user.username || 'A').slice(0, 1).toUpperCase();
  el.querySelector('.theme-action').onclick = toggleTheme;
  el.querySelector('.signout-action').onclick = doLogout;
  const input = el.querySelector('input');
  input.oninput = () => {
    let visible = 0;
    el.querySelectorAll('.nav-group').forEach(group => {
      let count = 0;
      group.querySelectorAll('a').forEach(link => {
        link.hidden = !link.textContent.toLowerCase().includes(input.value.trim().toLowerCase());
        if (!link.hidden) count++;
      });
      group.hidden = count === 0;
      visible += count;
    });
    el.querySelector('.nav-empty').hidden = visible !== 0;
  };
  document.querySelector('.menu-trigger')?.remove();
  document.querySelector('.menu-backdrop')?.remove();
  const trigger = document.createElement('button');
  trigger.className = 'menu-trigger';
  trigger.type = 'button';
  trigger.textContent = '☰';
  trigger.setAttribute('aria-label', 'Open navigation');
  trigger.setAttribute('aria-controls', 'sidebar');
  trigger.setAttribute('aria-expanded', 'false');
  document.querySelector('.topbar')?.prepend(trigger);
  const backdrop = document.createElement('button');
  backdrop.className = 'menu-backdrop';
  backdrop.setAttribute('aria-label', 'Close navigation');
  backdrop.tabIndex = -1;
  document.body.append(backdrop);
  const mobile = window.matchMedia('(max-width: 900px)');
  const setOpen = open => {
    document.body.classList.toggle('navigation-open', open);
    trigger.setAttribute('aria-expanded', String(open));
    trigger.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
    el.inert = mobile.matches && !open;
    if (open) input.focus(); else trigger.focus();
  };
  el.inert = mobile.matches;
  mobile.addEventListener('change', () => { el.inert = mobile.matches && !document.body.classList.contains('navigation-open'); });
  trigger.onclick = () => setOpen(!document.body.classList.contains('navigation-open'));
  backdrop.onclick = () => setOpen(false);
  document.addEventListener('keydown', event => {
    if (event.key === 'Escape' && document.body.classList.contains('navigation-open')) setOpen(false);
    if (event.key === '/' && !event.ctrlKey && !event.metaKey && !event.altKey && !event.target.matches('input,textarea,select,[contenteditable="true"]')) {
      event.preventDefault();
      if (mobile.matches) setOpen(true); else input.focus();
    }
    if (event.key === 'Tab' && mobile.matches && document.body.classList.contains('navigation-open')) {
      const elements = [...el.querySelectorAll('a,button,input')].filter(node => node.getClientRects().length);
      const first = elements[0], last = elements[elements.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    }
  });
}

async function doLogout() {
  try { await API.logout(); } catch {}
  localStorage.clear();
  window.location.href = "/panel/index.html";
}

// ─── Date formatting ──────────────────────────────────────────────────────────
function fmtDate(d) {
  if (!d) return "—";
  const dateObj = new Date(d + (d.includes("Z") ? "" : "Z"));
  const y = dateObj.getFullYear();
  const m = String(dateObj.getMonth() + 1).padStart(2, '0');
  const day = String(dateObj.getDate()).padStart(2, '0');
  const hh = String(dateObj.getHours()).padStart(2, '0');
  const mm = String(dateObj.getMinutes()).padStart(2, '0');
  return `${y}-${m}-${day} ${hh}:${mm}`;
}

function relTime(d) {
  if (!d) return "—";
  const diff = Date.now() - new Date(d + (d.includes("Z") ? "" : "Z")).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

// ─── Status badge ─────────────────────────────────────────────────────────────
function statusBadge(status) {
  const map = {
    active:  "badge-active",
    banned:  "badge-banned",
    expired: "badge-expired",
  };
  return `<span class="badge ${map[status] || "badge-active"}">${status}</span>`;
}

function roleBadge(role) {
  const map = {
    owner: "badge-owner",
    admin: "badge-admin",
    moderator: "badge-mod",
  };
  return `<span class="badge ${map[role] || "badge-admin"}">${role}</span>`;
}
