// ─── API Base ─────────────────────────────────────────────────────────────────
const BASE = "";

function getToken() { return localStorage.getItem("enauth_token"); }
function getUser()  { return JSON.parse(localStorage.getItem("enauth_user") || "{}"); }
function getResellerToken() { return localStorage.getItem("enauth_reseller_token"); }
function getTheme() { return localStorage.getItem("enauth_theme") || "dark"; }
function setTheme(theme) {
  const next = theme === "light" ? "light" : "dark";
  localStorage.setItem("enauth_theme", next);
  document.documentElement.setAttribute("data-theme", next);
}
function toggleTheme() {
  setTheme(getTheme() === "dark" ? "light" : "dark");
}
setTheme(getTheme());

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
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${getToken()}`,
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
    localStorage.clear();
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
  signup:  (u, p)      => api("POST", "/api/admin/auth/signup", { username: u, password: p }),
  signin:  (u, p)      => api("POST", "/api/admin/auth/signin", { username: u, password: p }),
  me:      ()          => api("GET",  "/api/admin/auth/me"),

  // Dashboard
  dashboard: ()        => api("GET",  "/api/admin/dashboard"),

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
  getProducts:   ()        => api("GET",    "/api/admin/products"),
  createProduct: (b)       => api("POST",   "/api/admin/products", b),
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
  getResellerPricing:(id)=> api("GET",      `/api/admin/resellers/${id}/pricing`),
  grantResellerPricing:(id,b)=> api("POST", `/api/admin/resellers/${id}/pricing`, b),
  deleteReseller:(id)      => api("DELETE", `/api/admin/resellers/${id}`),
  bulkDeleteResellers:(ids)=> api("POST",   "/api/admin/resellers/bulk-delete", { ids }),
  bulkResellerStatus:(ids, is_active) => api("POST", "/api/admin/resellers/bulk-status", { ids, is_active }),
  getResellerLedger:(id)   => api("GET",    `/api/admin/resellers/${id}/ledger`),

  // Reseller auth + actions (for testing)
  resellerLogin: (u, p)    => apiWithToken(null, "POST", "/api/admin/reseller/auth/signin", { username: u, password: p }),
  resellerProducts: (token)=> apiWithToken(token, "GET",  "/api/admin/reseller/products"),
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
  deleteFile: (id) => api("DELETE", `/api/admin/files/${id}`),
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
  const user = getUser();
  const isOwner = user.role === "owner";
  const nav = [
    { href: "dashboard.html", icon: "📊", label: "Dashboard",   page: "dashboard" },
    { href: "apps.html",      icon: "📦", label: "Apps",        page: "apps"      },
    { href: "panels.html",    icon: "🌐", label: "User Panels", page: "panels"    },
    { href: "products.html",  icon: "🧩", label: "Levels",      page: "products"  },
    { href: "licenses.html",  icon: "🔑", label: "Licenses",    page: "licenses"  },
    { href: "files.html",     icon: "📁", label: "App Files",   page: "files"     },
    { href: "sessions.html",  icon: "🔗", label: "Sessions",    page: "sessions"  },
    { href: "bans.html",      icon: "🚫", label: "Bans",        page: "bans"      },
    { href: "news.html",      icon: "📢", label: "News",        page: "news"      },
    { href: "variables.html", icon: "🧪", label: "Variables",   page: "variables", ownerOnly: true },
    { href: "resellers.html", icon: "🤝", label: "Resellers",   page: "resellers" },
    { href: "logs.html",      icon: "📋", label: "Logs",        page: "logs"      },
    { href: "audit.html",     icon: "🔎", label: "Audit",       page: "audit"     },
    { href: "users.html",     icon: "👥", label: "Users",       page: "users",     ownerOnly: true },
    { href: "settings.html",  icon: "⚙️", label: "Settings",   page: "settings"  },
  ].filter(n => !n.ownerOnly || isOwner);

  const html = `
    <div class="sidebar-logo">
      <div class="logo-icon">E</div>
      <div class="logo-text">ENAUTH</div>
    </div>
    <nav class="sidebar-nav">
      <div class="nav-section">Navigation</div>
      ${nav.map(n => `
        <a class="nav-item ${activePage === n.page ? "active" : ""}" href="${n.href}">
          <span class="nav-icon">${n.icon}</span> ${n.label}
        </a>`).join("")}
    </nav>
    <div class="sidebar-footer">
      <div class="sidebar-user">
        <div class="user-avatar">${(user.username || "?")[0].toUpperCase()}</div>
        <div class="user-info">
          <div class="user-name">${user.username || "Admin"}</div>
          <div class="user-role">${user.role || "admin"}</div>
        </div>
      </div>
      <button class="sidebar-logout" onclick="toggleTheme()">☼ Toggle Theme</button>
      <button class="sidebar-logout" onclick="doLogout()">⬅ Sign Out</button>
    </div>`;

  const el = document.getElementById("sidebar");
  if (el) el.innerHTML = html;
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
