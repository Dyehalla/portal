const $ = (id) => document.getElementById(id);
const number = new Intl.NumberFormat("ru-RU");
const tokenStorageKey = "portal.local-api-token";
let token = "";
let session = 0;
let snapshot = null;
let selectedKey = null;
let stale = false;
let account = null;
let accountStale = false;
let registering = false;
let accountBusy = false;
let policyTarget = null;
let policyRevision = 0;
let policyDirty = false;
let policyBusy = false;
let policyLoaded = false;
let ownerBusy = false;
let bulkPlan = null;
let bulkBusy = false;
let bulkRefreshing = false;
let terminalSocket = null;
let terminalInstance = null;
let filePath = [];
let fileBusy = false;
const knownPolicies = new Map();
const connectErrors = new Map();
let receivedAt = 0;
let pollTimer;
let toastTimer;
let refreshing = false;
let mapExpired = false;
const requests = new Set();
const connecting = new Set();

$("auth-address").textContent = location.host;
$("api-address").textContent = location.host;

function showError(element, message) {
  element.textContent = message || "";
  element.hidden = !message;
}

function toast(message, error = false) {
  clearTimeout(toastTimer);
  $("toast").textContent = message;
  $("toast").classList.toggle("error", error);
  $("toast").hidden = false;
  toastTimer = setTimeout(() => {
    $("toast").hidden = true;
  }, 6000);
}

async function api(path, body, credential = token) {
  const controller = new AbortController();
  requests.add(controller);
  const timer = setTimeout(
    () => controller.abort(),
    body?.operation === "connect" || path.startsWith("account") || path === "terminal/session" ? 40000 : 8000,
  );
  try {
    const headers = { Authorization: `Bearer ${credential}` };
    if (body) headers["Content-Type"] = "application/json";
    const response = await fetch(`/api/v1/${path}`, {
      method: body ? "POST" : "GET",
      headers,
      ...(body ? { body: JSON.stringify(body) } : {}),
      signal: controller.signal,
      cache: "no-store",
      credentials: "omit",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const error = new Error(
        response.status === 401
          ? "Токен не принят. Проверьте токен локального API этого агента."
          : data.message || `Ошибка API: HTTP ${response.status}`,
      );
      error.status = response.status;
      throw error;
    }
    return data;
  } catch (error) {
    if (error instanceof TypeError || error.name === "AbortError") {
      throw new Error(
        "Агент не отвечает. Проверьте, что portal запущен.",
      );
    }
    throw error;
  } finally {
    clearTimeout(timer);
    requests.delete(controller);
  }
}

function signOut(message = "") {
  session++;
  token = "";
  accessSignature = ""; seenAccessRequests.clear();
  $("access-notifications").hidden = true; $("access-request-list").replaceChildren();
  $("request-access-form").hidden = true; $("request-ports").value = ""; $("request-access-submit").disabled = false;
  try {
    sessionStorage.removeItem(tokenStorageKey);
  } catch {
    // Login and logout also work when browser storage is disabled.
  }
  snapshot = null;
  account = null;
  accountStale = false;
  knownPolicies.clear();
  mapPoliciesLoading = false;
  permissionMap.clear();
  bulkPlan = null;
  bulkBusy = false;
  bulkRefreshing = false;
  $("bulk-dialog").close();
  $("bulk-results").replaceChildren();
  $("bulk-rule").textContent = "";
  $("ca-file").value = "";
  $("coordinator").value = "";
  $("device-name").value = "";
  $("user-token").type = "password";
  $("toggle-user-token").textContent = "Показать токен";
  $("toggle-user-token").setAttribute("aria-pressed", "false");
  setLoginMode(false);
  for (const id of ["network-error", "device-error", "activation-error", "policy-error", "owner-error", "bulk-error"]) showError($(id), "");
  $("user-token").value = "";
  $("user-name").value = "";
  $("network-form").hidden = false;
  $("account-summary").hidden = true;
  $("add-device-form").hidden = true;
  selectedKey = null;
  stale = false;
  connectErrors.clear();
  $("details-dialog").close();
  $("policy-dialog").close();
  policyTarget = null;
  policyDirty = false;
  policyBusy = false;
  policyLoaded = false;
  ownerBusy = false;
  $("policy-rules").replaceChildren();
  $("rename-name").value = "";
  for (const id of [
    "device-list",
    "diagnostic-summary",
    "diagnostic-details",
    "stats-grid",
    "peer-detail-list",
    "current-device",
    "account-details",
  ])
    $(id).replaceChildren();
  clearTimeout(pollTimer);
  for (const request of requests) request.abort();
  connecting.clear();
  closeTerminal();
  filePath = [];
  if ($("files-list")) $("files-list").replaceChildren();
  refreshing = false;
  accountBusy = false;
  $("network-submit").disabled = false;
  $("add-device-submit").disabled = false;
  $("resume-network").disabled = false;
  $("token").value = "";
  $("token-file").value = "";
  $("peer-search").value = "";

  $("app").hidden = true;
  $("auth-view").hidden = false;
  $("sign-in").disabled = false;
  $("select-token").disabled = false;
  $("sign-in").textContent = "Открыть панель →";
  $("toast").hidden = true;
  showError($("auth-error"), message);
}

function terminalStatus(message, error = false) {
  $("terminal-status").textContent = message;
  $("terminal-status").classList.toggle("error", error);
}
function renderTerminalDevices() {
  const select = $("terminal-device");
  if (!select || !snapshot) return;
  const current = select.value;
  select.replaceChildren(new Option("Выберите устройство", ""));
  for (const peer of networkDevices().filter((peer) => peer.device_id && !peer.local)) {
    const option = new Option(`${nameOf(peer)} · ${peer.online === true ? "онлайн" : "оффлайн"}${peer.terminal === true ? "" : " · нет разрешения"}`, peer.device_id);
    option.disabled = peer.terminal !== true;
    select.append(option);
  }
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}
function renderFileDevices() {
  const select = $("files-device");
  if (!select || !snapshot) return;
  const current = select.value;
  select.replaceChildren(new Option("Выберите устройство", ""));
  for (const peer of networkDevices().filter((peer) => peer.device_id && !peer.local)) {
    const option = new Option(`${nameOf(peer)} · ${peer.online === true ? "онлайн" : "оффлайн"}${peer.files === true ? "" : " · нет разрешения"}`, peer.device_id);
    option.disabled = peer.files !== true;
    select.append(option);
  }
  if ([...select.options].some((option) => option.value === current)) select.value = current;
}
function fileStatus(message, error = false) {
  $("files-status").textContent = message;
  $("files-status").classList.toggle("error", error);
}
function fileUrl(device, path = filePath) {
  const encoded = path.map((part) => encodeURIComponent(part)).join("/");
  return `/api/v1/files/${encodeURIComponent(device)}/${encoded}`;
}
async function filesRequest(method, path = filePath, body = undefined, headers = {}) {
  const response = await fetch(fileUrl($("files-device").value, path), {
    method,
    headers: { Authorization: `Bearer ${token}`, ...headers },
    body,
    cache: "no-store",
    credentials: "omit",
  });
  if (!response.ok && response.status !== 207) {
    const text = await response.text().catch(() => "");
    throw new Error(text || `Ошибка File Explorer: HTTP ${response.status}`);
  }
  return response;
}
function renderFileBreadcrumbs() {
  const target = $("files-breadcrumbs");
  target.replaceChildren();
  const root = document.createElement("button"); root.className = "text-link plain-button"; root.textContent = "/"; root.onclick = () => { filePath = []; loadFiles(); }; target.append(root);
  filePath.forEach((part, index) => { target.append(document.createTextNode(" / ")); const button = document.createElement("button"); button.className = "text-link plain-button"; button.textContent = part; button.onclick = () => { filePath = filePath.slice(0, index + 1); loadFiles(); }; target.append(button); });
}
async function loadFiles() {
  const device = $("files-device").value;
  if (!device || fileBusy) return;
  fileBusy = true; fileStatus("Получаем каталог…"); renderFileBreadcrumbs();
  try {
    const response = await filesRequest("PROPFIND");
    const xml = new DOMParser().parseFromString(await response.text(), "application/xml");
    if (xml.querySelector("parsererror")) throw new Error("Некорректный ответ WebDAV");
    const rows = [...xml.getElementsByTagNameNS("DAV:", "response")].map((item) => {
      const href = item.getElementsByTagNameNS("DAV:", "href")[0]?.textContent || "";
      const name = decodeURIComponent(href.replace(/\/$/, "").split("/").pop() || "");
      const directory = !!item.getElementsByTagNameNS("DAV:", "collection")[0];
      return { name, directory };
    }).filter((item, index) => index > 0 && item.name).sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name, "ru"));
    const list = $("files-list"); list.replaceChildren();
    for (const item of rows) {
      const row = document.createElement("div"); row.className = "device-row"; row.setAttribute("role", "row");
      const name = document.createElement("button"); name.className = "text-link plain-button"; name.textContent = `${item.directory ? "📁" : "📄"} ${item.name}`;
      if (item.directory) name.onclick = () => { filePath.push(item.name); loadFiles(); };
      else name.onclick = async () => { const download = await filesRequest("GET", [...filePath, item.name]); const blob = await download.blob(); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = item.name; link.click(); URL.revokeObjectURL(link.href); };
      row.append(name);
      if (item.directory) { const open = document.createElement("span"); open.className = "muted"; open.textContent = "Каталог"; row.append(open); }
      const actions = document.createElement("span"); actions.className = "row-actions";
      const rename = document.createElement("button"); rename.className = "text-link plain-button"; rename.textContent = "Переименовать"; rename.onclick = async () => { const next = window.prompt("Новое имя", item.name); if (!next || next === item.name || /[\\/]/.test(next)) return; try { await filesRequest("MOVE", [...filePath, item.name], undefined, { Destination: `/${[...filePath, next].map(encodeURIComponent).join("/")}` }); loadFiles(); } catch (error) { fileStatus(error.message, true); } };
      const remove = document.createElement("button"); remove.className = "text-link plain-button"; remove.textContent = "Удалить"; remove.onclick = async () => { if (!window.confirm(`Удалить «${item.name}»?`)) return; try { await filesRequest("DELETE", [...filePath, item.name]); loadFiles(); } catch (error) { fileStatus(error.message, true); } };
      actions.append(rename, remove); row.append(actions);
      list.append(row);
    }
    fileStatus(`${rows.length} объектов`);
  } catch (error) { fileStatus(error.message, true); }
  finally { fileBusy = false; }
}
function closeTerminal() {
  if (terminalSocket) {
    if (terminalSocket.readyState === WebSocket.OPEN) terminalSocket.send(JSON.stringify({ type: "close" }));
    terminalSocket.close();
    terminalSocket = null;
  }
  if ($("terminal-close")) $("terminal-close").disabled = true;
  if ($("terminal-open")) $("terminal-open").disabled = false;
}
async function openTerminal(event) {
  event.preventDefault();
  if (!snapshot || terminalSocket) return;
  const deviceId = $("terminal-device").value;
  const user = $("terminal-user").value.trim() || "portal";
  if (!deviceId) return;
  $("terminal-open").disabled = true;
  terminalStatus("Проверяем разрешение и прямой путь…");
  if (!terminalInstance) {
    terminalInstance = new window.Terminal({ convertEol: true, cursorBlink: true });
    terminalInstance.open($("terminal-screen"));
    terminalInstance.onResize(({ cols, rows }) => {
      if (terminalSocket?.readyState === WebSocket.OPEN)
        terminalSocket.send(JSON.stringify({ type: "resize", cols, rows }));
    });
  }
  terminalInstance.clear();
  try {
    const data = await api("terminal/session", { device_id: deviceId, user });
    const protocol = location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(`${protocol}//${location.host}/api/v1/terminal/ws`);
    terminalSocket = socket;
    socket.binaryType = "arraybuffer";
    socket.onopen = () => {
      socket.send(JSON.stringify({ type: "open", ticket: data.ticket, cols: terminalInstance.cols, rows: terminalInstance.rows }));
      terminalStatus("Подключение…");
      $("terminal-close").disabled = false;
      terminalInstance.focus();
    };
    socket.onmessage = (event) => {
      if (typeof event.data === "string") {
        try {
          const message = JSON.parse(event.data);
          if (message.type === "status") terminalStatus(message.status === "connected" ? "Подключено" : message.status);
          else if (message.type === "stderr") terminalInstance.write(message.data);
          else if (message.type === "exit") { terminalStatus(`Сессия завершена (код ${message.status})`); closeTerminal(); }
          else if (message.type === "error") { terminalStatus(message.message, true); closeTerminal(); }
        } catch { terminalInstance.write(event.data); }
      } else terminalInstance.write(new Uint8Array(event.data));
    };
    socket.onclose = () => { if (terminalSocket === socket) { terminalSocket = null; $("terminal-close").disabled = true; $("terminal-open").disabled = false; terminalStatus("Сессия закрыта"); } };
    socket.onerror = () => terminalStatus("WebSocket терминала недоступен", true);
    terminalInstance.onData((data) => { if (socket.readyState === WebSocket.OPEN) socket.send(new TextEncoder().encode(data)); });
  } catch (error) {
    terminalStatus(error.message, true);
    $("terminal-open").disabled = false;
  }
}

async function signIn(candidate) {
  if (!/^[0-9a-fA-F]{64}$/.test(candidate)) {
    showError(
      $("auth-error"),
      "Токен должен содержать 64 шестнадцатеричных символа.",
    );
    return;
  }
  const current = ++session;
  $("sign-in").disabled = true;
  $("select-token").disabled = true;
  $("sign-in").textContent = "Подключение…";
  showError($("auth-error"), "");
  try {
    const data = await api("snapshot", null, candidate);
    if (current !== session) return;
    token = candidate;
    let remembered = false;
    try {
      sessionStorage.setItem(tokenStorageKey, candidate);
      remembered = true;
    } catch {
      // A storage restriction must not prevent access to the local API.
    }
    $("token").value = "";
    $("token-file").value = "";
    render(data);
    $("auth-view").hidden = true;
    $("app").hidden = false;
    scheduleRefresh();
    document.querySelector(".nav-link.active").focus();
    loadAccount(current);
    if (data.setup_available && !data.network) location.hash = "network";
    if (!remembered)
      toast(
        "Браузер запретил сохранение токена. После обновления потребуется войти снова.",
        true,
      );
  } catch (error) {
    if (current !== session) return;
    if (error.status === 401) {
      signOut(error.message);
      return;
    }
    $("token").value = candidate;
    $("sign-in").disabled = false;
    $("select-token").disabled = false;
    $("sign-in").textContent = "Повторить подключение →";
    showError($("auth-error"), error.message);
  }
}

$("auth-form").addEventListener("submit", (event) => {
  event.preventDefault();
  signIn($("token").value.trim());
});

$("select-token").addEventListener("click", () => $("token-file").click());
$("token-file").addEventListener("change", async () => {
  const file = $("token-file").files[0];
  if (!file) return;
  try {
    if (file.size > 256)
      throw new Error(
        "Это не файл токена локального API: файл слишком большой.",
      );
    const value = (await file.text()).trim();
    if (!/^[0-9a-fA-F]{64}$/.test(value))
      throw new Error(
        "В файле должен быть токен из 64 шестнадцатеричных символов.",
      );
    $("token").value = value;
    $("auth-form").requestSubmit();
  } catch (error) {
    showError($("auth-error"), error.message);
    $("token-file").value = "";
  }
});
$("sign-out").addEventListener("click", () => {
  signOut();
  $("token").focus();
});

function scheduleRefresh() {
  clearTimeout(pollTimer);
  if (token) pollTimer = setTimeout(refresh, 5000);
}

async function refresh() {
  if (!token || refreshing) return;
  clearTimeout(pollTimer);
  const current = session;
  refreshing = true;
  $("refresh").disabled = true;
  try {
    const data = await api("snapshot");
    if (current === session) { render(data); loadAccount(current); }
  } catch (error) {
    if (current !== session) return;
    if (error.status === 401) {
      signOut(error.message);
      return;
    }
    showError(
      $("connection-error"),
      `${error.message} Ниже показаны последние полученные данные.`,
    );
    $("agent-state").textContent = "Нет связи с агентом";
    $("agent-state").classList.add("error");
    $("local-status").textContent = "Нет связи с агентом";
    stale = true;
    updateLease();
    renderMap();
  } finally {
    if (current === session) {
      refreshing = false;
      $("refresh").disabled = false;
      scheduleRefresh();
    }
  }
}
$("refresh").addEventListener("click", refresh);

function shortKey(key) {
  return `${key.slice(0, 12)}…${key.slice(-8)}`;
}
function bytes(value) {
  if (!value) return "0 Б";
  const units = ["Б", "КиБ", "МиБ", "ГиБ", "ТиБ"];
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1,
  );
  return `${new Intl.NumberFormat("ru-RU", { maximumFractionDigits: index ? 1 : 0 }).format(value / 1024 ** index)} ${units[index]}`;
}

// UI states come only from the runtime snapshot. A configured endpoint is not
// proof of reachability, and an accepted HTTP request is not a synthetic session.
function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function icon(name) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.classList.add("icon");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS(svg.namespaceURI, "use");
  use.setAttribute("href", `#i-${name}`);
  svg.append(use);
  return svg;
}
function nameOf(peer) {
  return peer.name || `Пир ${peer.public_key.slice(0, 8)}`;
}
function currentDevice() {
  return {
    public_key: snapshot.interface.public_key,
    device_id: snapshot.network?.device_id,
    name: account?.devices.find(device => device.public_key === snapshot.interface.public_key)?.name || snapshot.network?.device_name || snapshot.interface.name,
    owned: true,
    local: true,
    online: true,
    allowed_ips: snapshot.interface.addresses,
  };
}
function networkDevices() {
  const devices = new Map();
  for (const device of [currentDevice(), ...snapshot.peers, ...(account?.devices || []).map(registryPeer)]) {
    if (!devices.has(device.public_key)) devices.set(device.public_key, device);
  }
  return [...devices.values()];
}

function selectedPeer() {
  return (snapshot && selectedKey === snapshot.interface.public_key ? currentDevice() : null) || snapshot?.peers.find((peer) => peer.public_key === selectedKey) || (account?.devices.find(d => d.public_key === selectedKey) ? registryPeer(account.devices.find(d => d.public_key === selectedKey)) : null);
}
function leaseRemaining() {
  return snapshot?.network
    ? Math.max(
        0,
        snapshot.network.lease_remaining_seconds -
          Math.floor((performance.now() - receivedAt) / 1000),
      )
    : null;
}
function expired() {
  return (
    !!snapshot?.network &&
    (!snapshot.network.lease_active || leaseRemaining() === 0)
  );
}
function canConnect(peer) {
  return !!(
    peer &&
    snapshot?.mode === "managed" &&
    peer.device_id &&
    (peer.outgoing_tcp?.length || peer.files === true) &&
    snapshot.healthy &&
    !expired() &&
    !stale
  );
}
function pathLabel(peer) {
  if (stale) return "Нет свежих данных";
  if (!snapshot.healthy) return "Ошибка агента";
  if (peer.local) return "Агент работает";
  if (peer.registryOnly) return "Путь неизвестен";
  if (expired()) return "Карта истекла";
  return (
    {
      direct: "Прямой путь",
      probing: "Проверяем путь",
      offline: "Путь не подтверждён",
    }[peer.path] || "Путь не подтверждён"
  );
}
function status(peer) {
  const badge = element(
    "span",
    `device-availability ${stale || !snapshot.healthy || expired() || peer.online !== true ? "offline" : ""}`,
  );
  badge.append(element("i", "dot"), document.createTextNode(peer.online === true ? "Онлайн" : "Оффлайн"));
  return badge;
}
function details(target, entries) {
  target.replaceChildren(
    ...entries.map(([label, value]) => {
      const row = element("div");
      row.append(element("dt", "", label), element("dd", "", value ?? "—"));
      return row;
    }),
  );
}
function ports(value) {
  return value == null
    ? "TCP ACL Portal не применяются"
    : value.length
      ? value.join(", ")
      : "Нет доступа";
}
function navigate() {
  const route = location.hash.slice(1);
  if (route === "overview") history.replaceState(null, "", "#devices");
  const page = ["devices", "map", "network", "diagnostics", "terminal", "files"].includes(route)
    ? route
    : "devices";
  for (const name of ["devices", "map", "network", "diagnostics", "terminal", "files"])
    $(name).hidden = name !== page;
  document.querySelectorAll("[data-page], a[href='#terminal'], a[href='#files']").forEach((link) => {
    const active = (link.dataset.page || link.getAttribute("href")?.slice(1)) === page;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  permissionMap.reveal();
}
function render(data) {
  snapshot = data;
  $("registration-key").value = data.interface.public_key;
  stale = false;
  receivedAt = performance.now();
  if (!selectedPeer())
    selectedKey =
      data.peers.find((peer) => peer.device_id && (peer.outgoing_tcp?.length || peer.files === true))
        ?.public_key ||
      data.peers[0]?.public_key ||
      null;
  showError(
    $("connection-error"),
    data.healthy
      ? ""
      : "Агент сообщил об ошибке. Подключение недоступно; проверьте журнал portal.",
  );
  $("agent-state").textContent = data.healthy
    ? "Агент работает"
    : "Ошибка агента";
  $("agent-state").classList.toggle("error", !data.healthy);
  $("local-name").textContent =
    data.network?.device_name || data.interface.name;
  $("local-status").textContent = data.healthy
    ? "Агент работает"
    : "Ошибка агента";
  $("workspace-mode").textContent =
    data.mode === "managed" ? "С координатором" : "Ручной WireGuard";
  $("network-context").textContent = data.network ? `Сеть ${data.network.network_id} · Аккаунт ${data.network.user_name || "—"}` : "Локальный агент · Сеть не подключена";
  $("workspace-name").textContent = data.network ? `Сеть ${data.network.network_id.slice(0, 8)}` : "Сеть не подключена";
  $("last-updated").textContent =
    `Обновлено в ${new Date().toLocaleTimeString("ru-RU")}`;
  renderDiagnostics();
  renderPeers();
  renderTerminalDevices();
  renderFileDevices();
  updateLease();
}
function updateLease() {
  if (!snapshot) return;
  if (mapExpired !== expired()) { mapExpired = expired(); renderMap(); }
  const network = snapshot.network;
  showError(
    $("lease-warning"),
    expired()
      ? "Срок карты сети истёк. Управляемый трафик заблокирован до получения свежей карты от координатора."
      : network && !network.coordinator_connected
        ? "Координатор недоступен. Текущие разрешения действуют до истечения срока карты."
        : "",
  );
  const lease = $("lease-value");
  if (lease) {
    const remaining = leaseRemaining();
    lease.textContent = expired()
      ? "Срок истёк"
      : `${Math.floor(remaining / 60)} мин ${remaining % 60} с`;
  }
  renderConnection();
  // Update path labels on expiry without rebuilding the list (and losing focus).
  const devicesByKey = new Map(networkDevices().map(device => [device.public_key, device]));
  document.querySelectorAll("[data-path]").forEach((node) => {
    const peer = devicesByKey.get(node.dataset.path);
    if (peer) node.replaceChildren(status(peer));
  });
}
setInterval(updateLease, 1000);
function renderConnection() {
  if (!snapshot) return;
  const peer = selectedPeer();
  const managed = snapshot.mode === "managed";
  const pending = peer && connecting.has(peer.public_key);
  const direct =
    peer?.path === "direct" && snapshot.healthy && !expired() && !stale;
  $("connection-card").classList.toggle("connected", !!direct);
  $("connection-card").classList.toggle(
    "error",
    stale || expired() || !snapshot.healthy,
  );
  $("connection-status").textContent = pending
    ? "Запрос P2P…"
    : peer
      ? pathLabel(peer)
      : "Текущее устройство";
  $("connection-title").textContent = direct
    ? "Прямое соединение установлено."
    : pending
      ? "Проверяем соединение."
      : peer
        ? "Подключение к устройству."
        : "Ваше текущее устройство.";
  let caption = !peer
    ? managed
      ? `${nameOf(currentDevice())} зарегистрировано в сети. Выберите другое устройство или подключите ещё одно к этому аккаунту с тем же токеном входа.`
      : "Подключите сеть в разделе «Сеть и аккаунт»."
    : stale
      ? "Агент не отвечает. Показаны последние полученные данные."
      : expired()
        ? "Дождитесь обновления карты сети координатором."
        : pending
          ? "Согласовываем P2P-путь и ждём проверенного ответа WireGuard."
          : !managed
            ? "Пиры настроены вручную. Соединениями управляет WireGuard."
            : !(peer.outgoing_tcp?.length || peer.files === true)
              ? peer.incoming_tcp?.length
                ? "Разрешены только входящие TCP-соединения."
                : "Для этого устройства нет разрешённого исходящего TCP-доступа."
              : direct
                ? "Локальный агент подтвердил прямой путь. Доступны только разрешённые TCP-порты."
                : "Запрос будет отправлен от этого устройства. Получатель ответит автоматически при действующем разрешении.";
  if (stale) caption = "Агент не отвечает. Показаны последние полученные данные.";
  else if (expired()) caption = "Срок карты сети истёк. Дождитесь обновления карты координатором.";
  if (
    !pending &&
    !direct &&
    canConnect(peer) &&
    connectErrors.has(peer.public_key)
  )
    caption = connectErrors.get(peer.public_key);
  $("connection-caption").textContent = caption;
  $("connection-card").hidden = !peer || !!peer.local || !!peer.registryOnly;
  $("connect").hidden =
    !peer || !managed || !peer.device_id || !(peer.outgoing_tcp?.length || peer.files === true);
  $("connect").disabled = !canConnect(peer) || !!pending;
  $("grant-access").hidden = !peer?.owned || !account?.user || !!peer.outgoing_tcp?.length || peer.files === true || peer.public_key === snapshot.interface.public_key;
  $("connect").replaceChildren(
    icon("power"),
    element(
      "span",
      "",
      pending ? "Проверка…" : direct ? "Проверить соединение" : "Подключиться с этого устройства",
    ),
  );
  $("selected-access").textContent = peer ? accessLabel(peer) : "";
  $("connection-stats").hidden = !peer;
  $("peer-tx").textContent = peer?.traffic ? bytes(peer.traffic.tx_bytes) : "—";
  $("peer-rx").textContent = peer?.traffic ? bytes(peer.traffic.rx_bytes) : "—";
  // Keep the outcome of this attempt even if a background path appears later.
  if ($("details-dialog").open) renderPeerDetails();
}
function emptyState(title, message) {
  const box = element("div", "empty-state");
  box.append(element("strong", "", title), document.createTextNode(message));
  return box;
}
function peerButton(peer) {
  const button = element("button", "device-row");
  button.type = "button";
  button.dataset.device = peer.public_key;
  const symbol = element("span", "device-icon");
  symbol.append(icon("server"));
  const info = element("span", "row-info");
  info.append(
    element("strong", "", nameOf(peer)),
    element("small", "", ownershipLabel(peer)),
    element("small", "", accessLabel(peer)),
    element(
      "small",
      "",
      peer.allowed_ips.join(", ") || shortKey(peer.public_key),
    ),
  );
  const path = element("span");
  path.dataset.path = peer.public_key;
  path.append(status(peer));
  button.append(symbol, info, path, icon("chevron"));
  return button;
}
function renderPeers() {
  if (!snapshot) return;
  const focused = document.activeElement?.closest("button[data-device]");
  const focusedKey = focused?.dataset.device;
  const focusedParent = focused?.parentElement;
  const query = $("peer-search").value.trim().toLocaleLowerCase("ru-RU");
  const devices = networkDevices();
  const peers = devices.filter((peer) => !peer.local &&
    [peer.name, peer.device_id, peer.public_key, peer.endpoint, ...peer.allowed_ips]
      .some(value => value?.toLocaleLowerCase("ru-RU").includes(query)),
  );
  $("device-count").textContent = number.format(devices.length);
  document.querySelector(".nav-count").textContent = number.format(devices.length);
  $("device-list").replaceChildren(...peers.map((peer) => peerButton(peer)));
  const local = snapshot.interface;
  $("current-device").replaceChildren(element("h2", "", nameOf(currentDevice())), element("p", "scope-note", "Ваше · Это устройство"), element("p", "scope-note", local.addresses.join(", ") || "Адреса ещё не назначены"), element("p", "scope-note", snapshot.healthy && !stale ? "Локальный агент работает" : "Нет свежих данных о локальном агенте"));
  if (account?.devices.some(d => d.public_key === local.public_key)) {
    const manage = element("button", "button secondary", "Параметры и разрешения"); manage.type = "button";
    manage.addEventListener("click", () => { selectedKey = local.public_key; $("rename-name").value = nameOf(selectedPeer()); renderConnection(); renderPeerDetails(); $("details-dialog").showModal(); });
    $("current-device").append(manage);
  }
  renderMap();
  if (!$("device-list").children.length)
    $("device-list").append(
      emptyState(
        query ? "Ничего не найдено" : "Пиров пока нет",
        query
          ? "Попробуйте другое имя, адрес или ключ."
          : "Доступные пиры появятся здесь.",
      ),
    );
  if (focusedKey && focusedParent?.isConnected) {
    [...focusedParent.querySelectorAll("button[data-device]")].find(button => button.dataset.device === focusedKey)?.focus({preventScroll: true});
  }
}
function renderDiagnostics() {
  const { interface: local, network, stats } = snapshot;
  details($("diagnostic-summary"), [
    ["Устройство", network?.device_name || local.name],
    ["Адреса Portal", local.addresses.join(", ") || "Не назначены"],
    ["Интерфейс", local.name],
    [
      "Режим",
      snapshot.mode === "managed" ? "С координатором" : "Ручной WireGuard",
    ],
    [
      "Координатор",
      network
        ? network.coordinator_connected
          ? "Есть связь"
          : "Нет связи"
        : "Не используется",
    ],
    ...(network
      ? [
          ["Срок карты", ""],
          [
            "Разрешения",
            network.policy_pending
              ? "Ожидают подтверждения координатора"
              : `Опубликованы · ревизия ${network.policy_revision}`,
          ],
        ]
      : []),
  ]);
  if (network)
    $("diagnostic-summary").children[5].querySelector("dd").id = "lease-value";
  details($("diagnostic-details"), [
    ["Публичный ключ", local.public_key],
    ["UDP-сокет", local.listen],
    ...(network
      ? [
          ["ID устройства", network.device_id],
          ["ID сети", network.network_id],
          ["Ревизия карты", network.revision],
        ]
      : [["TCP-разрешения", "TCP ACL Portal не применяются"]]),
  ]);
  $("stats-grid").replaceChildren(
    ...[
      ["Входящие UDP-пакеты", stats.received_udp_packets],
      ["Пакеты из TUN", stats.received_tun_packets],
      ["Отброшенные пакеты", stats.dropped_packets],
      ["Ошибки отправки UDP", stats.udp_send_errors],
      ["Ошибки таймерных отправок", stats.timer_send_errors],
    ].map(([label, value]) => {
      const card = element("article", "stat-card");
      card.append(
        element("span", "", label),
        element("strong", "", number.format(value)),
      );
      return card;
    }),
  );
}
function renderPeerDetails() {
  const peer = selectedPeer();
  if (!peer) {
    $("details-dialog").close();
    return;
  }
  $("details-title").textContent = nameOf(peer);
  $("owner-actions").hidden = !account?.user || !peer.owned;
  $("request-access-form").hidden = !account?.user || peer.owned !== false || !snapshot?.network?.device_id;
  showError($("request-access-error"), "");
  $("copy-peer-addresses").disabled = !peer.allowed_ips.length;
  if (document.activeElement !== $("rename-name")) $("rename-name").value ||= nameOf(peer);
  details($("peer-detail-list"), [
    ["Принадлежность", ownershipLabel(peer) + (peer.public_key === snapshot.interface.public_key ? " · Это устройство" : "")],
    ...(knownPolicies.has(peer.device_id) ? [["Разрешения устройства", policyState(knownPolicies.get(peer.device_id))]] : []),
    ["Присутствие агента", peer.online === true ? "Онлайн по данным координатора" : peer.online === false ? "Оффлайн по данным координатора" : "Нет данных координатора"],
    ["Состояние пути от этого устройства", pathLabel(peer)],
    ["Адреса Portal", peer.allowed_ips.join(", ") || "Не назначены"],
    ["UDP endpoint", peer.endpoint || "Не задан"],
    ["Исходящий TCP-доступ", ports(peer.outgoing_tcp)],
    ["Входящий TCP-доступ", ports(peer.incoming_tcp)],
    [
      "Отправлено",
      peer.traffic
        ? `${bytes(peer.traffic.tx_bytes)} · ${number.format(peer.traffic.tx_packets)} пакетов`
        : "—",
    ],
    [
      "Получено",
      peer.traffic
        ? `${bytes(peer.traffic.rx_bytes)} · ${number.format(peer.traffic.rx_packets)} пакетов`
        : "—",
    ],
    [
      "Keepalive",
      peer.keepalive_seconds ? `${peer.keepalive_seconds} с` : "Не задан",
    ],
    ["ID устройства", peer.device_id || "Не используется"],
    ["Публичный ключ", peer.public_key],
  ]);
}
$("peer-search").addEventListener("input", renderPeers);
document.addEventListener("click", (event) => {
  const button = event.target.closest("button[data-device]");
  if (
    !button ||
    !(snapshot?.peers.some((peer) => peer.public_key === button.dataset.device) || account?.devices.some(d => d.public_key === button.dataset.device))
  )
    return;
  selectedKey = button.dataset.device;
  $("rename-name").value = nameOf(selectedPeer());
  showError($("owner-error"), "");
  renderConnection();
  renderPeerDetails();
  if (!$("details-dialog").open) $("details-dialog").showModal();
});
for (const [dialog, close] of [
  ["details-dialog", "close-details"],
]) {
  $(close).addEventListener("click", () => $(dialog).close());
  $(dialog).addEventListener("click", (event) => {
    if (event.target !== $(dialog)) return;
    const bounds = $(dialog).getBoundingClientRect();
    if (
      event.clientX < bounds.left ||
      event.clientX > bounds.right ||
      event.clientY < bounds.top ||
      event.clientY > bounds.bottom
    )
      $(dialog).close();
  });
}
$("connect").addEventListener("click", async () => {
  const peer = selectedPeer();
  if (!canConnect(peer) || connecting.has(peer.public_key)) return;
  const current = session;
  const key = peer.public_key;
  connecting.add(key);
  connectErrors.delete(key);
  renderConnection();
  try {
    await api("command", {
      operation: "connect",
      peer_device_id: peer.device_id,
    });
    if (current !== session) return;
    toast("Прямое P2P-соединение установлено и проверено.");
  } catch (error) {
    if (current !== session) return;
    if (error.status === 401) {
      signOut(error.message);
      return;
    }
    connectErrors.set(key, error.message);
    toast(error.message, true);
  } finally {
    if (current === session) {
      connecting.delete(key);
      renderConnection();
      await refresh();
    }
  }
});

$("terminal-form").addEventListener("submit", openTerminal);
$("terminal-close").addEventListener("click", () => {
  closeTerminal();
  terminalStatus("Сессия закрыта");
});
$("files-device").addEventListener("change", () => { filePath = []; loadFiles(); });
$("files-refresh").addEventListener("click", () => loadFiles());
$("files-up").addEventListener("click", () => { if (filePath.length) { filePath.pop(); loadFiles(); } });
$("files-upload").addEventListener("change", async (event) => {
  const file = event.target.files?.[0]; if (!file || !$("files-device").value) return;
  try { fileStatus(`Загрузка ${file.name}…`); await filesRequest("PUT", [...filePath, file.name], file, { "Content-Type": "application/octet-stream" }); fileStatus("Файл загружен"); loadFiles(); }
  catch (error) { fileStatus(error.message, true); }
  finally { event.target.value = ""; }
});
$("files-mkdir").addEventListener("click", async () => {
  const name = window.prompt("Имя каталога"); if (!name || /[\\/]/.test(name)) return;
  try { await filesRequest("MKCOL", [...filePath, name]); loadFiles(); } catch (error) { fileStatus(error.message, true); }
});

$("copy-key").addEventListener("click", async () => {
  if (!snapshot) return;
  try {
    await navigator.clipboard.writeText(snapshot.interface.public_key);
    toast("Публичный ключ скопирован");
  } catch {
    toast(
      "Не удалось скопировать ключ. Разрешите доступ к буферу обмена.",
      true,
    );
  }
});

function signInFromLink() {
  const params = new URLSearchParams(location.hash.slice(1));
  if (!params.has("token")) return false;
  const candidates = params.getAll("token");
  history.replaceState(null, "", location.pathname + location.search);
  signOut();
  if (candidates.length === 1) signIn(candidates[0]);
  else showError($("auth-error"), "Ссылка должна содержать только один токен.");
  return true;
}

function restoreSession() {
  if (signInFromLink()) return;
  let savedToken;
  try {
    savedToken = sessionStorage.getItem(tokenStorageKey);
    if (savedToken && !/^[0-9a-fA-F]{64}$/.test(savedToken)) {
      sessionStorage.removeItem(tokenStorageKey);
      return;
    }
  } catch {
    // Fall back to manual login when browser storage is unavailable.
  }
  if (savedToken) signIn(savedToken);
}
window.addEventListener("hashchange", () => {
  if (!signInFromLink()) navigate();
});


function ownershipLabel(peer) {
  return peer.owned === true ? "Ваше устройство" : peer.owned === false ? "Чужое устройство" : "Владелец неизвестен";
}
function accessLabel(peer) {
  if (peer.outgoing_tcp == null) return "Разрешения Portal не используются";
  const parts = [];
  if (peer.outgoing_tcp.length) parts.push(`Это устройство → ${nameOf(peer)} · TCP ${ports(peer.outgoing_tcp)}`);
  if (peer.files === true) parts.push(`Это устройство → ${nameOf(peer)} · File Explorer`);
  if (peer.incoming_tcp?.length) parts.push(`${nameOf(peer)} → Это устройство · TCP ${ports(peer.incoming_tcp)}`);
  return parts.join("; ") || "Доступа от текущего устройства нет";
}
function isOwnDevice(device) {
  return !!account?.user && device.owner_user_id === account.user.id;
}
function registryPeer(device) {
  return { public_key: device.public_key, device_id: device.id, name: device.name, owned: isOwnDevice(device), registryOnly: true, allowed_ips: [device.ipv4, device.ipv6], incoming_tcp: [], outgoing_tcp: [], path: "unknown" };
}
const permissionMap = new window.PortalMap($("map-list"), {
  onDevice(key) {
    selectedKey = key;
    $("rename-name").value = nameOf(selectedPeer());
    renderConnection();
    renderPeerDetails();
    $("details-dialog").showModal();
  },
  onPermission: openMapPermission,
});
$("map-zoom-in").addEventListener("click", () => permissionMap.zoom(.1));
$("map-zoom-out").addEventListener("click", () => permissionMap.zoom(-.1));
$("map-fit").addEventListener("click", () => permissionMap.fit());
$("map-list").addEventListener("keydown", event => {
  if (!["Enter", " "].includes(event.key)) return;
  const node = event.target.closest('[data-device]');
  if (node) { event.preventDefault(); selectedKey = node.dataset.device; renderConnection(); renderPeerDetails(); $("details-dialog").showModal(); }
});
async function openMapPermission(source, target) {
  const peer = networkDevices().find(device => device.public_key === target);
  if (!peer?.owned || !account?.user) { toast("Разрешения меняет владелец целевого устройства", true); return; }
  policyTarget = peer; policyLoaded = false; policyDirty = false; policyRevision = 0;
  $("policy-rules").replaceChildren(); $("policy-target").textContent = `Цель: ${nameOf(peer)}`;
  $("policy-dialog").showModal();
  await loadPolicy(true);
  if (!policyLoaded || policyTarget?.public_key !== target || !$("policy-dialog").open) return;
  let row = [...$("policy-rules").children].find(row => row.querySelector('.rule-source').value === source);
  if (!row) { addRule(source); markPolicyDirty(); row = $("policy-rules").lastElementChild; }
  row.querySelector('input').focus();
}
function renderMap() {
  if (!snapshot?.network) { permissionMap.clear(); $("map-empty").hidden = false; return; }
  $("map-empty").hidden = true;
  const devices = networkDevices();
  const local = snapshot.interface.public_key;
  const edges = new Map();
  const add = (source, target, tcp, pending = false) => { if (tcp?.length) edges.set(source + ':' + target, {source, target, tcp, pending}); };
  for (const peer of snapshot.peers) {
    add(local, peer.public_key, peer.outgoing_tcp);
    add(peer.public_key, local, peer.incoming_tcp, snapshot.network.policy_pending);
  }
  // Desired policies replace the applied incoming edges of each owned target.
  for (const device of devices) {
    const policy = knownPolicies.get(device.device_id);
    if (!policy) continue;
    for (const [id, edge] of edges) if (edge.target === device.public_key) edges.delete(id);
    for (const [source, permission] of Object.entries(policy.permissions)) add(source, device.public_key, permission.tcp, policy.applied_revision !== policy.revision);
  }
  permissionMap.update({
    scope: snapshot.network.network_id,
    devices: devices.map(device => ({id: device.public_key, name: nameOf(device), owned: device.owned,
      local: device.public_key === local, editable: !!device.owned && !!account?.user,
      owner: device.owned ? (account?.user?.name || snapshot.network.user_name) : "Другой владелец",
      online: !stale && snapshot.healthy && !expired() && (device.public_key === local || device.online === true),
    })),
    edges: [...edges.values()],
  });
}
let mapPoliciesLoading = false;
async function refreshMapPolicies(current) {
  if (!account?.user || accountStale || mapPoliciesLoading) return;
  mapPoliciesLoading = true;
  try {
    const devices = networkDevices().filter(device => device.owned && device.device_id);
    const ids = new Set(devices.map(device => device.device_id));
    for (const id of knownPolicies.keys()) if (!ids.has(id)) knownPolicies.delete(id);
    // Keep requests bounded even for a large device registry.
    for (let offset = 0; offset < devices.length; offset += 4) {
      await Promise.all(devices.slice(offset, offset + 4).map(async device => {
        try {
          const policy = await api("account/device", {operation: "policy", device_id: device.device_id});
          if (current !== session) return;
          // A delayed read must not overwrite a policy just saved by this panel.
          if ((knownPolicies.get(device.device_id)?.revision ?? -1) <= policy.revision) {
            knownPolicies.set(device.device_id, policy);
            if (policyTarget?.device_id === device.device_id && policyLoaded && !policyBusy) updatePolicyStatus(policy);
          }
        } catch { /* Keep the last policy until the next successful coordinator poll. */ }
      }));
      if (current !== session) return;
    }
    renderMap();
  } finally { if (current === session) mapPoliciesLoading = false; }
}
async function loadAccount(current = session) {
  if (accountBusy) return;
  accountBusy = true;
  try {
    const data = await api("account");
    if (current !== session) return;
    if (data.error && account) { data.devices = account.devices; data.access_requests = account.access_requests; }
    account = data;
    accountStale = !!data.error;
    showError($("network-error"), data.error || "");
    renderAccount();
    renderAccessRequests();
    renderPeers();
    renderTerminalDevices();
    renderFileDevices();
    refreshBulkResults(current);
    refreshMapPolicies(current);
  } catch (error) {
    if (current !== session) return;
    accountStale = true;
    if (account) renderAccount();
    showError($("network-error"), error.message + (account ? " Показан последний полученный реестр сети." : ""));
  } finally { if (current === session) accountBusy = false; }
}
function renderAccount() {
  if (!account) return;
  showError($("activation-error"), account.activation_error || "");
  if (account.address) $("coordinator").value ||= account.address;
  if (account.pending_user_name && !$("user-name").value) { $("user-name").value = account.pending_user_name; setLoginMode(true); }
  if (account.user && accountStale) setLoginMode(false);
  $("network-form").hidden = !!account.user && !accountStale;
  $("account-summary").hidden = !account.user;
  $("add-device-form").hidden = !account.user || !account.needs_device;
  if (account.user) {
    details($("account-details"), [["Аккаунт", account.user.name], ["Координатор", account.address], ["Устройств в сети", account.devices.length], ["Собственных устройств", account.devices.filter(isOwnDevice).length], ["Состояние реестра", accountStale ? "Данные устарели" : "Получен с координатора"]]);
    $("device-name").value ||= account.device_name;
    $("device-public-key").value = snapshot.interface.public_key;
    $("resume-network").hidden = !!snapshot.network || account.needs_device;
  }
}
function setLoginMode(value) {
  registering = value;
  $("user-token-label").hidden = value;
  $("toggle-user-token").hidden = value;
  $("user-token").required = !value;
  $("user-name-label").hidden = !value;
  $("registration-key-label").hidden = !value;
  $("user-name").required = value;
  $("no-token").hidden = value;
  $("network-submit").textContent = value ? "Зарегистрироваться и подключиться" : "Войти в сеть";
  for (const [id, active] of [["login-mode", !value], ["register-mode", value]]) { $(id).setAttribute("aria-pressed", String(active)); $(id).classList.toggle("primary", active); $(id).classList.toggle("secondary", !active); }
}
$("login-mode").addEventListener("click", () => setLoginMode(false));
$("register-mode").addEventListener("click", () => setLoginMode(true));
$("no-token").addEventListener("click", () => setLoginMode(true));
$("toggle-user-token").addEventListener("click", () => { const visible = $("user-token").type === "password"; $("user-token").type = visible ? "text" : "password"; $("toggle-user-token").textContent = visible ? "Скрыть токен" : "Показать токен"; $("toggle-user-token").setAttribute("aria-pressed", String(visible)); });
$("coordinator").addEventListener("input", () => {
  const value = $("coordinator").value.trim();
  try { const url = new URL(value.includes("://") ? value : `https://${value}`); if (url.protocol !== "https:" || url.username || url.password || url.pathname !== "/" || url.search || url.hash) throw new Error(); $("normalized-address").textContent = `Адрес подключения: ${url.origin}`; }
  catch { $("normalized-address").textContent = "Укажите HTTPS-адрес без пути, пароля и параметров."; }
});
$("network-form").addEventListener("submit", async event => {
  event.preventDefault(); if (accountBusy) return;
  accountBusy = true; const current = session;
  $("network-submit").disabled = true; showError($("network-error"), "");
  try {
    const file = $("ca-file").files[0];
    if (file?.size > 32768) throw new Error("PEM-файл должен быть не больше 32 КиБ.");
    const data = await api("account", { address: $("coordinator").value, ...(registering ? {user_name: $("user-name").value.trim()} : {token: $("user-token").value.trim()}), ...(file ? {ca_pem: await file.text()} : {}) });
    if (current !== session) return;
    account = data; accountStale = !!data.error; $("user-token").value = ""; renderAccount(); renderPeers(); renderTerminalDevices(); renderFileDevices();
    if (data.error) throw new Error(data.error);
    if (!data.needs_device) { await api("account/activate", {name: data.device_name}); if (current === session) { await refresh(); location.hash = "devices"; } }
    else $("device-name").focus();
  } catch (error) { if (current === session) showError($("network-error"), error.message); }
  finally { if (current === session) { accountBusy = false; $("network-submit").disabled = false; } }
});
async function activateNetwork(event) {
  event?.preventDefault(); if (accountBusy) return;
  accountBusy = true; const current = session;
  $("add-device-submit").disabled = true; $("resume-network").disabled = true;
  showError($("device-error"), "");
  try { await api("account/activate", {name: $("device-name").value || account.device_name}); if (current === session) { $("add-device-form").hidden = true; await refresh(); location.hash = "devices"; } }
  catch (error) { if (current === session) { showError($("device-error"), error.message); showError($("network-error"), error.message); } }
  finally { if (current === session) { accountBusy = false; $("add-device-submit").disabled = false; $("resume-network").disabled = false; loadAccount(); } }
}
$("add-device-form").addEventListener("submit", activateNetwork);
$("resume-network").addEventListener("click", activateNetwork);
for (const [id, save] of [["copy-user-token", false], ["save-user-token", true]]) $(id).addEventListener("click", async () => {
  const current = session;
  try { const data = await api("account/token", {}); if (current !== session) return;
    if (save) { const url = URL.createObjectURL(new Blob([data.message + "\n"], {type: "text/plain"})); const link = element("a"); link.href = url; link.download = "portal-user-token.txt"; document.body.append(link); link.click(); link.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000); }
    else await navigator.clipboard.writeText(data.message);
    toast(save ? "Токен сохранён в файл" : "Токен скопирован");
  } catch (error) { if (current === session) showError($("network-error"), error.message); }
});
for (const id of ["copy-registration-key", "copy-device-key"]) $(id).addEventListener("click", async () => {
  if (!snapshot) return;
  try { await navigator.clipboard.writeText(snapshot.interface.public_key); toast("Публичный ключ скопирован"); }
  catch { showError($("network-error"), "Не удалось скопировать ключ. Выделите и скопируйте его из поля."); }
});
$("copy-peer-addresses").addEventListener("click", async () => {
  const peer = selectedPeer(); if (!peer) return;
  try { await navigator.clipboard.writeText(peer.allowed_ips.join(", ")); toast("Адреса скопированы"); }
  catch { toast("Не удалось скопировать адреса. Выделите их в параметрах устройства.", true); }
});
$("copy-peer-key").addEventListener("click", async () => {
  const peer = selectedPeer(); if (!peer) return;
  try { await navigator.clipboard.writeText(peer.public_key); toast("Публичный ключ скопирован"); } catch { toast("Не удалось скопировать ключ", true); }
});

function policyState(policy) {
  return policy.applied_revision === policy.revision ? `Применено · ревизия ${policy.revision}` : `Сохранено, ожидает устройства · ревизия ${policy.revision}. Подтверждена ревизия ${policy.applied_revision}. Старый доступ ограничен сроком ранее выданной карты.`;
}
const permissionServices = [{terminal: true, name: "Удалённый терминал"}, {files: true, name: "File Explorer"}];
function permissionSources() {
  const devices = new Map();
  for (const peer of [...(snapshot?.peers || []), ...(account?.devices || []).map(registryPeer), ...(snapshot ? [currentDevice()] : [])]) {
    if (peer.public_key !== policyTarget?.public_key) devices.set(peer.public_key, peer);
  }
  return [...devices.values()].sort((a, b) => nameOf(a).localeCompare(nameOf(b), "ru"));
}
function rulePorts(row) {
  return [...row.querySelectorAll('.service-checkbox:checked[data-port]')].map(input => input.dataset.port)
    .concat(row.querySelector('.rule-ports').value.trim()).filter(Boolean).join(", ");
}
function addRule(key = "", tcp = [], terminal = false, files = false) {
  const row = element("div", "policy-rule setup-card");
  const sourceLabel = element("label", "rule-field", "Кому разрешить доступ");
  const source = element("select", "rule-source");
  source.required = true;
  const placeholder = element("option", "", "Выберите устройство"); placeholder.value = ""; placeholder.disabled = true;
  source.append(placeholder);
  const devices = permissionSources();
  for (const peer of devices) {
    const address = (peer.allowed_ips || []).filter(Boolean)[0]?.split("/")[0];
    const option = element("option", "", `${nameOf(peer)}${address ? " · " + address : ""}${peer.public_key === snapshot?.interface.public_key ? " · Это устройство" : ""}`);
    option.value = peer.public_key; source.append(option);
  }
  // Preserve grants whose source is no longer present in the available registry.
  if (key && !devices.some(peer => peer.public_key === key)) {
    const option = element("option", "", `Недоступное устройство (${key.slice(0, 8)})`);
    option.value = key; source.append(option);
  }
  source.value = key;
  sourceLabel.append(source);
  const services = element("fieldset", "service-options");
  services.append(element("legend", "", "Что разрешить"));
  for (const service of permissionServices) {
    const label = element("label", "service-option");
    const checkbox = element("input", "service-checkbox");
    checkbox.type = "checkbox";
    if (service.terminal) {
      checkbox.dataset.terminal = "true";
      checkbox.checked = terminal;
    } else if (service.files) {
      checkbox.dataset.files = "true";
      checkbox.checked = files;
    } else {
      checkbox.dataset.port = String(service.port);
      checkbox.value = String(service.port);
      checkbox.checked = tcp.includes(service.port);
    }
    checkbox.addEventListener("change", markPolicyDirty);
    label.append(checkbox, element("span", "", service.name));
    services.append(label);
  }
  const extraLabel = element("label", "rule-field", "Другие TCP-порты");
  const portsInput = element("input", "rule-ports");
  portsInput.value = tcp.filter(port => !permissionServices.some(service => service.port === port)).join(", ");
  portsInput.placeholder = "Например: 3000, 8080";
  extraLabel.append(portsInput);
  const hint = element("p", "field-hint", "Выберите отдельные сервисы и укажите TCP-порты через запятую. Пустое правило не даёт доступа.");
  const actions = element("div", "rule-actions");
  const remove = element("button", "button secondary", "Убрать устройство"); remove.type = "button"; remove.addEventListener("click", () => { row.remove(); markPolicyDirty(); });
  const spread = element("button", "button secondary", "Применить это разрешение ко всем моим устройствам"); spread.type = "button"; spread.addEventListener("click", () => prepareBulk(source.value, rulePorts(row), row.querySelector(".service-checkbox[data-terminal]")?.checked === true, row.querySelector(".service-checkbox[data-files]")?.checked === true));
  actions.append(remove, spread);
  source.addEventListener("change", markPolicyDirty); portsInput.addEventListener("input", markPolicyDirty);
  row.append(sourceLabel, services, extraLabel, hint, actions); $("policy-rules").append(row);
}
function markPolicyDirty() { policyDirty = true; $("policy-status").textContent = "Есть несохранённые изменения"; }
function updatePolicyStatus(data) {
  if (!policyDirty) $("policy-status").textContent = data.revision === policyRevision
    ? policyState(data)
    : `Политика изменена другим клиентом · ревизия ${data.revision}. Загрузите актуальную ревизию.`;
}
async function loadPolicy(replace) {
  if (!policyTarget || policyBusy) return;
  const current = session, id = policyTarget.device_id;
  policyBusy = true; $("save-policy").disabled = true; $("reload-policy").disabled = true;
  try {
    const data = await api("account/device", {operation:"policy", device_id:id});
    if (current !== session || policyTarget?.device_id !== id) return;
    knownPolicies.set(id, data); renderMap();
    if (replace) { policyLoaded = true; policyRevision = data.revision; policyDirty = false; $("policy-rules").replaceChildren(); for (const [key, value] of Object.entries(data.permissions)) addRule(key, value.tcp, value.terminal === true, value.files === true); showError($("policy-error"), ""); }
    updatePolicyStatus(data);
  } catch (error) { if (current === session) showError($("policy-error"), error.message); }
  finally { if (current === session) { policyBusy = false; $("save-policy").disabled = false; $("reload-policy").disabled = false; } }
}
$("grant-access").addEventListener("click", () => $("edit-permissions").click());
$("edit-permissions").addEventListener("click", () => {
  const peer = selectedPeer(); if (!peer?.owned || !account?.user) return;
  policyTarget = peer; policyLoaded = false; policyDirty = false; policyRevision = 0; $("policy-rules").replaceChildren(); $("policy-target").textContent = `Цель: ${nameOf(peer)}`;
  $("policy-dialog").showModal(); loadPolicy(true);
});
$("close-policy").addEventListener("click", () => $("policy-dialog").close());
$("policy-dialog").addEventListener("close", () => { policyTarget = null; policyLoaded = false; policyDirty = false; });
$("policy-dialog").addEventListener("cancel", event => { if (policyDirty) { event.preventDefault(); showError($("policy-error"), "Есть несохранённые изменения. Сохраните их или нажмите «Закрыть», чтобы оставить редактор без сохранения."); } });
$("add-rule").addEventListener("click", () => { addRule(); markPolicyDirty(); });
$("reload-policy").addEventListener("click", () => { if (policyDirty && !window.confirm("Заменить несохранённые поля актуальной политикой с координатора?")) return; loadPolicy(true); });
$("policy-form").addEventListener("submit", async event => {
  event.preventDefault(); if (!policyTarget || policyBusy || !policyLoaded) return;
  const current = session, id = policyTarget.device_id;
  try {
    const permissions = Object.create(null);
    for (const row of $("policy-rules").children) {
      const {key, tcp} = parseRule(row.querySelector(".rule-source").value, rulePorts(row));
      const terminal = row.querySelector(".service-checkbox[data-terminal]")?.checked === true;
      const files = row.querySelector(".service-checkbox[data-files]")?.checked === true;
      if (Object.hasOwn(permissions, key)) throw new Error("Устройство выбрано дважды.");
      if (key === policyTarget.public_key) throw new Error("Выберите другое устройство: доступ самому себе не требуется.");
      permissions[key] = {tcp, ...(terminal ? {terminal: true} : {}), ...(files ? {files: true} : {})};
    }
    policyBusy = true; $("save-policy").disabled = true; $("policy-status").textContent = "Сохраняем"; showError($("policy-error"), "");
    const data = await api("account/device", {operation:"save_policy", device_id:id, base_revision:policyRevision, permissions});
    if (current !== session || policyTarget?.device_id !== id) return;
    knownPolicies.set(id, data); renderMap();
    policyRevision = data.revision; policyDirty = false; $("policy-status").textContent = policyState(data);
  } catch (error) { if (current === session) { showError($("policy-error"), error.message); $("policy-status").textContent = error.status === 409 ? "Конфликт изменений · черновик сохранён в редакторе" : "Изменения не подтверждены"; } }
  finally { if (current === session) { policyBusy = false; $("save-policy").disabled = false; } }
});
function parseRule(source, rawPorts) {
  const key = source.trim().toLowerCase();
  if (!/^[a-f0-9]{64}$/.test(key)) throw new Error("Выберите устройство, которому разрешён доступ.");
  const raw = rawPorts.trim();
  const tcp = raw ? raw.split(/[,\s]+/).map(value => {
    if (!/^\d+$/.test(value) || Number(value) < 1 || Number(value) > 65535) throw new Error("Укажите отдельные TCP-порты от 1 до 65535 через запятую.");
    return Number(value);
  }) : [];
  return {key, tcp: [...new Set(tcp)].sort((a, b) => a - b)};
}
function renderBulk() {
  $("bulk-results").replaceChildren(...(bulkPlan?.targets || []).map(target => {
    const row = element("div", "bulk-result");
    row.append(element("strong", "", target.device.name), element("p", "", target.message));
    return row;
  }));
}
async function prepareBulk(source, rawPorts, terminal = false, files = false) {
  if (bulkBusy || !account?.user) return;
  let rule;
  try { rule = parseRule(source, rawPorts); }
  catch (error) { showError($("policy-error"), error.message); return; }
  const current = session;
  const plan = { ...rule, terminal, files, targets: account.devices.filter(device => isOwnDevice(device) && device.public_key !== rule.key).map(device => ({device, message: "Загружаем текущую ревизию…"})) };
  bulkPlan = plan; bulkBusy = true;
  $("confirm-bulk").disabled = true; $("close-bulk").disabled = true;
  const serviceLabel = `${terminal ? " · terminal" : ""}${files ? " · files" : ""}`;
  $("bulk-rule").textContent = `Источник: ${nameOf(account.devices.map(registryPeer).find(peer => peer.public_key === rule.key) || snapshot.peers.find(peer => peer.public_key === rule.key) || {public_key: rule.key})} → TCP ${ports(rule.tcp)}${serviceLabel}`;
  showError($("bulk-error"), ""); renderBulk(); $("bulk-dialog").showModal();
  await Promise.all(plan.targets.map(async target => {
    try {
      const policy = await api("account/device", {operation: "policy", device_id: target.device.id});
      if (current !== session) return;
      target.policy = policy;
      target.message = `Будет изменена ревизия ${policy.revision}. Текущие порты источника: ${ports(policy.permissions[rule.key]?.tcp || [])}.`;
    } catch (error) { if (current === session) target.message = error.message + " Изменение не будет отправлено."; }
    if (current === session) renderBulk();
  }));
  if (current !== session) return;
  bulkBusy = false; $("close-bulk").disabled = false;
  $("confirm-bulk").disabled = !plan.targets.some(target => target.policy);
  if (!plan.targets.length) showError($("bulk-error"), "Нет других собственных устройств для применения разрешения.");
}
$("confirm-bulk").addEventListener("click", async () => {
  if (!bulkPlan || bulkBusy || $("confirm-bulk").disabled) return;
  const plan = bulkPlan, current = session;
  bulkBusy = true; $("confirm-bulk").disabled = true; $("close-bulk").disabled = true;
  await Promise.all(plan.targets.filter(target => target.policy).map(async target => {
    target.message = "Сохраняем…"; renderBulk();
    try {
      const permission = {tcp: plan.tcp, ...(plan.terminal ? {terminal: true} : {}), ...(plan.files ? {files: true} : {})};
      const data = await api("account/device", {operation: "save_policy", device_id: target.device.id, base_revision: target.policy.revision, permissions: {...target.policy.permissions, [plan.key]: permission}});
      if (current !== session) return;
      target.saved = true; target.savedRevision = data.revision; target.message = policyState(data); knownPolicies.set(target.device.id, data);
    } catch (error) {
      if (current !== session) return;
      target.message = error.status === 409 ? "Конфликт изменений. Разрешение не сохранено; откройте предварительный просмотр заново." : error.message + " Сохранение не подтверждено. Проверьте актуальную политику перед повтором.";
    }
    if (current === session) renderBulk();
  }));
  if (current !== session) return;
  bulkBusy = false; $("close-bulk").disabled = false;
  renderMap();
});
async function refreshBulkResults(current) {
  if (!$("bulk-dialog").open || !bulkPlan || bulkBusy || bulkRefreshing) return;
  const plan = bulkPlan;
  bulkRefreshing = true;
  try {
    await Promise.all(plan.targets.filter(target => target.saved).map(async target => {
      try {
        const policy = await api("account/device", {operation: "policy", device_id: target.device.id});
        if (current !== session || bulkPlan !== plan) return;
        // Later edits must not be reported as acknowledgement of this operation.
        target.message = policy.revision === target.savedRevision
          ? policyState(policy) : `После операции политика изменена · ревизия ${policy.revision}. Проверьте актуальные разрешения.`;
        knownPolicies.set(target.device.id, policy);
      } catch (error) { if (current === session && bulkPlan === plan) target.message = "Нет актуального подтверждения: " + error.message; }
    }));
    if (current === session && bulkPlan === plan) { renderBulk(); renderMap(); }
  } finally { if (current === session) bulkRefreshing = false; }
}

$("close-bulk").addEventListener("click", () => { if (!bulkBusy) $("bulk-dialog").close(); });
$("bulk-dialog").addEventListener("cancel", event => { if (bulkBusy) event.preventDefault(); });

async function ownerOperation(operation, extra = {}) {
  const peer = selectedPeer(); if (!peer?.owned || ownerBusy) return;
  ownerBusy = true; const current = session; $("rename-submit").disabled = true; $("revoke-device").disabled = true; showError($("owner-error"), "");
  try { await api("account/device", {operation, device_id:peer.device_id, ...extra}); if (current !== session) return; $("details-dialog").close(); await loadAccount(); await refresh(); toast(operation === "rename" ? "Имя устройства сохранено" : "Устройство отозвано. Старые карты ограничены сроком действия."); }
  catch (error) { if (current === session) showError($("owner-error"), error.message); }
  finally { if (current === session) { ownerBusy = false; $("rename-submit").disabled = false; $("revoke-device").disabled = false; } }
}
$("rename-form").addEventListener("submit", event => { event.preventDefault(); ownerOperation("rename", {name:$("rename-name").value.trim()}); });
$("revoke-device").addEventListener("click", () => ownerOperation("revoke"));

let accessSignature = "";
const seenAccessRequests = new Set();
function renderAccessRequests() {
  const requests = account?.access_requests || [];
  const signature = JSON.stringify([account?.user?.id, accountStale, requests]);
  if (signature === accessSignature) return;
  accessSignature = signature;
  const incoming = requests.filter(r => r.target.owner_user_id === account?.user?.id && r.status === "pending");
  $("access-notifications").hidden = !requests.length;
  $("access-request-heading").textContent = `Запросы доступа · входящих: ${incoming.length}`;
  $("access-request-list").replaceChildren(...requests.slice(0, 64).map(request => {
    const row = element("article", "setup-card");
    const mine = request.target.owner_user_id === account?.user?.id;
    row.append(element("strong", "", `${request.requester_name}: ${request.source.name} → ${request.target.name}`));
    row.append(element("p", "scope-note", `TCP ${ports(request.tcp)}${request.files ? " · File Explorer" : ""} · ${new Date(request.created_at * 1000).toLocaleString("ru-RU")}`));
    const labels = {pending: mine ? "Ожидает вашего решения" : "Ожидает решения владельца", accepted: "Одобрено. Доступ появится после применения разрешения устройством.", declined: "Владелец отклонил запрос", expired: "Срок запроса истёк"};
    row.append(element("p", "", labels[request.status] || request.status));
    if (mine && request.status === "pending") {
      for (const [accept, label] of [[true, "Принять"], [false, "Отклонить"]]) {
        const button = element("button", "button secondary", label);
        button.type = "button";
        button.disabled = accountStale;
        button.addEventListener("click", async () => {
          const current = session;
          for (const item of row.querySelectorAll("button")) item.disabled = true;
          showError($("access-notification-error"), "");
          try {
            await api("account/device", {operation: "decide_access", request_id: request.id, accept});
            if (current !== session) return;
            await loadAccount(); await refresh();
          } catch (error) { if (current === session) showError($("access-notification-error"), error.message); }
          finally { if (current === session) for (const item of row.querySelectorAll("button")) item.disabled = false; }
        });
        row.append(button);
      }
    }
    return row;
  }));
  if (incoming.some(request => !seenAccessRequests.has(request.id))) toast("Получен запрос доступа к вашему устройству");
  for (const request of requests) seenAccessRequests.add(request.id);
}
$("request-access-form").addEventListener("submit", async event => {
  event.preventDefault();
  const peer = selectedPeer();
  if (peer?.owned !== false || !snapshot?.network?.device_id) return;
  let tcp;
  const files = $("request-files").checked;
  try {
    tcp = parseRule(snapshot.interface.public_key, $("request-ports").value).tcp;
    if (!tcp.length && !files) throw new Error("Укажите TCP-порт или включите File Explorer");
  } catch (error) { showError($("request-access-error"), error.message); return; }
  const current = session;
  $("request-access-submit").disabled = true;
  showError($("request-access-error"), "");
  try {
    await api("account/device", {operation: "request_access", source_device_id: snapshot.network.device_id, target_device_id: peer.device_id, tcp, files});
    if (current !== session) return;
    toast("Запрос отправлен владельцу устройства");
    await loadAccount();
  } catch (error) { if (current === session) showError($("request-access-error"), error.message); }
  finally { if (current === session) $("request-access-submit").disabled = false; }
});

navigate();
restoreSession();
