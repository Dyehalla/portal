const $ = (id) => document.getElementById(id);
const number = new Intl.NumberFormat("ru-RU");
const tokenStorageKey = "portal.local-api-token";
let token = "";
let session = 0;
let snapshot = null;
let receivedAt = 0;
let pollTimer;
let toastTimer;
let refreshing = false;
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
    body?.operation === "connect" ? 16000 : 8000,
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
        "Агент не отвечает. Проверьте, что portal-runtime запущен.",
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
  try {
    sessionStorage.removeItem(tokenStorageKey);
  } catch {
    // Login and logout also work when browser storage is disabled.
  }
  snapshot = null;
  clearTimeout(pollTimer);
  for (const request of requests) request.abort();
  connecting.clear();
  refreshing = false;
  $("token").value = "";
  $("token-file").value = "";
  $("peer-search").value = "";
  $("peer-rows").replaceChildren();
  $("app").hidden = true;
  $("auth-view").hidden = false;
  $("sign-in").disabled = false;
  $("select-token").disabled = false;
  $("sign-in").textContent = "Открыть панель →";
  $("toast").hidden = true;
  showError($("auth-error"), message);
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
    $("refresh").focus();
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
    if (current === session) render(data);
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
    $("agent-state").className = "badge error";
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

function render(data) {
  snapshot = data;
  receivedAt = performance.now();
  showError($("connection-error"), "");
  $("refresh").disabled = false;
  $("agent-state").textContent = data.healthy
    ? "Агент работает"
    : "Ошибка агента";
  $("agent-state").className = data.healthy ? "badge" : "badge error";
  const local = data.interface;
  const network = data.network;
  $("page-title").textContent = network?.device_name || "Моё устройство";
  $("device-name").textContent = network?.device_name || "Это устройство";
  $("device-subtitle").textContent = network
    ? "Устройство в сети Portal"
    : "Ручное управление WireGuard";
  $("interface-name").textContent = local.name;
  $("mode-label").textContent =
    data.mode === "managed" ? "Управляется координатором" : "Ручной режим";
  const addresses = local.addresses.map((ip) => ip.split("/")[0]);
  $("primary-ip").textContent =
    addresses.find((ip) => !ip.includes(":")) || addresses[0] || "Не назначен";
  $("secondary-ip").textContent =
    addresses.find((ip) => ip.includes(":")) ||
    (addresses.length ? "IPv6 не назначен" : "Настройте адрес интерфейса");
  $("copy-key").textContent = `${shortKey(local.public_key)} ⧉`;
  $("copy-key").title = `Скопировать ${local.public_key}`;
  $("peer-count").textContent = number.format(data.peers.length);
  $("peer-count-caption").textContent =
    data.mode === "managed" ? "В текущей карте сети" : "Настроено вручную";
  $("coordinator-state").textContent = network
    ? network.coordinator_connected
      ? "Есть связь"
      : "Нет связи"
    : "Ручной режим";
  $("network-revision").textContent = network
    ? `Ревизия карты · ${network.revision}`
    : "Подключение не настроено";
  $("listen-address").textContent = local.listen;
  $("device-id").textContent =
    network?.device_id || "Не используется в ручном режиме";
  $("network-id").textContent =
    network?.network_id || "Не используется в ручном режиме";
  $("policy-state").textContent = network
    ? network.policy_pending
      ? "Ожидают подтверждения координатора"
      : `Опубликованы · ревизия ${network.policy_revision}`
    : "TCP ACL Portal не применяются";
  $("udp-count").textContent = number.format(data.stats.received_udp_packets);
  $("tun-count").textContent = number.format(data.stats.received_tun_packets);
  $("drop-count").textContent = number.format(data.stats.dropped_packets);
  $("send-error-count").textContent = number.format(data.stats.udp_send_errors);
  $("last-updated").textContent =
    `Обновлено в ${new Date().toLocaleTimeString("ru-RU")}`;
  updateLease();
  renderPeers();
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

function updateLease() {
  if (!snapshot) return;
  const network = snapshot.network;
  const remaining = leaseRemaining();
  $("lease-time").textContent = network
    ? remaining
      ? `${Math.floor(remaining / 60)} мин ${remaining % 60} с`
      : "Истёк срок"
    : "Без карты";
  $("lease-caption").textContent = network
    ? "До истечения разрешений"
    : "Пиры настраиваются вручную";
  const expired = network && (!network.lease_active || remaining === 0);
  showError(
    $("lease-warning"),
    expired
      ? "Срок карты сети истёк. Управляемый трафик заблокирован до получения свежей карты от координатора."
      : network && !network.coordinator_connected
        ? "Координатор недоступен. Текущие разрешения действуют до истечения срока карты."
        : "",
  );
  for (const button of $("peer-rows").querySelectorAll("button[data-connect]"))
    button.disabled = !!expired || connecting.has(button.dataset.connect);
}
setInterval(updateLease, 1000);

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderPeers() {
  if (!snapshot) return;
  const query = $("peer-search").value.trim().toLocaleLowerCase("ru-RU");
  const peers = snapshot.peers.filter((peer) =>
    [
      peer.name,
      peer.public_key,
      peer.device_id,
      peer.endpoint,
      ...peer.allowed_ips,
    ].some((value) => value?.toLocaleLowerCase("ru-RU").includes(query)),
  );
  const fragment = document.createDocumentFragment();
  for (const peer of peers) {
    const row = element("tr");
    const identity = element("td");
    identity.append(
      element(
        "div",
        "peer-title",
        peer.name || `Пир ${peer.public_key.slice(0, 8)}`,
      ),
      element("div", "peer-key mono", shortKey(peer.public_key)),
    );
    identity.title = [peer.name, peer.device_id, peer.public_key]
      .filter(Boolean)
      .join("\n");
    const addresses = element("td");
    for (const ip of peer.allowed_ips)
      addresses.append(element("div", "peer-address mono", ip));
    addresses.append(
      element(
        "div",
        "peer-endpoint mono",
        peer.endpoint || "UDP-адрес не задан",
      ),
    );
    const permissions = element("td");
    if (peer.incoming_tcp === null) {
      permissions.append(
        element("div", "peer-note", "Ручные правила WireGuard"),
      );
    } else {
      for (const [label, ports] of [
        ["К пиру: ", peer.outgoing_tcp],
        ["К вам: ", peer.incoming_tcp],
      ]) {
        const line = element("div", "permission-line");
        line.append(
          element("span", "permission-label", label),
          document.createTextNode(
            ports.length
              ? ports.slice(0, 8).join(", ") +
                  (ports.length > 8 ? ` и ещё ${ports.length - 8}` : "")
              : "нет доступа",
          ),
        );
        line.title = `${label}${ports.join(", ") || "нет доступа"}`;
        permissions.append(line);
      }
    }
    const traffic = element("td");
    if (peer.traffic) {
      for (const [symbol, value] of [
        ["↑", peer.traffic.tx_bytes],
        ["↓", peer.traffic.rx_bytes],
      ]) {
        const line = element("div", "traffic-line");
        line.append(
          element("span", "", symbol),
          document.createTextNode(bytes(value)),
        );
        traffic.append(line);
      }
    } else traffic.append(element("span", "peer-note", "—"));
    const action = element("td");
    if (
      snapshot.mode === "managed" &&
      peer.device_id &&
      peer.outgoing_tcp.length
    ) {
      const button = element(
        "button",
        "connect-button",
        connecting.has(peer.public_key) ? "Ожидание…" : "Подключиться",
      );
      button.type = "button";
      button.dataset.connect = peer.public_key;
      button.disabled =
        connecting.has(peer.public_key) ||
        !snapshot.network?.lease_active ||
        leaseRemaining() === 0;
      action.append(button);
    } else
      action.append(
        element(
          "span",
          "peer-note",
          snapshot.mode === "managed"
            ? peer.incoming_tcp.length
              ? "Только входящие"
              : "Нет доступа"
            : "Ручной режим",
        ),
      );
    row.append(identity, addresses, permissions, traffic, action);
    fragment.append(row);
  }
  $("peer-rows").replaceChildren(fragment);
  $("empty-peers").hidden = peers.length !== 0;
  $("empty-title").textContent = query ? "Ничего не найдено" : "Пиров пока нет";
  $("empty-caption").textContent = query
    ? "Попробуйте другое имя, адрес или ключ."
    : snapshot.mode === "managed"
      ? "Пиры появятся после выдачи разрешений на устройствах."
      : "Добавьте пиров через локальный API или CLI portal peer upsert.";
  $("peer-result-count").textContent =
    `${number.format(peers.length)} из ${number.format(snapshot.peers.length)} устройств`;
}
$("peer-search").addEventListener("input", renderPeers);

$("peer-rows").addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-connect]");
  if (!button || button.disabled) return;
  const key = button.dataset.connect;
  const peer = snapshot.peers.find((item) => item.public_key === key);
  if (!peer?.device_id) return;
  const current = session;
  connecting.add(key);
  renderPeers();
  try {
    await api("command", {
      operation: "connect",
      peer_device_id: peer.device_id,
    });
    if (current === session)
      toast(
        "Запрос принят. UDP-адреса согласованы; прямой путь ещё не проверен.",
      );
  } catch (error) {
    if (current !== session) return;
    if (error.status === 401) signOut(error.message);
    else toast(error.message, true);
  } finally {
    if (current === session) {
      connecting.delete(key);
      renderPeers();
    }
  }
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
window.addEventListener("hashchange", signInFromLink);
restoreSession();
