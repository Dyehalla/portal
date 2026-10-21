const $ = (id) => document.getElementById(id);
const svgNS = 'http://www.w3.org/2000/svg';
const session = { token: '', snapshot: null, generation: 0, page: 'devices', refreshing: false };
const browser = { peer: '', path: '', offset: 0, previous: [], entries: [], next: null, serial: 0, controller: null, loaded: false };
const aliasKey = `portal.device-names:${location.host}`;
let aliases = {};
try { aliases = JSON.parse(localStorage.getItem(aliasKey) || '{}'); } catch { /* Storage is optional. */ }
if (!aliases || typeof aliases !== 'object' || Array.isArray(aliases)) aliases = {};
let editingKey = null;
let confirmation = null;
let downloadController = null;

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}
function icon(name) {
  const node = document.createElementNS(svgNS, 'svg');
  node.classList.add('icon');
  node.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(svgNS, 'use');
  use.setAttribute('href', `#i-${name}`);
  node.append(use);
  return node;
}
function action(name, label, handler, className = 'icon-button') {
  const button = element('button', className);
  button.type = 'button';
  button.title = label;
  button.setAttribute('aria-label', label);
  button.append(icon(name));
  button.addEventListener('click', handler);
  return button;
}
function shortKey(key) { return `${key.slice(0, 8)}…${key.slice(-6)}`; }
function peerName(peer) {
  return typeof aliases[peer.public_key] === 'string' && aliases[peer.public_key]
    ? aliases[peer.public_key] : `Устройство ${peer.public_key.slice(0, 6)}`;
}
function saveAliases() {
  try { localStorage.setItem(aliasKey, JSON.stringify(aliases)); } catch { /* Browsing works without storage. */ }
}
function bytes(value = 0) {
  const units = ['Б', 'КиБ', 'МиБ', 'ГиБ', 'ТиБ'];
  const unit = Math.min(value > 0 ? Math.floor(Math.log(value) / Math.log(1024)) : 0, units.length - 1);
  return `${(value / 1024 ** unit).toLocaleString('ru-RU', { maximumFractionDigits: unit ? 1 : 0 })} ${units[unit]}`;
}
function date(value) {
  return value == null ? '—' : new Date(value * 1000).toLocaleString('ru-RU', { dateStyle: 'short', timeStyle: 'short' });
}
function errorText(error) { return error instanceof TypeError ? 'Нет связи с Portal. Проверьте, что приложение запущено.' : error.message; }
function showError(id, error) { $(id).textContent = errorText(error); $(id).hidden = false; }
function toast(message, error = false) {
  const node = element('div', `toast${error ? ' error' : ''}`);
  node.append(icon(error ? 'info' : 'check'), element('span', '', message));
  $('toast-stack').append(node);
  while ($('toast-stack').children.length > 3) $('toast-stack').firstChild.remove();
  setTimeout(() => node.remove(), 5500);
}
function connection(connected, message) {
  $('connection-status').className = `connection-status ${connected ? 'connected' : 'disconnected'}`;
  $('connection-label').textContent = message;
}
async function request(path, payload = {}, signal, token = session.token) {
  const response = await fetch(path, {
    method: 'POST', cache: 'no-store', signal,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    let message = `Ошибка запроса (${response.status})`;
    try { const body = await response.json(); message = body.message || body.error || message; } catch { /* Non-JSON proxy errors. */ }
    if (response.status === 401) {
      message = 'Токен не принят. Выберите актуальный файл доступа.';
      if (session.token && session.token === token) logout(message);
    }
    throw new Error(message);
  }
  return response;
}
async function json(path, payload, signal, token) { return (await request(path, payload, signal, token)).json(); }
const command = (operation, fields = {}) => json('/api/v1/command', { operation, ...fields });

function renderSnapshot(snapshot) {
  session.snapshot = snapshot;
  connection(snapshot.healthy, snapshot.healthy ? 'Portal работает' : 'Portal останавливается');
  $('connection-notice').hidden = true;
  $('peer-count').textContent = snapshot.peers.length;
  $('nav-peer-count').textContent = snapshot.peers.length;
  $('table-peer-count').textContent = snapshot.peers.length;
  $('connection-count').textContent = snapshot.stats.connections;
  const [amount, unit] = bytes(snapshot.stats.tx_bytes + snapshot.stats.rx_bytes).split(' ');
  $('traffic-total').replaceChildren(document.createTextNode(amount), element('span', 'unit', ` ${unit}`));
  $('traffic-caption').textContent = `↑ ${bytes(snapshot.stats.tx_bytes)} · ↓ ${bytes(snapshot.stats.rx_bytes)}`;
  $('sidebar-key').textContent = shortKey(snapshot.public_key);
  $('system-key').textContent = snapshot.public_key;
  $('system-api').textContent = location.host;
  $('system-listen').textContent = snapshot.listen || 'Только через relay';
  $('system-health').textContent = snapshot.healthy ? 'Работает' : 'Останавливается';
  $('relay-panel').hidden = !snapshot.relay_server;
  if (snapshot.relay_server) {
    $('system-relay-endpoint').textContent = snapshot.relay_server.endpoint;
    $('relay-clients').textContent = snapshot.relay_server.connected_clients;
    $('relay-allowed-count').textContent = snapshot.relay_server.allowed_peers.length;
    $('relay-mode').textContent = 'Peer relay · UDP / QUIC';
  }
  $('reload-services').disabled = !snapshot.can_reload;
  $('reload-hint').textContent = snapshot.can_reload ? 'Сервисы будут загружены из текущего файла конфигурации.' : 'Для перезагрузки запустите runtime с файлом конфигурации.';
  $('last-updated').textContent = `Обновлено ${new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' })}`;
  renderPeers();
  const select = $('file-peer');
  select.replaceChildren(new Option('Выберите устройство', ''));
  for (const peer of snapshot.peers) select.add(new Option(`${peerName(peer)} · ${shortKey(peer.public_key)}`, peer.public_key));
  if (snapshot.peers.some((peer) => peer.public_key === browser.peer)) select.value = browser.peer;
  else if (browser.peer) resetBrowser();
}
async function refresh(announce = false) {
  if (!session.token || session.refreshing) return;
  session.refreshing = true;
  const generation = session.generation;
  $('refresh-button').classList.add('loading');
  try {
    const snapshot = await json('/api/v1/state');
    if (generation !== session.generation) return;
    renderSnapshot(snapshot);
    if (announce) toast('Состояние обновлено');
  } catch (error) {
    if (generation !== session.generation) return;
    connection(false, 'Нет связи');
    showError('connection-notice', error);
  } finally {
    session.refreshing = false;
    $('refresh-button').classList.remove('loading');
  }
}
function renderPeers() {
  const peers = session.snapshot?.peers || [];
  const query = $('device-search').value.trim().toLocaleLowerCase();
  const filter = $('device-filter').value;
  const visible = peers.filter((peer) => `${peerName(peer)} ${peer.public_key} ${peer.endpoint || ''}`.toLocaleLowerCase().includes(query) && (filter === 'all' || peer.path === filter));
  $('device-rows').replaceChildren();
  for (const peer of visible) {
    const name = peerName(peer);
    const row = element('tr');
    const identity = element('td');
    const cell = element('div', 'identity-cell');
    const avatar = element('span', 'device-avatar'); avatar.append(icon('laptop'));
    const description = element('div');
    const title = element('div', 'identity-title'); title.append(element('span', 'peer-name', name));
    if (peer.relay_server) title.append(element('span', 'role-badge', 'Реле'));
    description.append(title);
    const subtitle = element('div', 'identity-subtitle');
    subtitle.append(element('code', 'key-short', shortKey(peer.public_key)), action('copy', `Скопировать ключ: ${name}`, () => copy(peer.public_key)));
    description.append(subtitle); cell.append(avatar, description); identity.append(cell);
    const transport = element('td');
    const label = { direct: 'Напрямую', relay: 'Через relay', connecting: 'Подключение', offline: 'Не подключено' }[peer.path] || peer.path;
    const badge = element('span', `path-badge ${peer.path}`); badge.append(element('span', 'small-dot'), document.createTextNode(label));
    transport.append(badge, element('div', 'connection-detail', peer.endpoint || (peer.relay ? 'Адрес через relay' : 'Сеанс ещё не открыт')));
    const traffic = element('td', 'traffic-cell'); traffic.append(element('span', '', `↑ ${bytes(peer.stats.tx_bytes)}`), element('span', '', `↓ ${bytes(peer.stats.rx_bytes)}`));
    const actions = element('td'); const buttons = element('div', 'row-actions');
    const files = action('folder', `Открыть файлы: ${name}`, () => { setPage('files'); openPeer(peer.public_key); }, 'button secondary file-action');
    files.append(document.createTextNode('Файлы'));
    buttons.append(files, action('info', `Сведения об устройстве: ${name}`, () => inspectPeer(peer)), action('edit', `Изменить: ${name}`, () => editDevice(peer)), action('trash', `Удалить: ${name}`, () => removeDevice(peer)));
    actions.append(buttons); row.append(identity, transport, traffic, actions); $('device-rows').append(row);
  }
  $('devices-empty').hidden = visible.length > 0;
  $('devices-empty').classList.toggle('search-empty', peers.length > 0);
  $('devices-empty').querySelector('h3').textContent = peers.length ? 'Устройства не найдены' : 'Всё начинается с подключения';
  $('devices-empty').querySelector('p').textContent = peers.length ? 'Попробуйте другое название или измените фильтр подключения.' : 'Добавьте публичный ключ другого устройства. Оно появится здесь, и вы сможете открыть его файлы.';
  $('empty-add-device').hidden = peers.length > 0;
}
function setPage(page) {
  if (!['devices', 'files', 'system'].includes(page)) page = 'devices';
  session.page = page;
  for (const button of document.querySelectorAll('[data-page]')) {
    const active = button.dataset.page === page;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page'); else button.removeAttribute('aria-current');
    $(`page-${button.dataset.page}`).hidden = !active;
  }
  $('page-label').textContent = { devices: 'Устройства', files: 'Файлы', system: 'Система' }[page];
  history.replaceState(null, '', `#${page}`);
  mobileMenu(false);
}
function mobileMenu(open) {
  const mobile = matchMedia('(max-width: 720px)').matches;
  const wasOpen = $('sidebar').classList.contains('open');
  if (mobile && wasOpen && !open) $('menu-toggle').focus();
  $('sidebar').inert = mobile && !open;
  $('sidebar').classList.toggle('open', open);
  $('mobile-backdrop').hidden = !open;
  $('menu-toggle').setAttribute('aria-expanded', String(open));
}
async function copy(value) {
  try { await navigator.clipboard.writeText(value); toast('Публичный ключ скопирован'); }
  catch { toast('Не удалось скопировать. Выделите ключ в разделе «Система».', true); }
}
function editDevice(peer = null) {
  editingKey = peer?.public_key || null;
  $('device-form').reset();
  $('device-error').hidden = true;
  $('device-dialog-title').textContent = peer ? 'Изменить устройство' : 'Добавить устройство';
  $('device-submit').textContent = peer ? 'Сохранить изменения' : 'Добавить устройство';
  $('device-name').value = peer ? aliases[peer.public_key] || '' : '';
  $('device-key').value = peer?.public_key || '';
  $('device-key').readOnly = Boolean(peer);
  $('device-endpoint').value = peer?.endpoint || '';
  $('device-relay-key').value = peer?.relay?.public_key || '';
  $('device-relay-endpoint').value = peer?.relay?.endpoint || '';
  $('device-relay-permission').hidden = !session.snapshot?.relay_server;
  $('device-allow-relay').checked = peer?.relay_allowed || false;
  $('device-dialog').showModal();
}
function confirm(title, description, label, callback) {
  confirmation = callback;
  $('confirm-title').textContent = title;
  $('confirm-description').textContent = description;
  $('confirm-action').textContent = label;
  $('confirm-error').hidden = true;
  $('confirm-dialog').showModal();
}
function removeDevice(peer) {
  confirm('Удалить устройство?', `«${peerName(peer)}» потеряет доступ к этому устройству. Активные соединения будут закрыты.`, 'Удалить устройство', async () => {
    await command('peer_remove', { public_key: peer.public_key });
    delete aliases[peer.public_key]; saveAliases();
    if (browser.peer === peer.public_key) resetBrowser();
    await refresh(); toast('Устройство удалено');
  });
}

function fileMessage(title, message) {
  $('file-message').hidden = false;
  $('file-message').querySelector('h3').textContent = title;
  $('file-message').querySelector('p').textContent = message;
  $('file-table-wrap').hidden = true;
}
function resetBrowser() {
  browser.controller?.abort(); browser.serial++;
  Object.assign(browser, { peer: '', path: '', offset: 0, previous: [], entries: [], next: null, loaded: false });
  $('file-peer').value = '';
  $('file-rows').replaceChildren();
  $('file-breadcrumbs').replaceChildren(element('span', '', 'Файлы'));
  $('file-source-status').textContent = 'Выберите источник файлов';
  $('file-range').textContent = 'Нет открытой папки';
  $('previous-page').disabled = true; $('next-page').disabled = true;
  fileMessage('Выберите устройство', 'Здесь появятся доступные вам файлы и папки.');
}
async function openPeer(key) {
  resetBrowser();
  browser.peer = key;
  $('file-peer').value = key;
  if (key) {
    // Capability discovery is optional and must not block the file browser.
    inspectPeer({ public_key: key }, false);
    await loadFolder('', 0, true);
  }
}
async function inspectPeer(peer, show = true) {
  const generation = session.generation;
  try {
    const info = await json('/api/v1/peers/info', { peer: peer.public_key });
    if (generation !== session.generation) return;
    await refresh();
    if (generation !== session.generation) return;
    if (!show) return;
    $('details-title').textContent = 'Сведения об устройстве';
    $('file-details').replaceChildren();
    for (const [label, value] of [['Устройство', peerName(peer)], ['Публичный ключ', info.public_key], ['Роль', info.relay_server ? 'Пир и реле' : 'Пир'], ['UDP-адрес реле', info.relay_server?.endpoint || 'Реле выключено']]) {
      const row = element('div'); row.append(element('dt', '', label), element('dd', '', value)); $('file-details').append(row);
    }
    $('details-dialog').showModal();
  } catch (error) { if (show && generation === session.generation) toast(errorText(error), true); }
}
function renderBreadcrumbs() {
  const crumbs = $('file-breadcrumbs'); crumbs.replaceChildren();
  const root = element('button', '', 'Файлы'); root.addEventListener('click', () => loadFolder('', 0)); crumbs.append(root);
  let path = '';
  for (const part of browser.path.split('/').filter(Boolean)) {
    path += (path ? '/' : '') + part;
    const target = path;
    const button = element('button', '', part); button.addEventListener('click', () => loadFolder(target, 0));
    crumbs.append(icon('chevron'), button);
  }
}
async function loadFolder(path = browser.path, offset = browser.offset, checkResources = false, previous = []) {
  if (!browser.peer || !session.token) return;
  browser.controller?.abort();
  const controller = new AbortController(); browser.controller = controller;
  const serial = ++browser.serial;
  const peer = browser.peer;
  browser.loaded = false;
  $('file-source-status').textContent = 'Подключаемся к устройству…';
  $('previous-page').disabled = true; $('next-page').disabled = true;
  fileMessage('Открываем папку…', 'Устанавливаем зашифрованное соединение и получаем список файлов.');
  try {
    if (checkResources) {
      const resources = await json('/api/v1/files/resources', { peer }, controller.signal);
      if (!resources.resources.length) {
        if (serial !== browser.serial) return;
        fileMessage('Нет доступных папок', 'На этом устройстве нет папок, открытых для вашего публичного ключа.');
        $('file-source-status').textContent = 'Нет доступа к файлам';
        return;
      }
    }
    const listing = await json('/api/v1/files/list', { peer, path, offset, limit: 50 }, controller.signal);
    if (serial !== browser.serial) return;
    Object.assign(browser, { path: listing.path, offset, previous, entries: listing.entries, next: listing.next_offset, loaded: true });
    $('file-search').value = '';
    renderBreadcrumbs(); renderFiles();
    $('file-source-status').textContent = 'Доступ только для чтения';
    refresh();
  } catch (error) {
    if (controller.signal.aborted || serial !== browser.serial) return;
    fileMessage('Не удалось открыть папку', errorText(error));
    $('file-source-status').textContent = 'Ошибка подключения';
    $('file-range').textContent = 'Повторите запрос кнопкой обновления';
  }
}
function renderFiles() {
  if (!browser.loaded) return;
  const query = $('file-search').value.toLocaleLowerCase();
  const entries = browser.entries.filter((entry) => entry.name.toLocaleLowerCase().includes(query));
  $('file-rows').replaceChildren();
  for (const entry of entries) {
    const row = element('tr');
    const name = element('td');
    const button = element('button', 'file-name-button');
    const image = element('span', `file-type-icon ${entry.kind === 'directory' ? '' : 'file'}`);
    image.append(icon(entry.kind === 'directory' ? 'folder' : entry.kind === 'symlink' ? 'link' : 'file'));
    button.append(image, element('span', '', entry.name));
    button.addEventListener('click', () => openEntry(entry));
    if (entry.kind === 'other') button.disabled = true;
    name.append(button);
    const size = element('td', '', entry.size_bytes == null ? '—' : bytes(entry.size_bytes));
    const modified = element('td', '', date(entry.modified_at_unix_seconds));
    const actions = element('td'); const buttons = element('div', 'row-actions');
    buttons.append(action('info', `Сведения: ${entry.name}`, () => details(entry)));
    if (entry.kind === 'file') buttons.append(action('download', `Скачать: ${entry.name}`, () => download(entry)));
    actions.append(buttons); row.append(name, size, modified, actions); $('file-rows').append(row);
  }
  if (!entries.length) fileMessage(browser.entries.length ? 'Ничего не найдено' : 'В этой папке пока пусто', browser.entries.length ? 'Поиск работает на текущей странице. Попробуйте другое название.' : 'Вы можете открыть другую папку с помощью пути выше.');
  else { $('file-message').hidden = true; $('file-table-wrap').hidden = false; }
  $('file-range').textContent = browser.entries.length ? `Записи ${browser.offset + 1}–${browser.offset + browser.entries.length}${query ? ` · найдено ${entries.length}` : ''}` : '0 записей';
  $('previous-page').disabled = !browser.previous.length;
  $('next-page').disabled = browser.next == null;
}
async function openEntry(entry) {
  const serial = browser.serial;
  try {
    if (entry.kind === 'symlink') entry = await json('/api/v1/files/metadata', { peer: browser.peer, path: entry.path });
    if (serial !== browser.serial) return;
    if (entry.kind === 'directory') await loadFolder(entry.path, 0);
    else if (entry.kind === 'file') await download(entry);
    else toast('Этот тип файла недоступен для открытия', true);
  } catch (error) { toast(errorText(error), true); }
}
async function details(entry) {
  const peer = browser.peer;
  const generation = session.generation;
  try {
    const metadata = await json('/api/v1/files/metadata', { peer, path: entry.path });
    if (generation !== session.generation) return;
    $('details-title').textContent = metadata.name;
    $('file-details').replaceChildren();
    const kind = { file: 'Файл', directory: 'Папка', symlink: 'Символическая ссылка', other: 'Другой' };
    for (const [label, value] of [['Название', metadata.name], ['Путь', metadata.path || '/'], ['Тип', kind[metadata.kind]], ['Размер', metadata.size_bytes == null ? '—' : bytes(metadata.size_bytes)], ['Изменено', date(metadata.modified_at_unix_seconds)]]) {
      const row = element('div'); row.append(element('dt', '', label), element('dd', '', value)); $('file-details').append(row);
    }
    $('details-dialog').showModal();
  } catch (error) { toast(errorText(error), true); }
}
async function download(entry) {
  if (downloadController) { toast('Дождитесь текущего скачивания или отмените его'); return; }
  const controller = new AbortController(); downloadController = controller;
  const peer = browser.peer;
  let writer;
  let reader;
  try {
    // Where supported, stream directly to disk rather than keeping the file in memory.
    if ('showSaveFilePicker' in window) {
      const handle = await window.showSaveFilePicker({ suggestedName: entry.name });
      if (controller.signal.aborted) throw new DOMException('Cancelled', 'AbortError');
      writer = await handle.createWritable();
    }
    $('transfer-card').hidden = false;
    $('transfer-name').textContent = entry.name;
    $('transfer-status').textContent = 'Подключение…';
    $('transfer-progress').removeAttribute('value');
    const response = await request('/api/v1/files/download', { peer, path: entry.path }, controller.signal);
    const total = Number(response.headers.get('content-length')) || entry.size_bytes || 0;
    reader = response.body.getReader();
    const chunks = [];
    let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (writer) await writer.write(value); else chunks.push(value);
      received += value.length;
      $('transfer-status').textContent = `${bytes(received)}${total ? ` из ${bytes(total)}` : ''}`;
      if (total) $('transfer-progress').value = received / total * 100;
    }
    if (controller.signal.aborted) throw new DOMException('Cancelled', 'AbortError');
    if (writer) await writer.close();
    else {
      const url = URL.createObjectURL(new Blob(chunks));
      const link = element('a'); link.href = url; link.download = entry.name; link.hidden = true;
      document.body.append(link); link.click(); link.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);
    }
    toast(`Файл «${entry.name}» скачан`);
  } catch (error) {
    if (writer) { try { await writer.abort(); } catch { /* Already closed. */ } }
    if (reader) { try { await reader.cancel(); } catch { /* Request already aborted. */ } }
    if (error.name !== 'AbortError') toast(errorText(error), true);
  } finally {
    $('transfer-card').hidden = true;
    downloadController = null;
  }
}

function logout(message) {
  session.token = ''; session.snapshot = null; session.generation++;
  downloadController?.abort(); resetBrowser();
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
  $('access-token').value = '';
  $('login-error').hidden = !message;
  if (message) $('login-error').textContent = message;
  for (const id of ['peer-count', 'connection-count', 'traffic-total', 'sidebar-key', 'system-key', 'system-health', 'nav-peer-count']) $(id).textContent = '—';
  $('device-rows').replaceChildren();
  connection(false, 'Не подключено');
  $('login-dialog').showModal();
}

$('login-origin').textContent = location.host;
$('login-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('login-error').hidden = true; $('login-submit').disabled = true;
  const token = $('access-token').value.trim();
  try {
    const snapshot = await json('/api/v1/state', {}, undefined, token);
    session.generation++; session.token = token;
    renderSnapshot(snapshot); $('access-token').value = ''; $('login-dialog').close();
    if (session.page === 'files') resetBrowser();
  } catch (error) { showError('login-error', error); }
  finally { $('login-submit').disabled = false; }
});
$('token-file').addEventListener('change', async (event) => {
  const file = event.target.files[0]; if (!file) return;
  try {
    if (file.size > 4096) throw new Error('Выберите небольшой текстовый файл токена, созданный Portal.');
    $('access-token').value = (await file.text()).trim();
    $('login-form').requestSubmit();
  } catch (error) { showError('login-error', error); }
  event.target.value = '';
});
$('login-dialog').addEventListener('cancel', (event) => event.preventDefault());
$('logout-button').addEventListener('click', () => logout());
for (const button of document.querySelectorAll('[data-page]')) button.addEventListener('click', () => setPage(button.dataset.page));
for (const button of document.querySelectorAll('[data-close]')) button.addEventListener('click', () => $(button.dataset.close).close());
$('menu-toggle').addEventListener('click', () => mobileMenu($('menu-toggle').getAttribute('aria-expanded') !== 'true'));
$('mobile-backdrop').addEventListener('click', () => mobileMenu(false));
window.addEventListener('resize', () => mobileMenu(false));
document.addEventListener('keydown', (event) => { if (event.key === 'Escape') mobileMenu(false); });
$('refresh-button').addEventListener('click', () => refresh(true));
$('device-search').addEventListener('input', renderPeers);
$('device-filter').addEventListener('change', renderPeers);
$('add-device').addEventListener('click', () => editDevice());
$('empty-add-device').addEventListener('click', () => editDevice());
$('device-form').addEventListener('submit', async (event) => {
  event.preventDefault(); $('device-error').hidden = true; $('device-submit').disabled = true;
  const key = $('device-key').value.trim().toLowerCase();
  try {
    const relayKey = $('device-relay-key').value.trim().toLowerCase();
    const relayEndpoint = $('device-relay-endpoint').value.trim();
    if (Boolean(relayKey) !== Boolean(relayEndpoint)) throw new Error('Укажите и публичный ключ, и UDP-адрес пира-реле.');
    await command('peer_upsert', { public_key: key, endpoint: $('device-endpoint').value.trim() || null, relay: relayKey ? { public_key: relayKey, endpoint: relayEndpoint } : null,
      allow_relay: session.snapshot?.relay_server ? $('device-allow-relay').checked : undefined });
    aliases[key] = $('device-name').value.trim(); saveAliases();
    $('device-dialog').close(); await refresh(); toast(editingKey ? 'Устройство обновлено' : 'Устройство добавлено');
  } catch (error) { showError('device-error', error); }
  finally { $('device-submit').disabled = false; }
});
$('confirm-action').addEventListener('click', async () => {
  $('confirm-action').disabled = true; $('confirm-error').hidden = true;
  try { await confirmation(); $('confirm-dialog').close(); }
  catch (error) { showError('confirm-error', error); }
  finally { $('confirm-action').disabled = false; }
});
$('file-peer').addEventListener('change', (event) => openPeer(event.target.value));
$('file-search').addEventListener('input', renderFiles);
$('refresh-files').addEventListener('click', () => loadFolder(browser.path, browser.offset, !browser.loaded, browser.previous));
$('previous-page').addEventListener('click', () => {
  if (!browser.previous.length) return;
  const previous = browser.previous.slice(); const offset = previous.pop(); loadFolder(browser.path, offset, false, previous);
});
$('next-page').addEventListener('click', () => { if (browser.next != null) loadFolder(browser.path, browser.next, false, [...browser.previous, browser.offset]); });
$('cancel-download').addEventListener('click', () => downloadController?.abort());
$('copy-self-key').addEventListener('click', () => session.snapshot && copy(session.snapshot.public_key));
$('copy-relay-endpoint').addEventListener('click', async () => {
  try { await navigator.clipboard.writeText(session.snapshot.relay_server.endpoint); toast('Адрес реле скопирован'); }
  catch { toast('Не удалось скопировать адрес реле', true); }
});
$('reload-services').addEventListener('click', () => {
  confirm('Перезагрузить сервисы?', 'Будет применена конфигурация сервисов из файла. Текущие передачи файлов могут прерваться.', 'Перезагрузить', async () => {
    await command('services_reload'); await refresh(); toast('Сервисы перезагружены');
    if (browser.peer) loadFolder(browser.path, 0, true);
  });
});
$('shutdown-runtime').addEventListener('click', () => {
  confirm('Остановить Portal?', 'Все соединения будут закрыты. Чтобы вернуться, запустите приложение снова.', 'Остановить', async () => {
    await command('shutdown'); session.token = ''; session.generation++; downloadController?.abort(); browser.controller?.abort();
    connection(false, 'Portal остановлен'); $('connection-notice').hidden = false;
    $('connection-notice').textContent = 'Portal остановлен. Запустите приложение и обновите эту страницу для подключения.';
    $('refresh-button').disabled = true; $('reload-services').disabled = true; $('shutdown-runtime').disabled = true;
  });
});
setInterval(() => { if (!document.hidden) refresh(); }, 5000);
document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
setPage(location.hash.slice(1));
logout();
