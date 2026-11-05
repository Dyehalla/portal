import { Graph } from '@antv/x6'
import './style.css'

const $ = (selector) => document.querySelector(selector)
const owners = {
  alex: { name: 'Алексей', color: '#71889c', fill: '#f0f4f7', border: '#c4d1dc' },
  anna: { name: 'Анна', color: '#93839b', fill: '#f5f1f6', border: '#d4c9da' },
  mark: { name: 'Марк', color: '#8b9271', fill: '#f3f4ed', border: '#ced2bc' },
}
const services = { terminal: 'Терминал', desktop: 'Рабочий стол', vpn: 'VPN-туннель' }
// A bitmask gives every non-empty permission set its own stable color.
const colors = ['#aaa', '#72848c', '#9b8797', '#8779a0', '#879477', '#658c86', '#ab9170', '#7e83a0']
const canonical = (permissions) => Object.keys(services).filter((key) => permissions.includes(key))
const colorFor = (permissions) => colors[(permissions.includes('terminal') ? 1 : 0) + (permissions.includes('desktop') ? 2 : 0) + (permissions.includes('vpn') ? 4 : 0)]
const labelFor = (permissions) => canonical(permissions).map((key) => services[key]).join(' + ')
const devices = [
  { id: 'macbook', name: 'MacBook Pro', os: 'macOS Sonoma', icon: 'apple', owner: 'alex', online: true, ip: '10.42.0.2', x: 80, y: 80 },
  { id: 'ubuntu', name: 'Домашний сервер', os: 'Ubuntu 24.04', icon: 'linux', owner: 'alex', online: true, ip: '10.42.0.3', x: 460, y: 200 },
  { id: 'iphone', name: 'iPhone 15', os: 'iOS 18', icon: 'apple', owner: 'alex', online: false, seen: 'Был в сети 2 часа назад', ip: '10.42.0.4', x: 80, y: 365 },
  { id: 'thinkpad', name: 'ThinkPad X1', os: 'Windows 11', icon: 'windows', owner: 'anna', online: true, ip: '10.42.0.5', x: 840, y: 80 },
  { id: 'imac', name: 'iMac', os: 'macOS Sequoia', icon: 'apple', owner: 'anna', online: false, seen: 'Был в сети 1 день назад', ip: '10.42.0.6', x: 840, y: 365 },
  { id: 'workstation', name: 'Рабочая станция', os: 'Fedora 41', icon: 'linux', owner: 'mark', online: true, ip: '10.42.0.7', x: 460, y: 480 },
  { id: 'pixel', name: 'Pixel 8', os: 'Android 15', icon: 'android', owner: 'mark', online: false, seen: 'Был в сети 3 дня назад', ip: '10.42.0.8', x: 840, y: 620 },
  { id: 'mini', name: 'Mac mini', os: 'macOS Sequoia', icon: 'apple', owner: 'alex', online: true, ip: '10.42.0.9', x: 80, y: 620 },
]
const byId = (id) => devices.find((device) => device.id === id)
const statusFor = (device) => device.online ? 'Онлайн' : device.seen
const initialEdges = [
  ['macbook', 'ubuntu', ['terminal', 'vpn']],
  ['thinkpad', 'ubuntu', ['terminal', 'desktop']],
  ['iphone', 'ubuntu', ['vpn']],
  ['ubuntu', 'workstation', ['terminal']],
  ['workstation', 'imac', ['terminal', 'desktop']],
  ['mini', 'workstation', ['terminal', 'vpn']],
  ['pixel', 'workstation', ['vpn']],
]
const iconPaths = {
  apple: 'M17.1 12.4c0-2 1.6-3 1.7-3.1-1-1.4-2.5-1.6-3-1.6-1.3-.1-2.5.8-3.2.8-.6 0-1.6-.8-2.7-.8-1.4 0-2.7.8-3.4 2-1.5 2.5-.4 6.3 1 8.4.7 1 1.5 2.1 2.6 2 1-.1 1.4-.7 2.7-.7 1.2 0 1.6.7 2.7.7 1.1 0 1.8-1 2.5-2 .8-1.1 1.1-2.2 1.2-2.2-.1-.1-2.1-.8-2.1-3.5ZM15 6.4c.6-.8 1.1-1.8 1-2.9-.9 0-2 .6-2.7 1.4-.6.6-1.2 1.7-1 2.7 1 .1 2-.5 2.7-1.2Z',
  windows: 'M3 5.1 10.4 4v7.4H3Zm8.4-1.2L21 2.5v8.9h-9.6ZM3 12.5h7.4v7.4L3 18.8Zm8.4 0H21v8.9L11.4 20Z',
  linux: 'M12 2.5c-3 0-4 2.6-3.7 5.7-.1 1.9-2.5 4.1-2.5 7.6 0 2.8 2.6 4.9 6.2 4.9s6.2-2.1 6.2-4.9c0-3.5-2.4-5.7-2.5-7.6.3-3.1-.7-5.7-3.7-5.7ZM10 6a1 1 0 1 1 0 2 1 1 0 0 1 0-2Zm4 0a1 1 0 1 1 0 2 1 1 0 0 1 0-2Zm-2 2.2 2 1.3-2 1.2-2-1.2Zm0 3c2 0 3.6 2 3.6 4.4S14 19 12 19s-3.6-1-3.6-3.4 1.6-4.4 3.6-4.4Z',
  android: 'm7 4-1.3-2 .8-.5L8 3.6a9.7 9.7 0 0 1 8 0l1.5-2.1.8.5L17 4c2 1.3 3.5 3.3 3.7 5.7H3.3C3.5 7.3 5 5.3 7 4Zm1 2a.8.8 0 1 0 0 1.6A.8.8 0 0 0 8 6Zm8 0a.8.8 0 1 0 0 1.6A.8.8 0 0 0 16 6ZM4 11h16v7H4Zm2 6h3v5H6Zm9 0h3v5h-3Z',
}
Graph.registerNode('portal-device', {
  inherit: 'rect', width: 224, height: 100,
  markup: [
    { tagName: 'rect', selector: 'body' }, { tagName: 'rect', selector: 'iconBox' },
    { tagName: 'path', selector: 'osIcon' }, { tagName: 'text', selector: 'name' },
    { tagName: 'circle', selector: 'statusDot' }, { tagName: 'text', selector: 'status' },
    { tagName: 'path', selector: 'divider' }, { tagName: 'circle', selector: 'ownerDot' },
    { tagName: 'text', selector: 'owner' }, { tagName: 'text', selector: 'os' },
  ],
  attrs: {
    body: { rx: 8, ry: 8, strokeWidth: 1, magnet: false },
    iconBox: { x: 14, y: 15, width: 32, height: 32, rx: 6, fill: '#ffffffaa', stroke: 'none' },
    osIcon: { transform: 'translate(18,19)', fill: '#636970', stroke: 'none' },
    name: { refX: 57, refY: 25, fontSize: 12, fontWeight: 550, fill: '#343434', textAnchor: 'start' },
    statusDot: { cx: 60, cy: 46, r: 2.5 },
    status: { refX: 67, refY: 46, fontSize: 9, textAnchor: 'start', fill: '#858585' },
    divider: { d: 'M14 65H210', stroke: '#0000000b', strokeWidth: 1 },
    ownerDot: { cx: 18, cy: 82, r: 3 },
    owner: { refX: 27, refY: 82, fontSize: 9, fill: '#777', textAnchor: 'start' },
    os: { refX: 210, refY: 82, fontSize: 9, fill: '#999', textAnchor: 'end' },
  },
  ports: {
    groups: Object.fromEntries(['left', 'right', 'top', 'bottom'].map((side) => [side, {
      position: side, attrs: { circle: { r: 4, magnet: true, stroke: '#b9b9b9', strokeWidth: 1, fill: '#fff' } },
    }])),
    items: ['left', 'right', 'top', 'bottom'].map((side) => ({ id: side, group: side })),
  },
}, true)

const graph = new Graph({
  container: $('#graph'), autoResize: true, async: false, background: { color: '#fcfcfc' },
  grid: { visible: true, size: 20, type: 'dot', args: { color: '#ddd', thickness: 1 } },
  panning: { enabled: true, eventTypes: ['leftMouseDown', 'mouseWheelDown'] },
  mousewheel: { enabled: true, minScale: .3, maxScale: 1.6, factor: 1.1 },
  interacting: { edgeMovable: false, arrowheadMovable: false, vertexMovable: false, vertexAddable: false, vertexDeletable: false },
  connecting: {
    snap: { radius: 28 }, allowBlank: false, allowLoop: false, allowMulti: false, allowEdge: false,
    allowNode: true, highlight: true, connector: { name: 'smooth' },
    connectionPoint: 'boundary',
    createEdge() { return this.createEdge({ attrs: { line: { stroke: '#aaa', strokeWidth: 1.5, strokeDasharray: '5 4', targetMarker: { name: 'block', width: 7, height: 6 } } }, zIndex: 0, data: { pending: true } }) },
  },
  highlighting: { magnetAvailable: { name: 'stroke', args: { attrs: { stroke: '#a3a3a3', strokeWidth: 3 } } }, magnetAdsorbed: { name: 'stroke', args: { attrs: { stroke: '#666', strokeWidth: 3 } } } },
})
const STORAGE_KEY = 'portal-x6-demo-v1'
let loading = false
let activeEdge = null
let isNewEdge = false
let toastTimer

function toast(message) {
  clearTimeout(toastTimer)
  $('#toast').textContent = message
  $('#toast').hidden = false
  toastTimer = setTimeout(() => { $('#toast').hidden = true }, 2800)
}
function persist() {
  if (loading) return
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      positions: devices.map((device) => ({ id: device.id, ...graph.getCellById(device.id).position() })),
      edges: graph.getEdges().filter((edge) => !edge.getData()?.pending).map((edge) => ({ source: edge.getSource(), target: edge.getTarget(), permissions: edge.getData().permissions })),
    }))
  } catch { toast('Браузер не разрешает сохранять изменения. Они доступны до обновления страницы.') }
}
function styleEdge(edge, permissions) {
  const normalized = canonical(permissions)
  const color = colorFor(normalized)
  edge.setData({ permissions: normalized, pending: false })
  edge.attr('line', { stroke: color, strokeWidth: 1.8, strokeDasharray: '', targetMarker: { name: 'block', width: 7, height: 6 }, strokeLinecap: 'round' })
}
function addEdge(source, target, permissions, sourcePort, targetPort) {
  const a = graph.getCellById(source).getBBox().center
  const b = graph.getCellById(target).getBBox().center
  const vertical = Math.abs(a.y - b.y) > Math.abs(a.x - b.x)
  const edge = graph.addEdge({
    source: { cell: source, port: sourcePort || (vertical ? (a.y < b.y ? 'bottom' : 'top') : (a.x < b.x ? 'right' : 'left')) },
    target: { cell: target, port: targetPort || (vertical ? (a.y < b.y ? 'top' : 'bottom') : (a.x < b.x ? 'left' : 'right')) },
    connector: 'smooth', zIndex: 0,
  })
  styleEdge(edge, permissions)
  return edge
}
function refreshLegend() {
  const edges = graph.getEdges().filter((edge) => !edge.getData()?.pending)
  $('#edge-count').textContent = `${edges.length} ${edges.length === 1 ? 'разрешение' : edges.length > 1 && edges.length < 5 ? 'разрешения' : 'разрешений'}`
  const sets = new Map(edges.map((edge) => { const permissions = edge.getData().permissions; return [canonical(permissions).join(','), permissions] }))
  $('#edge-legend').replaceChildren(...[...sets.values()].map((permissions) => {
    const row = document.createElement('div'); row.className = 'edge-key'
    const swatch = document.createElement('span'); swatch.className = 'edge-swatch'; swatch.style.background = colorFor(permissions); swatch.style.setProperty('--edge-color', colorFor(permissions))
    const text = document.createElement('span'); text.textContent = labelFor(permissions)
    row.append(swatch, text); return row
  }))
}
function fit() {
  // Reserve room for graph controls and the legend without covering devices.
  const narrow = window.innerWidth < 760
  const padding = { top: 74, right: narrow ? 24 : 60, bottom: narrow ? 280 : 80, left: narrow ? 24 : 300 }
  graph.zoomToFit({ padding, maxScale: 1 })
  // X6 centers zoomToFit on the whole canvas; offset it into the padded area.
  const { tx, ty } = graph.translate()
  graph.translate(tx + (padding.left - padding.right) / 2, ty + (padding.top - padding.bottom) / 2)
  updateZoom()
}
function updateZoom() { $('#zoom-level').value = `${Math.round(graph.zoom() * 100)}%` }
function loadDemo(restore = true) {
  loading = true
  graph.clearCells()
  let saved
  if (restore) { try { saved = JSON.parse(localStorage.getItem(STORAGE_KEY)) } catch { /* Use the example when storage is unavailable. */ } }
  for (const device of devices) {
    const position = saved?.positions?.find((item) => item.id === device.id)
    const palette = owners[device.owner]
    graph.addNode({ id: device.id, shape: 'portal-device', x: Number.isFinite(position?.x) ? position.x : device.x, y: Number.isFinite(position?.y) ? position.y : device.y, zIndex: 1,
      attrs: { body: { fill: palette.fill, stroke: palette.border }, name: { text: device.name }, status: { text: statusFor(device), fill: device.online ? '#648471' : '#929292' }, statusDot: { fill: device.online ? '#779582' : '#bbb' }, osIcon: { d: iconPaths[device.icon] }, ownerDot: { fill: palette.color }, owner: { text: owners[device.owner].name }, os: { text: device.os } },
    })
  }
  if (Array.isArray(saved?.edges)) {
    for (const edge of saved.edges) {
      if (byId(edge.source?.cell) && byId(edge.target?.cell) && edge.source.cell !== edge.target.cell && Array.isArray(edge.permissions) && canonical(edge.permissions).length) {
        addEdge(edge.source.cell, edge.target.cell, edge.permissions, edge.source.port, edge.target.port)
      }
    }
  } else initialEdges.forEach(([source, target, permissions]) => addEdge(source, target, permissions))
  loading = false
  refreshLegend()
  requestAnimationFrame(fit)
}

function endpoint(device) {
  const element = document.createElement('div'); element.className = 'endpoint'
  const name = document.createElement('strong'); name.textContent = device.name
  const owner = document.createElement('small')
  const swatch = document.createElement('span'); swatch.className = 'swatch'; swatch.style.background = owners[device.owner].color
  owner.append(swatch, owners[device.owner].name); element.append(name, owner); return element
}
function openPermissions(edge, fresh = false) {
  activeEdge = edge; isNewEdge = fresh
  const source = byId(edge.getSourceCellId()), target = byId(edge.getTargetCellId())
  if (!source || !target) return
  const line = document.createElement('div'); line.className = 'endpoint-line'
  const arrow = document.createElement('span'); arrow.className = 'endpoint-arrow'; arrow.textContent = '→'
  line.append(endpoint(source), arrow, endpoint(target)); $('#endpoints').replaceChildren(line)
  $('#direction-description').textContent = `${source.name} сможет подключаться к ${target.name}. Обратный доступ настраивается отдельной стрелкой.`
  $('#permissions-title').textContent = fresh ? 'Новое разрешение' : 'Настройка разрешений'
  const selected = edge.getData()?.permissions || []
  document.querySelectorAll('[name="permission"]').forEach((input) => { input.checked = selected.includes(input.value) })
  $('#delete-edge').hidden = fresh
  updatePreview(); $('#permissions').showModal()
}
function selectedPermissions() { return [...document.querySelectorAll('[name="permission"]:checked')].map((input) => input.value) }
function updatePreview() {
  const permissions = selectedPermissions()
  $('#permission-color').style.background = colorFor(permissions)
  $('#permission-preview').textContent = permissions.length ? labelFor(permissions) : 'Выберите хотя бы одно разрешение'
  $('#save-permissions').disabled = !permissions.length
}
$('#permissions-form').addEventListener('change', updatePreview)
$('#permissions-form').addEventListener('submit', (event) => {
  event.preventDefault()
  const permissions = selectedPermissions()
  if (!permissions.length || !activeEdge) return
  styleEdge(activeEdge, permissions)
  activeEdge = null; isNewEdge = false
  $('#permissions').close(); refreshLegend(); persist(); toast('Разрешение сохранено в демо')
})
$('#permissions').addEventListener('close', () => {
  if (activeEdge && isNewEdge) activeEdge.remove()
  activeEdge = null; isNewEdge = false; refreshLegend()
})
$('#delete-edge').addEventListener('click', () => {
  activeEdge?.remove(); activeEdge = null
  $('#permissions').close(); refreshLegend(); persist(); toast('Стрелка удалена')
})
function showDevice(id) {
  const device = byId(id)
  if (!device) return
  $('#device-title').textContent = device.name
  const list = document.createElement('dl'); list.className = 'details-list'
  for (const [label, value] of [['Владелец', owners[device.owner].name], ['Операционная система', device.os], ['Статус', statusFor(device)], ['Адрес в сети', device.ip]]) {
    const row = document.createElement('div'), term = document.createElement('dt'), description = document.createElement('dd')
    term.textContent = label; description.textContent = value; row.append(term, description); list.append(row)
  }
  $('#device-details').replaceChildren(list)
  const edges = graph.getConnectedEdges(id).filter((edge) => !edge.getData()?.pending)
  $('#device-connections').replaceChildren(...edges.map((edge) => {
    const button = document.createElement('button'); button.className = 'connection-row'
    const dot = document.createElement('span'); dot.className = 'swatch'; dot.style.background = colorFor(edge.getData().permissions)
    const text = document.createElement('span'); text.textContent = `${byId(edge.getSourceCellId()).name} → ${byId(edge.getTargetCellId()).name}`
    const small = document.createElement('small'); small.textContent = labelFor(edge.getData().permissions); text.append(small)
    button.append(dot, text)
    button.addEventListener('click', () => { $('#device-info').close(); openPermissions(edge) })
    return button
  }))
  if (!edges.length) $('#device-connections').textContent = 'Разрешений пока нет'
  $('#device-info').showModal()
}
for (const [key, owner] of Object.entries(owners)) {
  const chip = document.createElement('span'); chip.className = 'owner-chip'
  const swatch = document.createElement('span'); swatch.className = 'swatch'; swatch.style.background = owner.color
  chip.append(swatch, owner.name); $('#owners').append(chip)
}
for (const device of devices) {
  for (const selector of ['#device-picker', '#source-picker', '#target-picker']) {
    const option = document.createElement('option'); option.value = device.id; option.textContent = `${device.name} · ${owners[device.owner].name}`; $(selector).append(option)
  }
}
$('#target-picker').value = 'ubuntu'
$('#online-count').textContent = `${devices.filter((device) => device.online).length} онлайн`
$('#device-picker').addEventListener('change', (event) => { showDevice(event.target.value); event.target.value = '' })
$('#connect').addEventListener('click', () => { $('#picker-error').textContent = ''; $('#connection-picker').showModal() })
$('#connection-form').addEventListener('submit', (event) => {
  event.preventDefault()
  const source = $('#source-picker').value, target = $('#target-picker').value
  if (source === target) { $('#picker-error').textContent = 'Выберите два разных устройства.'; return }
  const existing = graph.getEdges().find((edge) => edge.getSourceCellId() === source && edge.getTargetCellId() === target)
  $('#connection-picker').close()
  if (existing) { openPermissions(existing); return }
  const edge = addEdge(source, target, [])
  edge.setData({ pending: true, permissions: [] }); edge.attr('line/strokeDasharray', '5 4')
  openPermissions(edge, true)
})
document.querySelectorAll('[data-close]').forEach((button) => button.addEventListener('click', () => button.closest('dialog').close()))
document.querySelectorAll('dialog').forEach((dialog) => dialog.addEventListener('click', (event) => {
  const rect = dialog.getBoundingClientRect()
  if (event.target === dialog && (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom)) dialog.close()
}))
graph.on('node:click', ({ node, e }) => { if (!e.target.closest('.x6-port')) showDevice(node.id) })
graph.on('edge:click', ({ edge }) => { if (!edge.getData()?.pending) openPermissions(edge) })
graph.on('edge:connected', ({ edge, isNew }) => { if (isNew) openPermissions(edge, true) })
graph.on('node:moved', persist)
graph.on('scale', updateZoom)
$('#zoom-in').addEventListener('click', () => graph.zoom(.1, { minScale: .3, maxScale: 1.6 }))
$('#zoom-out').addEventListener('click', () => graph.zoom(-.1, { minScale: .3, maxScale: 1.6 }))
$('#fit').addEventListener('click', fit)
$('#reset').addEventListener('click', () => { loadDemo(false); persist(); toast('Пример восстановлен') })
let resizeTimer
new ResizeObserver(() => { clearTimeout(resizeTimer); resizeTimer = setTimeout(fit, 150) }).observe($('.canvas-wrap'))
loadDemo()
