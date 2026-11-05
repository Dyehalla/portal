import { Graph, Config } from '@antv/x6';
Config.autoInsertCSS = false;
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


const palette = [
  {color: '#71889c', fill: '#f0f4f7', border: '#c4d1dc'},
  {color: '#93839b', fill: '#f5f1f6', border: '#d4c9da'},
];
function colorFor(ports) {
  const mask = (ports.includes(22) ? 1 : 0) | (ports.some(p => p === 3389 || p === 5900) ? 2 : 0) | (ports.some(p => ![22,3389,5900].includes(p)) ? 4 : 0);
  return ['#aaa','#72848c','#9b8797','#8779a0','#879477','#658c86','#ab9170','#7e83a0'][mask];
}
window.PortalMap = class {
  constructor(container, {onDevice, onPermission}) {
    this.container = container;
    this.onPermission = onPermission;
    this.positions = new Map();
    this.scope = null;
    this.needsFit = true;
    this.graph = new Graph({
      container, autoResize: true, async: false, background: {color: '#fcfcfc'},
      grid: {visible: true, size: 20, type: 'dot', args: {color: '#ddd', thickness: 1}},
      panning: {enabled: true, eventTypes: ['leftMouseDown', 'mouseWheelDown']},
      mousewheel: {enabled: true, minScale: .3, maxScale: 1.6, factor: 1.1},
      interacting: {edgeMovable: false, arrowheadMovable: false, vertexMovable: false, vertexAddable: false, vertexDeletable: false},
      connecting: {
        snap: {radius: 28}, allowBlank: false, allowLoop: false, allowMulti: false, allowEdge: false,
        allowNode: true, highlight: true, connector: {name: 'smooth'}, connectionPoint: 'boundary',
        validateConnection: ({sourceCell, targetCell}) => sourceCell !== targetCell && !!targetCell?.getData()?.editable,
        createEdge() { return this.createEdge({attrs: {line: {stroke: '#aaa', strokeWidth: 1.8, strokeDasharray: '5 4', targetMarker: {name: 'block', width: 7, height: 6}}}, zIndex: 0, data: {draft: true}}); },
      },
    });
    this.graph.on('node:click', ({node}) => onDevice(node.id));
    this.graph.on('edge:click', ({edge}) => onPermission(edge.getSourceCellId(), edge.getTargetCellId()));
    this.graph.on('edge:connected', ({edge, isNew}) => {
      if (!isNew) return;
      const source = edge.getSourceCellId(), target = edge.getTargetCellId();
      edge.remove();
      onPermission(source, target);
    });
    this.graph.on('node:change:position', ({node}) => {
      this.positions.set(node.id, node.position());
      try { localStorage.setItem('portal-map-positions:' + this.scope, JSON.stringify([...this.positions])); } catch {}
    });
    this.graph.on('scale', () => { document.getElementById('map-zoom-level').value = Math.round(this.graph.zoom() * 100) + '%'; });
  }
  update({scope, devices, edges}) {
    if (scope !== this.scope) {
      this.graph.clearCells();
      this.positions.clear();
      this.scope = scope;
      this.needsFit = true;
      try { this.positions = new Map(JSON.parse(localStorage.getItem('portal-map-positions:' + scope)) || []); } catch {}
    }
    const wanted = new Set(devices.map(d => d.id));
    for (const node of this.graph.getNodes()) if (!wanted.has(node.id)) node.remove();
    devices.forEach((device, index) => {
      const colors = palette[device.owned ? 0 : 1];
      let node = this.graph.getCellById(device.id);
      if (!node) {
        const saved = this.positions.get(device.id);
        const position = Number.isFinite(saved?.x) && Number.isFinite(saved?.y) ? saved : {x: 60 + index % 3 * 360, y: 70 + Math.floor(index / 3) * 300 + (index % 3 === 1 ? 150 : 0)};
        node = this.graph.addNode({id: device.id, shape: 'portal-device', ...position, zIndex: 1});
      }
      node.setData({editable: device.editable});
      node.attr({
        body: {fill: colors.fill, stroke: colors.border},
        name: {text: device.name, textWrap: {width: 153, height: 24, ellipsis: true}},
        status: {text: device.online ? 'Онлайн' : 'Офлайн', fill: device.online ? '#648471' : '#929292'},
        statusDot: {fill: device.online ? '#779582' : '#bbb'},
        osIcon: {d: iconPaths[device.icon] || 'M3 4h18v13H3ZM8 21h8m-4-4v4', fill: device.icon ? '#636970' : 'none', stroke: device.icon ? 'none' : '#636970'},
        ownerDot: {fill: colors.color}, owner: {text: device.owner, textWrap: {width: 110, height: 18, ellipsis: true}}, os: {text: device.local ? 'Это устройство' : ''},
      });
      const view = this.graph.findViewByCell(node);
      if (view) { view.container.setAttribute('data-device', device.id); view.container.setAttribute('role', 'button'); view.container.setAttribute('tabindex', '0'); view.container.setAttribute('aria-label', device.name + ', ' + (device.online ? 'Онлайн' : 'Офлайн')); }
    });
    const edgeIds = new Set();
    for (const item of edges) {
      if (!wanted.has(item.source) || !wanted.has(item.target) || item.source === item.target) continue;
      const id = 'permission:' + item.source + ':' + item.target;
      edgeIds.add(id);
      let edge = this.graph.getCellById(id);
      if (!edge) {
        const a = this.graph.getCellById(item.source).getBBox().center;
        const b = this.graph.getCellById(item.target).getBBox().center;
        const vertical = Math.abs(a.y - b.y) > Math.abs(a.x - b.x);
        edge = this.graph.addEdge({id, source: {cell: item.source, port: vertical ? (a.y < b.y ? 'bottom' : 'top') : (a.x < b.x ? 'right' : 'left')}, target: {cell: item.target, port: vertical ? (a.y < b.y ? 'top' : 'bottom') : (a.x < b.x ? 'left' : 'right')}, connector: 'smooth', zIndex: 0});
      }
      // Opposite permissions need separate curves and labels.
      const reverse = edges.some(other => other.source === item.target && other.target === item.source);
      if (reverse) {
        const a = this.graph.getCellById(item.source).getBBox().center;
        const b = this.graph.getCellById(item.target).getBBox().center;
        const length = Math.hypot(b.x - a.x, b.y - a.y) || 1;
        edge.setVertices([{x: (a.x + b.x) / 2 - (b.y - a.y) / length * 30, y: (a.y + b.y) / 2 + (b.x - a.x) / length * 30}]);
      } else edge.setVertices([]);
      edge.setData(item);
      edge.attr('line', {stroke: colorFor(item.tcp), strokeWidth: 1.8, strokeDasharray: item.pending ? '5 4' : '', targetMarker: {name: 'block', width: 7, height: 6}, strokeLinecap: 'round'});
    }
    for (const edge of this.graph.getEdges()) if (!edge.getData()?.draft && !edgeIds.has(edge.id)) edge.remove();
    this.reveal();
  }
  reveal() {
    requestAnimationFrame(() => {
      if (!this.container.clientWidth || !this.container.clientHeight) return;
      this.graph.resize(this.container.clientWidth, this.container.clientHeight);
      if (this.needsFit && this.graph.getNodes().length) { this.fit(); this.needsFit = false; }
    });
  }
  fit() { this.graph.zoomToFit({padding: {top: 65, right: 35, bottom: 35, left: 35}, maxScale: 1}); }
  zoom(delta) { this.graph.zoom(delta); }
  clear() { this.graph.clearCells(); this.positions.clear(); this.scope = null; this.needsFit = true; }
};
