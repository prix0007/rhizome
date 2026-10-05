import {
  detailRows,
  labelFor,
  linkParticles,
  nodeColor,
  nodeSize,
  reconcile,
  removeDevice,
  toGraphData,
  upsertDevice,
} from './graph-model.js';

const statusText = document.getElementById('status-text');
const banners = document.getElementById('banners');
const panel = document.getElementById('panel');
const panelTitle = document.getElementById('panel-title');
const panelRows = document.getElementById('panel-rows');
const nodeMap = new Map();
let selectedId = null;

function endpointNode(end) {
  return typeof end === 'object' && end !== null ? end : nodeMap.get(end);
}

let graph = null;
try {
  graph = ForceGraph3D()(document.getElementById('graph'))
    .backgroundColor('#05070d')
    .nodeColor(nodeColor)
    .nodeVal(nodeSize)
    .nodeOpacity(0.95)
    .nodeLabel(labelFor) // HTML, but labelFor escapes every field
    .linkColor(() => 'rgba(120,150,190,0.45)')
    .linkDirectionalParticles((l) => linkParticles(endpointNode(l.source)))
    .linkDirectionalParticleWidth(2)
    .onNodeClick(selectNode);
} catch (e) {
  statusText.textContent = 'WebGL is unavailable in this browser: ' + e.message;
}

function renderPanel() {
  const d = selectedId && nodeMap.get(selectedId);
  if (!d) {
    panel.hidden = true;
    return;
  }
  panel.hidden = false;
  panelTitle.textContent = d.hostname || d.ip; // textContent only, never innerHTML
  const rows = detailRows(d, Date.now()).flatMap(([k, v]) => {
    const dt = document.createElement('dt');
    dt.textContent = k;
    const dd = document.createElement('dd');
    dd.textContent = v;
    return [dt, dd];
  });
  panelRows.replaceChildren(...rows);
}

function selectNode(n) {
  selectedId = n.id;
  renderPanel();
  const dist = 120;
  const len = Math.hypot(n.x || 0, n.y || 0, n.z || 0);
  const pos = len < 1 ? { x: 0, y: 0, z: dist } : { x: n.x * (1 + dist / len), y: n.y * (1 + dist / len), z: n.z * (1 + dist / len) };
  graph.cameraPosition(pos, n, 1000);
}

document.getElementById('panel-close').addEventListener('click', () => {
  selectedId = null;
  renderPanel();
});

const pending = { structure: false, scheduled: false };
function scheduleRender(structureChanged) {
  pending.structure ||= structureChanged;
  if (pending.scheduled || !graph) return;
  pending.scheduled = true;
  requestAnimationFrame(() => {
    pending.scheduled = false;
    if (pending.structure) {
      graph.graphData(toGraphData(nodeMap));
    } else {
      // Re-evaluate accessors without re-heating the layout.
      graph.nodeColor(graph.nodeColor());
      graph.linkDirectionalParticles(graph.linkDirectionalParticles());
    }
    pending.structure = false;
    if (selectedId && !nodeMap.has(selectedId)) selectedId = null;
    renderPanel();
  });
}

function showStatus(s) {
  if (!s) return;
  const parts = [`${s.online}/${s.devices} online`, s.iface, s.net];
  if (s.gateway) parts.push('gw ' + s.gateway);
  statusText.textContent = parts.filter(Boolean).join(' | ');
  const notes = [...(s.warnings || [])];
  banners.replaceChildren(
    ...notes.map((w) => {
      const el = document.createElement('div');
      el.className = 'banner';
      el.textContent = w; // never innerHTML
      return el;
    }),
  );
}

const es = new EventSource('/api/events');
es.addEventListener('snapshot', (e) => {
  const snap = JSON.parse(e.data);
  const r = reconcile(nodeMap, snap.devices);
  showStatus(snap.status);
  scheduleRender(r.structureChanged);
});
es.addEventListener('device', (e) => scheduleRender(upsertDevice(nodeMap, JSON.parse(e.data))));
es.addEventListener('removed', (e) => scheduleRender(removeDevice(nodeMap, JSON.parse(e.data))));
es.addEventListener('scan', (e) => showStatus(JSON.parse(e.data)));
es.onerror = () => {
  statusText.textContent = 'disconnected, retrying...';
};
