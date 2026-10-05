import {
  collisionRadius,
  detailRows,
  hashAngle,
  labelFor,
  linkParticles,
  makeCollideForce,
  nodeCategory,
  nodeColor,
  nodeSize,
  nodeStyle,
  reconcile,
  removeDevice,
  seedPosition,
  toGraphData,
  upsertDevice,
} from './graph-model.js';
import { createLabels } from './labels.js';
import { createLinkMaterials, createNodes, createSpores, probeKit, setupRenderer } from './scene.js';

const statusbar = document.getElementById('statusbar');
const statusText = document.getElementById('status-text');
const banners = document.getElementById('banners');
const panel = document.getElementById('panel');
const panelTitle = document.getElementById('panel-title');
const panelRows = document.getElementById('panel-rows');
const stage = document.getElementById('graph');
const nodeMap = new Map();
const calm = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

let selectedId = null;
let hoveredId = null;
let ready = false; // the 3D kit has been probed and node objects are available
let settled = false; // the first layout has cooled; later reheats are gentle
let fitted = false;
let lastInteract = performance.now();
let gatewayReturn = null; // gateway released after a drag: eases back to the origin

// ---- simulation tuning ----
// Lower alpha decay = a longer, softer cool-down; lower velocity decay = less
// friction, so nodes glide instead of stopping dead. Link and charge forces
// are capped after the first layout (see damped) so an SSE update nudges the
// graph instead of re-exploding it.
const SIM = {
  alphaDecay: 0.014,
  alphaMin: 0.002,
  velocityDecay: 0.26,
  linkDistance: 74,
  linkStrength: 0.45,
  charge: -75,
  chargeMax: 340,
  reheatCap: 0.28,
  seedDistance: 66,
};

function endpointNode(end) {
  return typeof end === 'object' && end !== null ? end : nodeMap.get(end);
}

/** Wrap a d3 force so that its alpha never exceeds `cap()`; every other method passes through. */
function damped(force, cap) {
  const f = (alpha) => force(Math.min(alpha, cap()));
  const proxy = new Proxy(f, {
    get(target, key) {
      if (key in target) return target[key];
      const v = force[key];
      if (typeof v !== 'function') return v;
      return (...args) => {
        const r = v.apply(force, args);
        return r === force ? proxy : r;
      };
    },
  });
  return proxy;
}

let graph = null;
let nodes3d = null;
let spores = null;
let labels = null;
let linkMats = null;

try {
  graph = ForceGraph3D({ rendererConfig: { antialias: true, alpha: true, powerPreference: 'high-performance' } })(stage)
    .backgroundColor('rgba(0,0,0,0)')
    .showNavInfo(false)
    .d3AlphaDecay(SIM.alphaDecay)
    .d3AlphaMin(SIM.alphaMin)
    .d3VelocityDecay(SIM.velocityDecay)
    .cooldownTicks(Infinity)
    .cooldownTime(60000)
    .nodeLabel(labelFor) // HTML, but labelFor escapes every field
    .nodeResolution(24)
    .linkWidth(0.7)
    .linkResolution(5)
    .linkCurvature(0.16)
    .linkCurveRotation((l) => hashAngle(endpointNode(l.source)?.id ?? ''))
    .linkDirectionalParticles((l) => linkParticles(endpointNode(l.source)))
    .linkDirectionalParticleWidth(1.5)
    .linkDirectionalParticleSpeed((l) => (endpointNode(l.source)?.is_new ? 0.011 : 0.005))
    .linkDirectionalParticleColor((l) => nodeStyle(endpointNode(l.source) || {}).color)
    .onNodeClick(selectNode)
    .onNodeHover((n) => {
      hoveredId = n ? n.id : null;
      stage.style.cursor = n ? 'pointer' : '';
    })
    .onNodeDragEnd((n) => {
      if (n.is_gateway) {
        gatewayReturn = n; // the engine left it pinned where it was dropped
        graph.d3ReheatSimulation();
      }
    })
    .onEngineStop(() => {
      settled = true;
      fitOnce();
    });

  const cap = () => (settled ? SIM.reheatCap : 1);
  graph.d3Force('link').distance(SIM.linkDistance).strength(SIM.linkStrength);
  graph.d3Force('charge').strength(SIM.charge).distanceMax(SIM.chargeMax);
  graph.d3Force('link', damped(graph.d3Force('link'), cap));
  graph.d3Force('charge', damped(graph.d3Force('charge'), cap));
  graph.d3Force('collide', makeCollideForce(collisionRadius));

  labels = createLabels(document.getElementById('labels'), graph);
  setupRenderer(graph);
  probeKit(graph)
    .then((kit) => {
      nodes3d = createNodes(kit);
      linkMats = createLinkMaterials(kit);
      spores = createSpores(kit, graph.scene());
      graph
        .nodeThreeObject(nodes3d.build)
        .nodeThreeObjectExtend(false)
        .linkMaterial(linkMaterialFor);
      ready = true;
      scheduleRender(true);
      setTimeout(fitOnce, 3500);
    })
    .catch((e) => {
      // Degrade to the library's own spheres; labels and the panel still work.
      graph.nodeColor(nodeColor).nodeVal(nodeSize).nodeOpacity(0.95).linkColor(() => 'rgba(120,190,170,0.45)');
      ready = true;
      statusText.textContent = e.message;
      scheduleRender(true);
    });
} catch (e) {
  statusText.textContent = 'WebGL is unavailable in this browser: ' + e.message;
}

/** Frame the whole graph once, unless the user has already taken the camera. */
function fitOnce() {
  if (fitted || performance.now() - lastInteract < 2000) return;
  fitted = true;
  graph.zoomToFit(1600, 120);
}

function linkMaterialFor(l) {
  const d = endpointNode(l.source);
  const s = nodeStyle(d || {});
  return linkMats(s.color, d && d.online === false ? 0.07 : 0.22 + 0.2 * s.glow);
}

// ---- details panel ----

function renderPanel() {
  const d = selectedId && nodeMap.get(selectedId);
  if (!d) {
    panel.classList.remove('open');
    panel.setAttribute('aria-hidden', 'true');
    return;
  }
  panel.classList.add('open');
  panel.setAttribute('aria-hidden', 'false');
  panel.style.setProperty('--accent', nodeStyle(d).color);
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
  lastInteract = performance.now();
  renderPanel();
  const dist = 130;
  const len = Math.hypot(n.x || 0, n.y || 0, n.z || 0);
  const pos = len < 1 ? { x: 0, y: 0, z: dist } : { x: n.x * (1 + dist / len), y: n.y * (1 + dist / len), z: n.z * (1 + dist / len) };
  graph.cameraPosition(pos, n, 1100);
}

document.getElementById('panel-close').addEventListener('click', () => {
  selectedId = null;
  renderPanel();
});

// ---- legend counts ----

const legendCounts = {};
for (const el of document.querySelectorAll('[data-count]')) legendCounts[el.dataset.count] = el;

function renderLegend() {
  const counts = { gw: 0, me: 0, on: 0, new: 0, off: 0 };
  for (const d of nodeMap.values()) counts[nodeCategory(d)]++;
  for (const [k, el] of Object.entries(legendCounts)) el.textContent = String(counts[k] ?? 0);
}

// ---- data flow ----

const pending = { structure: false, scheduled: false };
function scheduleRender(structureChanged) {
  pending.structure ||= structureChanged;
  if (pending.scheduled || !graph || !ready) return;
  pending.scheduled = true;
  requestAnimationFrame(() => {
    pending.scheduled = false;
    if (pending.structure) {
      seedNewcomers();
      graph.graphData(toGraphData(nodeMap));
    } else {
      // Re-evaluate accessors without re-heating the layout. Node colour and
      // size are eased every frame in createNodes().animate.
      graph.linkDirectionalParticles(graph.linkDirectionalParticles());
      if (linkMats) graph.linkMaterial(graph.linkMaterial());
      else graph.nodeColor(graph.nodeColor());
    }
    pending.structure = false;
    if (selectedId && !nodeMap.has(selectedId)) selectedId = null;
    renderPanel();
    renderLegend();
  });
}

/** Start new nodes on a random bearing around the gateway instead of on top of it. */
function seedNewcomers() {
  const gw = [...nodeMap.values()].find((n) => n.is_gateway);
  for (const n of nodeMap.values()) {
    if (n.is_gateway || typeof n.x === 'number') continue;
    Object.assign(n, seedPosition(gw, Math.random, SIM.seedDistance));
  }
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
es.onopen = () => statusbar.classList.add('live');
es.onerror = () => {
  statusbar.classList.remove('live');
  statusText.textContent = 'disconnected, retrying...';
};

// ---- per-frame: node animation, camera drift, labels ----

for (const ev of ['pointerdown', 'wheel', 'keydown', 'touchstart']) {
  window.addEventListener(ev, () => { lastInteract = performance.now(); }, { passive: true });
}
let pointerDown = false;
window.addEventListener('pointerdown', () => { pointerDown = true; });
window.addEventListener('pointerup', () => { pointerDown = false; lastInteract = performance.now(); });

/** Rotate the camera slowly about its up axis through the controls' target. */
function drift(dt) {
  const cam = graph.camera();
  const ctl = graph.controls();
  const t = (ctl && ctl.target) || { x: 0, y: 0, z: 0 };
  const a = 0.032 * dt;
  const c = Math.cos(a), s = Math.sin(a);
  const u = cam.up;
  const ul = Math.hypot(u.x, u.y, u.z) || 1;
  const ax = u.x / ul, ay = u.y / ul, az = u.z / ul;
  const vx = cam.position.x - t.x, vy = cam.position.y - t.y, vz = cam.position.z - t.z;
  const dot = ax * vx + ay * vy + az * vz;
  const cx = ay * vz - az * vy, cy = az * vx - ax * vz, cz = ax * vy - ay * vx;
  cam.position.x = t.x + vx * c + cx * s + ax * dot * (1 - c);
  cam.position.y = t.y + vy * c + cy * s + ay * dot * (1 - c);
  cam.position.z = t.z + vz * c + cz * s + az * dot * (1 - c);
}

function easeGatewayHome(dt) {
  const g = gatewayReturn;
  if (!g) return;
  const k = 1 - Math.exp(-dt * 6);
  for (const f of ['fx', 'fy', 'fz']) g[f] += (0 - g[f]) * k;
  if (Math.hypot(g.fx, g.fy, g.fz) < 0.05) {
    g.fx = 0; g.fy = 0; g.fz = 0;
    gatewayReturn = null;
  }
}

let last = performance.now();
function frame(now) {
  requestAnimationFrame(frame);
  const dt = Math.min(0.05, (now - last) / 1000);
  last = now;
  if (!graph || !ready) return;
  if (nodes3d) nodes3d.animate(now, dt, nodeMap, { selectedId, hoveredId, calm });
  if (spores) spores.animate(now, calm);
  easeGatewayHome(dt);
  if (!calm && !pointerDown && !selectedId && now - lastInteract > 5000 && gatewayReturn === null) drift(dt);
  labels.update(nodeMap, { selectedId, hoveredId, calm });
}
requestAnimationFrame(frame);

// Test and debugging hook: read-only view of the live scene state.
window.__rhizome = {
  nodeMap,
  reheat: () => graph.d3ReheatSimulation(),
  screenOf: (id) => { const n = nodeMap.get(id); return graph.graph2ScreenCoords(n.x, n.y, n.z); },
  labelCount: () => (labels ? labels.count() : 0), settled: () => settled };
