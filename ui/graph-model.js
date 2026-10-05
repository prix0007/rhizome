// Pure helpers: no DOM, no network. Tested with `node --test ui/tests/`.

/**
 * Turn a device list into a star graph: the gateway is pinned at the origin
 * and every other device links to it. With no gateway there are no links.
 */
export function buildGraph(devices) {
  const list = Array.isArray(devices) ? devices : [];
  const gw = list.find((d) => d.is_gateway);
  const nodes = list.map((d) => (d.is_gateway ? { ...d, fx: 0, fy: 0, fz: 0 } : { ...d }));
  const links = gw ? list.filter((d) => d !== gw).map((d) => ({ source: d.id, target: gw.id })) : [];
  return { nodes, links };
}

const COLOR = {
  gateway: '#ffc247',
  self: '#3ddcff',
  fresh: '#ff7a3d',
  online: '#6ee7a8',
  offline: 'rgba(150,150,150,0.35)',
};

export function nodeColor(d) {
  if (d.is_gateway) return COLOR.gateway;
  if (d.is_self) return COLOR.self;
  if (d.online === false) return COLOR.offline;
  if (d.is_new) return COLOR.fresh;
  return COLOR.online;
}

export function nodeSize(d) {
  if (d.is_gateway) return 8;
  if (d.is_self) return 5;
  return 3;
}

/** Particles flow along the link of a newly-seen device. */
export function linkParticles(d) {
  return d && d.is_new ? 4 : 0;
}

/** Escape text for use inside HTML (3d-force-graph renders `nodeLabel` as HTML). */
export function escapeHtml(v) {
  if (v === null || v === undefined) return '';
  return String(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/** Tooltip HTML. Every device-supplied field is escaped. */
export function labelFor(d) {
  const title = d.hostname || d.ip;
  const bits = [d.ip, d.mac, d.vendor, d.kind].filter(Boolean).map(escapeHtml);
  return `<div><b>${escapeHtml(title)}</b><br/>${bits.join(' &middot; ')}</div>`;
}

export function lastSeenText(ms, now) {
  if (!ms) return 'never';
  const s = Math.max(0, Math.floor((now - ms) / 1000));
  if (s < 30) return 'just now';
  if (s < 3600) return `${Math.max(1, Math.round(s / 60))} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function dateText(ms) {
  return ms ? new Date(ms).toLocaleString() : 'never';
}

/** [label, value] string pairs for the details panel; the UI renders them with textContent. */
export function detailRows(d, now) {
  const rows = [
    ['IP', d.ip],
    ['MAC', d.mac],
    ['Vendor', d.vendor || (d.randomized_mac ? '(private address)' : '(unknown)')],
  ];
  if (d.randomized_mac) rows.push(['Private MAC', 'yes (randomized / locally administered)']);
  if (d.hostname) rows.push(['Hostname', d.hostname]);
  rows.push(['Kind', d.kind || 'unknown']);
  rows.push(['Status', d.online ? 'online' : 'offline']);
  if (d.is_new) rows.push(['New', 'seen for the first time recently']);
  rows.push(['Last seen', d.online ? 'now' : lastSeenText(d.last_seen, now)]);
  rows.push(['First seen', dateText(d.first_seen)]);
  if (d.services && d.services.length) rows.push(['Services', d.services.join(', ')]);
  if (d.ssdp_server) rows.push(['SSDP server', d.ssdp_server]);
  if (d.ssdp_location) rows.push(['SSDP location', d.ssdp_location]);
  return rows.map(([k, v]) => [String(k), String(v ?? '')]);
}

// ---- reconciliation: keep node objects (and so their layout positions) stable ----

function applyPin(node, isGateway) {
  if (isGateway) {
    node.fx = 0; node.fy = 0; node.fz = 0;
  } else if ('fx' in node) {
    delete node.fx; delete node.fy; delete node.fz;
  }
}

function gatewayId(nodeMap) {
  for (const n of nodeMap.values()) if (n.is_gateway) return n.id;
  return null;
}

/** Insert or update one device in place. Returns true when a node was added. */
export function upsertDevice(nodeMap, device) {
  const existing = nodeMap.get(device.id);
  if (existing) {
    Object.assign(existing, device);
    applyPin(existing, !!device.is_gateway);
    return false;
  }
  const node = { ...device };
  applyPin(node, !!device.is_gateway);
  nodeMap.set(device.id, node);
  return true;
}

/** Returns true when a node was removed. */
export function removeDevice(nodeMap, id) {
  return nodeMap.delete(id);
}

/**
 * Make `nodeMap` match `devices` (a full snapshot). `structureChanged` is true
 * when nodes were added/removed or the gateway changed, i.e. when the graph
 * must be re-fed to the layout engine.
 */
export function reconcile(nodeMap, devices) {
  const list = Array.isArray(devices) ? devices : [];
  const before = gatewayId(nodeMap);
  let structureChanged = false;
  const keep = new Set(list.map((d) => d.id));
  for (const id of [...nodeMap.keys()]) {
    if (!keep.has(id)) { nodeMap.delete(id); structureChanged = true; }
  }
  for (const d of list) if (upsertDevice(nodeMap, d)) structureChanged = true;
  if (gatewayId(nodeMap) !== before) structureChanged = true;
  return { structureChanged };
}

/** Graph data for the layout engine, reusing the node objects in `nodeMap`. */
export function toGraphData(nodeMap) {
  const nodes = [...nodeMap.values()];
  const gw = gatewayId(nodeMap);
  const links = gw === null ? [] : nodes.filter((n) => n.id !== gw).map((n) => ({ source: n.id, target: gw }));
  return { nodes, links };
}
