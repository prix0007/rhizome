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

/** Legend category of a device, in the same precedence as `nodeColor`: gw, me, off, new, on. */
export function nodeCategory(d) {
  if (d.is_gateway) return 'gw';
  if (d.is_self) return 'me';
  if (d.online === false) return 'off';
  if (d.is_new) return 'new';
  return 'on';
}

/** Stable pseudo-random angle in [0, 2pi) from a string, so each link keeps its own curve direction. */
export function hashAngle(str) {
  let h = 2166136261;
  for (const ch of String(str)) {
    h ^= ch.codePointAt(0);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return (h / 4294967296) * Math.PI * 2;
}

/** World-space radius of a node's body. Collision and rendering both use this. */
export function nodeRadius(d) {
  if (d.is_gateway) return 9;
  if (d.is_self) return 6;
  return 4.5;
}

/** Clearance kept around a body so the glow halo and a little air fit inside the collision sphere. */
export const COLLIDE_PADDING = 6;

export function collisionRadius(d) {
  return nodeRadius(d) + COLLIDE_PADDING;
}

/**
 * Visual state of a node as plain data (hex colour, body opacity, halo
 * strength 0..1). The renderer eases towards it, so a status change fades.
 * Colours match `nodeColor` and the legend; offline is grey and glowless.
 */
export function nodeStyle(d) {
  if (d.is_gateway) return { color: COLOR.gateway, opacity: 1, glow: 1 };
  if (d.is_self) return { color: COLOR.self, opacity: 1, glow: 0.8 };
  if (d.online === false) return { color: '#8a919c', opacity: 0.4, glow: 0 };
  if (d.is_new) return { color: COLOR.fresh, opacity: 1, glow: 1 };
  return { color: COLOR.online, opacity: 0.95, glow: 0.55 };
}

/** Particles flow along every live link; a newly-seen device gets a denser, faster stream. */
export function linkParticles(d) {
  if (!d || d.online === false) return 0;
  return d.is_new ? 4 : 1;
}

// ---- labels ----

const LEGAL_SUFFIX = /[\s,]+(?:co\.?(?:\s*,?\s*ltd\.?)?|ltd\.?|inc\.?|llc|gmbh|corp(?:oration)?\.?|company|limited|technology|technologies|electronics|communications?|intl\.?|international)[.,]*\s*$/i;

/** Drop control characters and bidi overrides (device strings are untrusted) and collapse whitespace. */
function clean(v) {
  if (typeof v !== 'string') return '';
  return v
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

function ellipsize(s, max) {
  const chars = [...s];
  return chars.length <= max ? s : chars.slice(0, max - 1).join('').trimEnd() + '\u2026';
}

function shortVendor(v) {
  let s = clean(v);
  for (let i = 0; i < 6; i++) {
    const next = s.replace(/\s*\([^)]*\)\s*$/, '').replace(LEGAL_SUFFIX, '').trim();
    if (next === s || next === '') break;
    s = next;
  }
  return s;
}

function shortHost(h) {
  let s = clean(h).replace(/\.(local|lan|home|localdomain)\.?$/i, '');
  const stripped = s.replace(/[-_ ]?[0-9a-f]{12,}$/i, '');
  return stripped || s;
}

/**
 * What to print next to a device: hostname if known, else vendor, else IP.
 * `primary` is the name; `secondary` is a short qualifier (the IP when the
 * name is not the IP, "private MAC" for an anonymous device) or null.
 * Plain strings only; the UI sets them with textContent.
 */
export function labelParts(d, max = 22) {
  const host = shortHost(d.hostname);
  if (host) return { primary: ellipsize(host, max), secondary: clean(d.ip) || null };
  const vendor = shortVendor(d.vendor);
  if (vendor) return { primary: ellipsize(vendor, max), secondary: clean(d.ip) || null };
  const ip = clean(d.ip) || clean(d.mac) || '?';
  return { primary: ellipsize(ip, max + 4), secondary: d.randomized_mac ? 'private MAC' : null };
}

export function labelText(d, max = 22) {
  return labelParts(d, max).primary;
}

/** Where a freshly seen node should start: on a random bearing around the gateway, not on top of it. */
export function seedPosition(gateway, rand, distance) {
  const gx = (gateway && gateway.x) || 0;
  const gy = (gateway && gateway.y) || 0;
  const gz = (gateway && gateway.z) || 0;
  const u = rand() * 2 - 1;
  const a = rand() * Math.PI * 2;
  const s = Math.sqrt(1 - u * u);
  return { x: gx + distance * s * Math.cos(a), y: gy + distance * u, z: gz + distance * s * Math.sin(a) };
}

// ---- collision ----

function isFixed(n) {
  return n.fx !== undefined && n.fx !== null;
}

/**
 * Push overlapping spheres apart, in place. Each pair closer than the sum of
 * its radii is separated along the line between centres; a pinned node never
 * moves, a heavier node (mass ~ r^3) moves less. `softness` is the share of
 * the overlap removed per iteration, so separation is eased over several ticks
 * instead of snapping. Coincident centres get a deterministic direction.
 */
export function separate(nodes, radiusOf, { softness = 0.7, iterations = 2 } = {}) {
  const n = nodes.length;
  const r = nodes.map((d) => radiusOf(d));
  for (let it = 0; it < iterations; it++) {
    for (let i = 0; i < n; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < n; j++) {
        const b = nodes[j];
        const fa = isFixed(a);
        const fb = isFixed(b);
        if (fa && fb) continue;
        let dx = (b.x || 0) - (a.x || 0);
        let dy = (b.y || 0) - (a.y || 0);
        let dz = (b.z || 0) - (a.z || 0);
        let dist = Math.hypot(dx, dy, dz);
        const min = r[i] + r[j];
        if (dist >= min) continue;
        if (dist < 1e-6) {
          const ang = (i * 2.399963 + j) % (Math.PI * 2);
          dx = Math.cos(ang); dy = Math.sin(ang); dz = 0.3 * Math.cos(ang * 2);
          dist = Math.hypot(dx, dy, dz);
        }
        const push = ((min - dist) * softness) / dist;
        const ma = r[i] ** 3;
        const mb = r[j] ** 3;
        const shareA = fa ? 0 : fb ? 1 : mb / (ma + mb);
        const shareB = fb ? 0 : fa ? 1 : ma / (ma + mb);
        a.x = (a.x || 0) - dx * push * shareA; a.y = (a.y || 0) - dy * push * shareA; a.z = (a.z || 0) - dz * push * shareA;
        b.x = (b.x || 0) + dx * push * shareB; b.y = (b.y || 0) + dy * push * shareB; b.z = (b.z || 0) + dz * push * shareB;
      }
    }
  }
}

/**
 * A d3-force compatible force (d3-force-3d's forceCollide is not exposed by
 * the vendored bundle). Install with `graph.d3Force('collide', makeCollideForce(collisionRadius))`.
 */
export function makeCollideForce(radiusOf, opts) {
  let nodes = [];
  const force = () => separate(nodes, radiusOf, opts);
  force.initialize = (ns) => { nodes = ns; };
  return force;
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
