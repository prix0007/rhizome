import test from 'node:test';
import assert from 'node:assert/strict';
import { buildGraph } from '../graph-model.js';

const dev = (id, extra = {}) => ({ id, ip: '10.0.0.' + id.length, is_gateway: false, is_self: false, online: true, ...extra });

test('gateway node is pinned at the origin', () => {
  const g = buildGraph([dev('gw', { is_gateway: true }), dev('a')]);
  const gw = g.nodes.find((n) => n.id === 'gw');
  assert.equal(gw.fx, 0);
  assert.equal(gw.fy, 0);
  assert.equal(gw.fz, 0);
});

test('every non-gateway node has exactly one link to the gateway', () => {
  const g = buildGraph([dev('gw', { is_gateway: true }), dev('a'), dev('bb'), dev('ccc', { is_self: true })]);
  assert.equal(g.links.length, 3);
  for (const id of ['a', 'bb', 'ccc']) {
    const ls = g.links.filter((l) => l.source === id);
    assert.equal(ls.length, 1);
    assert.equal(ls[0].target, 'gw');
  }
  assert.ok(g.links.every((l) => l.source !== 'gw'));
});

test('non-gateway nodes are not pinned', () => {
  const g = buildGraph([dev('gw', { is_gateway: true }), dev('a')]);
  const a = g.nodes.find((n) => n.id === 'a');
  assert.equal(a.fx, undefined);
});

test('with no gateway there are no links and no crash', () => {
  const g = buildGraph([dev('a'), dev('bb')]);
  assert.equal(g.nodes.length, 2);
  assert.deepEqual(g.links, []);
});

test('empty or missing input yields an empty graph', () => {
  assert.deepEqual(buildGraph([]), { nodes: [], links: [] });
  assert.deepEqual(buildGraph(undefined), { nodes: [], links: [] });
  assert.deepEqual(buildGraph(null), { nodes: [], links: [] });
});

test('input devices are not mutated', () => {
  const d = dev('gw', { is_gateway: true });
  buildGraph([d]);
  assert.equal(d.fx, undefined);
});

// ---- slice 2: reconciliation keeps node identity ----
import { reconcile, upsertDevice, removeDevice, toGraphData } from '../graph-model.js';

test('reconcile keeps node object identity so positions survive', () => {
  const map = new Map();
  reconcile(map, [dev('gw', { is_gateway: true }), dev('a')]);
  const a = map.get('a');
  a.x = 5; a.y = 6; a.z = 7; a.vx = 0.1;
  const r = reconcile(map, [dev('gw', { is_gateway: true }), dev('a', { online: false })]);
  assert.equal(map.get('a'), a);
  assert.deepEqual([a.x, a.y, a.z, a.vx], [5, 6, 7, 0.1]);
  assert.equal(a.online, false);
  assert.equal(r.structureChanged, false);
});

test('reconcile reports structure change on add and remove', () => {
  const map = new Map();
  assert.equal(reconcile(map, [dev('gw', { is_gateway: true })]).structureChanged, true);
  assert.equal(reconcile(map, [dev('gw', { is_gateway: true }), dev('a')]).structureChanged, true);
  assert.equal(reconcile(map, [dev('gw', { is_gateway: true })]).structureChanged, true);
  assert.equal(map.has('a'), false);
});

test('removal drops the node and its link', () => {
  const map = new Map();
  reconcile(map, [dev('gw', { is_gateway: true }), dev('a'), dev('bb')]);
  assert.equal(removeDevice(map, 'a'), true);
  const g = toGraphData(map);
  assert.deepEqual(g.nodes.map((n) => n.id).sort(), ['bb', 'gw']);
  assert.deepEqual(g.links, [{ source: 'bb', target: 'gw' }]);
  assert.equal(removeDevice(map, 'nope'), false);
});

test('upsertDevice updates in place and reports additions', () => {
  const map = new Map();
  assert.equal(upsertDevice(map, dev('a')), true);
  const a = map.get('a');
  assert.equal(upsertDevice(map, dev('a', { ip: '9.9.9.9' })), false);
  assert.equal(map.get('a'), a);
  assert.equal(a.ip, '9.9.9.9');
});

test('gateway pin follows the is_gateway flag', () => {
  const map = new Map();
  reconcile(map, [dev('x', { is_gateway: true })]);
  assert.equal(map.get('x').fx, 0);
  const r = reconcile(map, [dev('x', { is_gateway: false }), dev('y', { is_gateway: true })]);
  assert.equal(map.get('x').fx, undefined);
  assert.equal(map.get('y').fz, 0);
  assert.equal(r.structureChanged, true);
});

test('toGraphData with no gateway has no links', () => {
  const map = new Map();
  reconcile(map, [dev('a'), dev('bb')]);
  assert.deepEqual(toGraphData(map).links, []);
});

test('toGraphData returns the same node objects every time', () => {
  const map = new Map();
  reconcile(map, [dev('gw', { is_gateway: true }), dev('a')]);
  const n1 = toGraphData(map).nodes;
  const n2 = toGraphData(map).nodes;
  assert.ok(n1.every((n, i) => n === n2[i]));
});

// ---- slice 4: escaping, labels, colours ----
import { escapeHtml, labelFor, lastSeenText, nodeColor, linkParticles, detailRows } from '../graph-model.js';

test('escapeHtml neutralises markup', () => {
  const out = escapeHtml('<img src=x onerror=1>');
  assert.ok(!out.includes('<'));
  assert.ok(!out.includes('>'));
  assert.equal(out, '&lt;img src=x onerror=1&gt;');
  assert.equal(escapeHtml(`"'&`), '&quot;&#39;&amp;');
});

test('escapeHtml tolerates non-strings', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
  assert.equal(escapeHtml(42), '42');
});

test('label builder escapes every field', () => {
  const evil = '<img src=x onerror=alert(1)>';
  const d = dev('a', { ip: evil, mac: evil, vendor: evil, hostname: evil, kind: evil, ssdp_server: evil });
  const html = labelFor(d);
  assert.ok(!html.includes('<img'), html);
  assert.ok(html.includes('&lt;img'));
  // only our own formatting tags may appear
  const tags = html.match(/<\/?[a-z]+[^>]*>/g) || [];
  assert.ok(tags.every((t) => /^<\/?(div|b|span|br)\s*\/?>$/.test(t)), tags.join(' '));
});

test('lastSeenText is human readable', () => {
  const now = 1_000_000_000;
  assert.equal(lastSeenText(now - 5_000, now), 'just now');
  assert.equal(lastSeenText(now - 5 * 60_000, now), '5 min ago');
  assert.equal(lastSeenText(now - 3 * 3_600_000, now), '3 h ago');
  assert.equal(lastSeenText(now - 2 * 86_400_000, now), '2 d ago');
  assert.equal(lastSeenText(0, now), 'never');
  assert.equal(lastSeenText(undefined, now), 'never');
});

test('colours distinguish gateway, self, new, online and offline', () => {
  const colours = [
    nodeColor(dev('g', { is_gateway: true })),
    nodeColor(dev('s', { is_self: true })),
    nodeColor(dev('n', { is_new: true })),
    nodeColor(dev('o')),
    nodeColor(dev('x', { online: false })),
  ];
  assert.equal(new Set(colours).size, 5);
  assert.match(nodeColor(dev('x', { online: false })), /rgba\(.*0\.\d+\)/, 'offline is translucent');
});

test('live links carry particles, new devices a denser stream, offline none', () => {
  assert.ok(linkParticles(dev('n', { is_new: true })) > linkParticles(dev('o')));
  assert.ok(linkParticles(dev('o')) > 0);
  assert.equal(linkParticles(dev('x', { online: false })), 0);
  assert.equal(linkParticles(undefined), 0);
});

test('detailRows lists the fields shown in the panel as plain text', () => {
  const rows = detailRows(dev('a', { ip: '10.0.0.2', mac: 'aa:bb', vendor: 'V', kind: 'printer', randomized_mac: true, online: false, last_seen: 0 }), 1000);
  const m = Object.fromEntries(rows);
  assert.equal(m.IP, '10.0.0.2');
  assert.equal(m.MAC, 'aa:bb');
  assert.equal(m.Vendor, 'V');
  assert.equal(m.Kind, 'printer');
  assert.equal(m.Status, 'offline');
  assert.equal(m['Private MAC'], 'yes (randomized / locally administered)');
  assert.ok(rows.every(([k, v]) => typeof k === 'string' && typeof v === 'string'));
});

test('detailRows shows SSDP location as plain text and omits empty optional rows', () => {
  const evil = 'http://x/<script>alert(1)</script>';
  const rows = Object.fromEntries(detailRows(dev('a', { ip: '10.0.0.2', mac: 'aa', ssdp_server: 'S', ssdp_location: evil, services: ['_ipp'] }), 0));
  assert.equal(rows['SSDP location'], evil, 'raw text; the panel uses textContent');
  assert.equal(rows['SSDP server'], 'S');
  assert.equal(rows.Services, '_ipp');
  const bare = Object.fromEntries(detailRows(dev('b', { ip: '10.0.0.3', mac: 'bb' }), 0));
  assert.ok(!('SSDP location' in bare));
  assert.ok(!('Hostname' in bare));
});

// ---- round 1: labels, node style, collision ----
import { labelParts, labelText, nodeStyle, nodeRadius, collisionRadius, separate, makeCollideForce, seedPosition } from '../graph-model.js';

test('label: hostname wins, then vendor, then IP', () => {
  assert.equal(labelText(dev('a', { hostname: 'printer', vendor: 'HP', ip: '10.0.0.9' })), 'printer');
  assert.equal(labelText(dev('a', { hostname: null, vendor: 'Sonos, Inc.', ip: '10.0.0.9' })), 'Sonos');
  assert.equal(labelText(dev('a', { hostname: '', vendor: null, ip: '10.0.0.9' })), '10.0.0.9');
  assert.equal(labelText(dev('a', { hostname: '   ', vendor: '  ', ip: '10.0.0.9' })), '10.0.0.9');
});

test('label: every device gets non-empty text, even with no fields at all', () => {
  assert.ok(labelText({}).length > 0);
  assert.ok(labelText({ ip: '10.0.0.1' }).length > 0);
});

test('label: vendor legal suffixes are trimmed, never to nothing', () => {
  assert.equal(labelText(dev('a', { vendor: 'GIGA-BYTE TECHNOLOGY CO.,LTD.' })), 'GIGA-BYTE');
  assert.equal(labelText(dev('a', { vendor: 'QDI Technology (H.K.) Limited' })), 'QDI');
  assert.equal(labelText(dev('a', { vendor: 'Apple, Inc.' })), 'Apple');
  assert.equal(labelText(dev('a', { vendor: 'Technology' })), 'Technology');
});

test('label: long machine hostnames lose the hex tail and .local; long text is ellipsized', () => {
  assert.equal(labelText(dev('a', { hostname: 'Android_0123456789abcdef0123456789abcdef' })), 'Android');
  assert.equal(labelText(dev('a', { hostname: 'macbook.local' })), 'macbook');
  const long = labelText(dev('a', { hostname: 'a-very-long-human-hostname-indeed-yes' }));
  assert.ok([...long].length <= 24);
  assert.ok(long.endsWith('\u2026'));
});

test('label: control and bidi characters from the LAN are removed', () => {
  const t = labelText(dev('a', { hostname: 'evil\u202Ename\n\u0000x' }));
  assert.ok(!/[\u202e\u0000\n]/.test(t), JSON.stringify(t));
  // markup stays plain text: the UI uses textContent, so it is never parsed
  assert.equal(labelText(dev('a', { hostname: '<b>x</b>' })), '<b>x</b>');
});

test('label: secondary line carries the IP, or "private MAC" when the IP is the name', () => {
  assert.deepEqual(labelParts(dev('a', { hostname: 'tv', ip: '10.0.0.2' })), { primary: 'tv', secondary: '10.0.0.2' });
  assert.deepEqual(labelParts(dev('a', { ip: '10.0.0.3', randomized_mac: true })), { primary: '10.0.0.3', secondary: 'private MAC' });
  assert.deepEqual(labelParts(dev('a', { ip: '10.0.0.3' })), { primary: '10.0.0.3', secondary: null });
});

test('nodeStyle uses the legend colours and fades offline devices', () => {
  assert.equal(nodeStyle(dev('g', { is_gateway: true })).color, '#ffc247');
  assert.equal(nodeStyle(dev('s', { is_self: true })).color, '#5ab0ff');
  assert.equal(nodeStyle(dev('n', { is_new: true })).color, '#ff7a3d');
  assert.equal(nodeStyle(dev('o')).color, '#5fe08a');
  const off = nodeStyle(dev('x', { online: false }));
  assert.ok(off.opacity < 0.5 && off.glow === 0);
  const hexes = [dev('g', { is_gateway: true }), dev('s', { is_self: true }), dev('n', { is_new: true }), dev('o'), dev('x', { online: false })].map((d) => nodeStyle(d).color);
  assert.equal(new Set(hexes).size, 5);
  assert.ok(hexes.every((h) => /^#[0-9a-f]{6}$/.test(h)));
});

test('radii: gateway > this Mac > others, collision radius adds clearance', () => {
  assert.ok(nodeRadius(dev('g', { is_gateway: true })) > nodeRadius(dev('s', { is_self: true })));
  assert.ok(nodeRadius(dev('s', { is_self: true })) > nodeRadius(dev('o')));
  assert.ok(collisionRadius(dev('o')) > nodeRadius(dev('o')));
});

function rng(seed) {
  let s = seed;
  return () => ((s = (s * 1664525 + 1013904223) % 4294967296) / 4294967296);
}

function minGap(nodes) {
  let worst = Infinity;
  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const a = nodes[i], b = nodes[j];
      worst = Math.min(worst, Math.hypot(a.x - b.x, a.y - b.y, a.z - b.z) - (collisionRadius(a) + collisionRadius(b)));
    }
  }
  return worst;
}

test('separate: a crowd of overlapping nodes ends up with no overlap, pinned gateway untouched', () => {
  const r = rng(7);
  const nodes = [{ ...dev('gw', { is_gateway: true }), x: 0, y: 0, z: 0, fx: 0, fy: 0, fz: 0 }];
  for (let i = 0; i < 40; i++) nodes.push({ ...dev('n' + i, i % 5 === 0 ? { is_self: true } : {}), x: (r() - 0.5) * 20, y: (r() - 0.5) * 20, z: (r() - 0.5) * 20 });
  assert.ok(minGap(nodes) < 0);
  for (let t = 0; t < 120; t++) separate(nodes, collisionRadius);
  assert.ok(minGap(nodes) > -0.01, 'min gap ' + minGap(nodes));
  assert.deepEqual([nodes[0].x, nodes[0].y, nodes[0].z], [0, 0, 0]);
});

test('separate: coincident nodes are pulled apart without NaN', () => {
  const nodes = [{ ...dev('a'), x: 1, y: 1, z: 1 }, { ...dev('b'), x: 1, y: 1, z: 1 }];
  for (let t = 0; t < 30; t++) separate(nodes, collisionRadius);
  assert.ok(nodes.every((n) => Number.isFinite(n.x + n.y + n.z)));
  assert.ok(minGap(nodes) > -0.01);
});

test('separate: nodes that are already clear do not move; the heavier node moves less', () => {
  const far = [{ ...dev('a'), x: 0, y: 0, z: 0 }, { ...dev('b'), x: 100, y: 0, z: 0 }];
  separate(far, collisionRadius);
  assert.deepEqual([far[0].x, far[1].x], [0, 100]);
  const mixed = [{ ...dev('g', { is_gateway: true }), x: 0, y: 0, z: 0 }, { ...dev('o'), x: 5, y: 0, z: 0 }];
  separate(mixed, collisionRadius, { iterations: 1 });
  assert.ok(Math.abs(mixed[0].x) < Math.abs(mixed[1].x - 5));
});

test('separate: removes only part of an overlap per iteration (eased, not snapped)', () => {
  const nodes = [{ ...dev('a'), x: 0, y: 0, z: 0 }, { ...dev('b'), x: 4, y: 0, z: 0 }];
  separate(nodes, collisionRadius, { iterations: 1, softness: 0.5 });
  const d = Math.abs(nodes[1].x - nodes[0].x);
  assert.ok(d > 4 && d < collisionRadius(nodes[0]) * 2, 'distance ' + d);
});

test('makeCollideForce follows the d3 force contract (initialize + call)', () => {
  const nodes = [{ ...dev('a'), x: 0, y: 0, z: 0 }, { ...dev('b'), x: 1, y: 0, z: 0 }];
  const f = makeCollideForce(collisionRadius);
  f.initialize(nodes);
  f(0.3);
  assert.ok(Math.abs(nodes[1].x - nodes[0].x) > 1);
});

test('seedPosition lands at the requested distance from the gateway, on any bearing', () => {
  const r = rng(3);
  for (let i = 0; i < 20; i++) {
    const p = seedPosition({ x: 10, y: -5, z: 2 }, r, 60);
    assert.ok(Math.abs(Math.hypot(p.x - 10, p.y + 5, p.z - 2) - 60) < 1e-9);
  }
  const p = seedPosition(undefined, () => 0.5, 10);
  assert.ok(Number.isFinite(p.x + p.y + p.z));
});

import { nodeCategory, hashAngle } from '../graph-model.js';

test('nodeCategory follows the colour precedence and matches the five legend entries', () => {
  assert.equal(nodeCategory(dev('g', { is_gateway: true, is_self: true })), 'gw');
  assert.equal(nodeCategory(dev('s', { is_self: true })), 'me');
  assert.equal(nodeCategory(dev('x', { online: false, is_new: true })), 'off');
  assert.equal(nodeCategory(dev('n', { is_new: true })), 'new');
  assert.equal(nodeCategory(dev('o')), 'on');
});

test('hashAngle is stable and within [0, 2pi)', () => {
  assert.equal(hashAngle('abc'), hashAngle('abc'));
  assert.notEqual(hashAngle('abc'), hashAngle('abd'));
  for (const s of ['', 'a', '00:16:96:00:00:68', '\u{1F9A0}']) {
    const a = hashAngle(s);
    assert.ok(a >= 0 && a < Math.PI * 2);
  }
});

// ---- round 2: new fields, rename, duplicates, pin ----
import { displayName, duplicatePrimaries, detailGroups, normalizeMeta, metaUrl, linkStrength } from '../graph-model.js';

test('label priority: custom, friendly, hostname, dns, netbios, vendor, IP', () => {
  const all = { custom_name: 'Mine', friendly_name: 'Living Room TV', hostname: 'host', dns_name: 'dns.local', netbios_name: 'NB', vendor: 'Vend', ip: '10.0.0.5' };
  const order = ['custom_name', 'friendly_name', 'hostname', 'dns_name', 'netbios_name'];
  const want = ['Mine', 'Living Room TV', 'host', 'dns', 'NB'];
  const d = { ...all };
  for (let i = 0; i < order.length; i++) {
    assert.equal(labelText(d), want[i], order[i]);
    assert.equal(displayName(d), i === 3 ? 'dns.local' : want[i]);
    delete d[order[i]];
  }
  assert.equal(labelText(d), 'Vend');
  delete d.vendor;
  assert.equal(labelText(d), '10.0.0.5');
});

test('blank or null new fields are skipped, not shown', () => {
  assert.equal(labelText({ custom_name: '  ', friendly_name: null, hostname: 'h', ip: '1.1.1.1' }), 'h');
  assert.equal(displayName({ custom_name: '', ip: '1.1.1.1' }), '1.1.1.1');
});

test('duplicate primaries are tagged with the last IP octet', () => {
  const a = dev('a', { hostname: 'Mac', ip: '10.0.0.172' });
  const b = dev('b', { hostname: 'Mac', ip: '10.0.0.173' });
  const c = dev('c', { hostname: 'tv', ip: '10.0.0.9' });
  const dup = duplicatePrimaries([a, b, c]);
  assert.deepEqual([...dup], ['Mac']);
  assert.equal(labelParts(a, 22, dup.has('Mac')).primary, 'Mac .172');
  assert.equal(labelParts(b, 22, true).primary, 'Mac .173');
  assert.equal(labelParts(c, 22, dup.has('tv')).primary, 'tv');
  assert.ok([...labelParts(dev('x', { hostname: 'a-very-long-human-hostname-indeed-yes', ip: '10.0.0.7' }), 22, true).primary].length <= 24);
});

test('detailGroups groups the fields, shows new ones only when present, formats rtt', () => {
  const base = detailGroups(dev('a', { ip: '10.0.0.2', mac: 'aa', kind: 'tv' }), 0);
  assert.deepEqual(base.map((g) => g.title), ['Identity', 'Hardware', 'Network', 'History']);
  const flat = Object.fromEntries(base.flatMap((g) => g.rows));
  for (const k of ['Name', 'Friendly name', 'DNS name', 'NetBIOS name', 'OS', 'Manufacturer', 'Model', 'Latency']) assert.ok(!(k in flat), k);
  const full = Object.fromEntries(
    detailGroups(dev('a', { ip: '10.0.0.2', mac: 'aa', custom_name: 'Den', friendly_name: 'F', dns_name: 'd', netbios_name: 'N', os_hint: 'Android', manufacturer: 'M', model: 'X1', rtt_ms: 4 }), 0).flatMap((g) => g.rows),
  );
  assert.equal(full.Name, 'Den');
  assert.equal(full.Latency, '4 ms');
  assert.equal(full.OS, 'Android');
  assert.equal(full.Model, 'X1');
  assert.equal(Object.fromEntries(detailGroups(dev('a', { rtt_ms: 12.6 }), 0).flatMap((g) => g.rows)).Latency, '13 ms');
  assert.equal(Object.fromEntries(detailGroups(dev('a', { rtt_ms: 0.46 }), 0).flatMap((g) => g.rows)).Latency, '0.5 ms');
  assert.ok(!('Latency' in Object.fromEntries(detailGroups(dev('a', { rtt_ms: 'x' }), 0).flatMap((g) => g.rows))));
});

test('normalizeMeta: empty clears, trims, enforces limits', () => {
  assert.deepEqual(normalizeMeta('  ', '').body, { custom_name: null, notes: null });
  assert.deepEqual(normalizeMeta(' Den ', ' hello\nworld ').body, { custom_name: 'Den', notes: 'hello\nworld' });
  assert.ok(normalizeMeta('x'.repeat(65), '').error);
  assert.ok(normalizeMeta('x'.repeat(64), '').body);
  assert.ok(normalizeMeta('', 'y'.repeat(501)).error);
  assert.ok(normalizeMeta('', 'y'.repeat(500)).body);
  assert.equal(normalizeMeta('a\u202eb\u0000', '').body.custom_name, 'ab');
  assert.equal(normalizeMeta(null, undefined).body.custom_name, null);
});

test('metaUrl encodes colons and @ in the id', () => {
  assert.equal(metaUrl('aa:bb:cc'), '/api/devices/aa%3Abb%3Acc/meta');
  assert.equal(metaUrl('a@b/c'), '/api/devices/a%40b%2Fc/meta');
});

test('linkStrength: live links glow, offline links fade with time', () => {
  const now = 10 * 3600000;
  assert.ok(linkStrength(dev('a'), now) > linkStrength(dev('x', { online: false, last_seen: now - 1000 }), now));
  assert.ok(linkStrength(dev('x', { online: false, last_seen: now - 1000 }), now) > linkStrength(dev('y', { online: false, last_seen: now - 40 * 3600000 }), now));
  assert.ok(linkStrength(undefined, now) > 0);
});

test('an update does not re-pin a gateway the user has moved; a role change does', () => {
  const map = new Map();
  reconcile(map, [dev('gw', { is_gateway: true })]);
  const g = map.get('gw');
  g.fx = 12; g.fy = 3; g.fz = 0;
  upsertDevice(map, dev('gw', { is_gateway: true, ip: '1.2.3.4' }));
  assert.equal(g.fx, 12);
  upsertDevice(map, dev('gw', { is_gateway: false }));
  assert.equal(g.fx, undefined);
  upsertDevice(map, dev('gw', { is_gateway: true }));
  assert.equal(g.fx, 0);
});

import { mixHex, pulseParams } from '../graph-model.js';

test('mixHex blends and tolerates bad input', () => {
  assert.equal(mixHex('#000000', '#ffffff', 0.5), '#808080');
  assert.equal(mixHex('#102030', '#102030', 0.7), '#102030');
  assert.equal(mixHex('#ff0000', '#0000ff', 0), '#ff0000');
  assert.equal(mixHex('#ff0000', '#0000ff', 2), '#0000ff');
  assert.equal(mixHex('rgba(1,2,3,0.4)', '#ffffff', 0.5), 'rgba(1,2,3,0.4)');
});

test('pulse: rtt drives speed and brightness when present, recency when not, offline is still', () => {
  const now = 1_000_000;
  const near = pulseParams(dev('a', { rtt_ms: 2 }), now);
  const far = pulseParams(dev('b', { rtt_ms: 200 }), now);
  assert.ok(near.speed > far.speed && near.glow > far.glow);
  const fresh = pulseParams(dev('c', { last_seen: now - 1000 }), now);
  const stale = pulseParams(dev('d', { last_seen: now - 3_600_000 }), now);
  assert.ok(fresh.speed > stale.speed && fresh.glow > stale.glow);
  assert.ok(stale.speed > 0, 'a quiet device still trickles');
  assert.deepEqual(pulseParams(dev('e', { online: false, rtt_ms: 1 }), now), { speed: 0, glow: 0 });
  // an unusable rtt falls back to recency instead of breaking
  assert.deepEqual(pulseParams(dev('f', { rtt_ms: NaN, last_seen: now }), now), pulseParams(dev('f', { last_seen: now }), now));
  assert.deepEqual(pulseParams(dev('g', { rtt_ms: -5, last_seen: now }), now), pulseParams(dev('g', { last_seen: now }), now));
});

test('collision radius gives this Mac room for its ring; two Macs keep their rings apart', () => {
  const mac = dev('m', { is_self: true });
  assert.ok(collisionRadius(mac) >= nodeRadius(mac) * 2.05 + 2);
  assert.ok(collisionRadius(mac) * 2 > nodeRadius(mac) * 2.05 * 2 + 4);
  assert.equal(collisionRadius(dev('o')), nodeRadius(dev('o')) + 6);
});

import { makeFlattenForce } from '../graph-model.js';

test('flatten force pulls free nodes toward y = 0 and leaves pinned ones', () => {
  const free = { y: 60, vy: 0 };
  const pinned = { y: 60, vy: 0, fy: 60 };
  const f = makeFlattenForce(0.03);
  f.initialize([free, pinned]);
  for (let i = 0; i < 200; i++) {
    f();
    free.y += free.vy;
    free.vy *= 0.75; // friction, as in the simulation
  }
  assert.ok(Math.abs(free.y) < 5, 'y ' + free.y);
  assert.equal(pinned.vy, 0);
});
