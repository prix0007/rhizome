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

test('new devices get link particles, others none', () => {
  assert.ok(linkParticles(dev('n', { is_new: true })) > 0);
  assert.equal(linkParticles(dev('o')), 0);
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
