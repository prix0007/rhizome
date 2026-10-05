import test from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeSample, formatRate, formatLinkRate, signalQuality, describeLink, isStale, smooth, pushHistory,
  niceCeil, sparkPoints, rememberedOpen, storeOpen, rateLevel, pulseMode, pulsePlan, chatterEmitters, captureStatus, trafficGroup, fakeSample, HISTORY,
} from '../traffic.js';

const full = () => ({
  ts: 1,
  host: { iface: 'en8', rx_bps: 1250000, tx_bps: 98000, link: { kind: 'wifi', rate_mbps: 866, rssi_dbm: -52, noise_dbm: -90, channel: '44 (5 GHz, 80 MHz)', phy: '802.11ax' } },
  wan: { rx_bps: 5400000, tx_bps: 310000, source: 'upnp-igd' },
  devices: { a: { loss_pct: 0, jitter_ms: 1.4, rx_bps: 12000, tx_bps: 800, measured: true }, b: { loss_pct: 1, jitter_ms: 2, rx_bps: null, tx_bps: null, measured: false } },
  capture: { enabled: true, available: true, reason: null, flows: [{ src: 'a', dst: 'multicast', proto: 'mdns', bps: 4200, pps: 6 }, { src: 'x' }, null] },
});

test('normalizeSample keeps good data and drops garbage', () => {
  const s = normalizeSample(full());
  assert.equal(s.host.rx_bps, 1250000);
  assert.equal(s.host.link.kind, 'wifi');
  assert.equal(s.wan.source, 'upnp-igd');
  assert.equal(s.devices.get('a').measured, true);
  assert.equal(s.devices.get('b').measured, false);
  assert.equal(s.capture.flows.length, 1);
});

test('normalizeSample survives nulls and nonsense in every position', () => {
  for (const bad of [null, undefined, 5, 'x', [], true]) assert.equal(normalizeSample(bad), null);
  const s = normalizeSample({ host: null, wan: null, devices: null, capture: null });
  assert.equal(s.host, null); assert.equal(s.wan, null); assert.equal(s.devices.size, 0); assert.equal(s.capture, null);
  const t = normalizeSample({ host: { rx_bps: -5, tx_bps: 'x', link: { kind: 'carrier-pigeon', rate_mbps: NaN } }, wan: { rx_bps: null, tx_bps: null }, devices: { a: null, b: { loss_pct: 'x', measured: true } }, capture: { flows: 'no' } });
  assert.equal(t.host.rx_bps, null); assert.equal(t.host.tx_bps, null); assert.equal(t.host.link.kind, null);
  assert.equal(t.wan, null);
  assert.equal(t.devices.has('a'), false);
  assert.equal(t.devices.get('b').measured, false, 'measured:true without any rate is not a measurement');
  assert.deepEqual(t.capture.flows, []);
});

test('formatRate uses human units with stable precision', () => {
  assert.equal(formatRate(null), '—');
  assert.equal(formatRate(NaN), '—');
  assert.equal(formatRate(-1), '—');
  assert.equal(formatRate(0), '0 bps');
  assert.equal(formatRate(999), '999 bps');
  assert.equal(formatRate(1250), '1.3 kbps');
  assert.equal(formatRate(98000), '98 kbps');
  assert.equal(formatRate(1250000), '1.3 Mbps');
  assert.equal(formatRate(866e6), '866 Mbps');
  assert.equal(formatRate(2.5e9), '2.5 Gbps');
});

test('link description: wifi with signal, ethernet, unknown', () => {
  assert.equal(formatLinkRate(866), '866 Mbps');
  assert.equal(formatLinkRate(1000), '1 Gbps');
  assert.equal(formatLinkRate(2500), '2.5 Gbps');
  assert.equal(formatLinkRate(0), null);
  assert.deepEqual(describeLink(normalizeSample(full()).host.link), { title: 'Wi-Fi 866 Mbps', detail: 'good signal -52 dBm, SNR 38 dB, 44 (5 GHz, 80 MHz), 802.11ax' });
  assert.deepEqual(describeLink({ kind: 'ethernet', rate_mbps: 1000 }), { title: 'Ethernet 1 Gbps', detail: '' });
  assert.deepEqual(describeLink({ kind: 'wifi', rate_mbps: null, rssi_dbm: null, noise_dbm: null, channel: null, phy: null }), { title: 'Wi-Fi', detail: '' });
  assert.equal(describeLink(null), null);
  assert.equal(describeLink({ kind: null }), null);
  assert.deepEqual(['excellent', 'good', 'fair', 'weak', null], [-45, -55, -65, -80, undefined].map(signalQuality));
});

test('stale detection', () => {
  assert.equal(isStale(1000, 3000), false);
  assert.equal(isStale(1000, 7000), true);
  assert.equal(isStale(undefined, 1000), true);
  assert.equal(isStale(null, 1000), true);
});

test('smoothing ignores bad samples and converges', () => {
  assert.equal(smooth(10, null), 10);
  assert.equal(smooth(undefined, 4), 4);
  let v = 0; for (let i = 0; i < 40; i++) v = smooth(v, 100);
  assert.ok(Math.abs(v - 100) < 0.1);
});

test('history is bounded and keeps the time axis (null becomes 0)', () => {
  const h = [];
  for (let i = 0; i < 100; i++) pushHistory(h, i);
  assert.equal(h.length, HISTORY); assert.equal(h[h.length - 1], 99);
  pushHistory(h, null); assert.equal(h[h.length - 1], 0);
});

test('sparkline scale steps in 1-2-5 and points stay inside the box', () => {
  assert.equal(niceCeil(0), 10000);
  assert.equal(niceCeil(1200000), 2000000);
  assert.equal(niceCeil(2000000), 2000000);
  assert.equal(niceCeil(2000001), 5000000);
  assert.equal(niceCeil(9e6), 1e7);
  const pts = sparkPoints([0, 5, 10, 20], 100, 30, 10).split(' ').map((p) => p.split(',').map(Number));
  assert.equal(pts.length, 4);
  assert.ok(pts.every(([x, y]) => x >= 0 && x <= 100 && y >= 0 && y <= 30));
  assert.equal(pts[3][0], 100, 'newest sample at the right edge');
  assert.ok(pts[2][1] === pts[3][1], 'values above max are clamped');
  assert.equal(sparkPoints([], 100, 30, 10), '');
});

test('rateLevel is a log scale clamped to 0..1', () => {
  assert.equal(rateLevel(0), 0); assert.equal(rateLevel(null), 0); assert.equal(rateLevel(500), 0);
  assert.equal(rateLevel(1e5), 0.4); assert.equal(rateLevel(1e9), 1);
  assert.ok(rateLevel(1e6) > rateLevel(1e4));
});

test('measured vs estimated: only a measured device is "measured"', () => {
  const s = normalizeSample(full());
  assert.equal(pulseMode(s.devices.get('a')), 'measured');
  assert.equal(pulseMode(s.devices.get('b')), 'latency');
  assert.equal(pulseMode(undefined), 'latency');
});

test('pulsePlan: measured follows rates, latency is the fallback, offline is still, host uses its counters', () => {
  const s = normalizeSample(full());
  const lat = { speed: 0.3, glow: 0.6 };
  const a = pulsePlan({ id: 'a', online: true }, s, lat);
  assert.equal(a.mode, 'measured');
  assert.ok(a.streams.every((x) => x.dir === 1 || x.dir === -1));
  const b = pulsePlan({ id: 'b', online: true }, s, lat);
  assert.equal(b.mode, 'latency'); assert.deepEqual(b.streams, [{ dir: 1, speed: 0.3, glow: 0.6, count: 1 }]);
  assert.equal(pulsePlan({ id: 'b', online: false }, s, lat).mode, 'none');
  assert.equal(pulsePlan({ id: 'zz', online: true }, null, lat).mode, 'latency');
  assert.equal(pulsePlan({ id: 'zz', online: true }, null, { speed: 0, glow: 0 }).mode, 'none');
  const me = pulsePlan({ id: 'me', is_self: true, online: true }, s, lat);
  assert.equal(me.mode, 'measured');
  assert.equal(me.streams.length, 2);
  const fast = pulsePlan({ id: 'f', online: true }, normalizeSample({ devices: { f: { rx_bps: 5e7, tx_bps: 5e7, measured: true } } }), lat);
  const slow = pulsePlan({ id: 'f', online: true }, normalizeSample({ devices: { f: { rx_bps: 2e3, tx_bps: 2e3, measured: true } } }), lat);
  assert.ok(fast.streams[0].speed > slow.streams[0].speed && fast.streams[0].count >= slow.streams[0].count);
  const idle = pulsePlan({ id: 'f', online: true }, normalizeSample({ devices: { f: { rx_bps: 0, tx_bps: 0, measured: true } } }), lat);
  assert.equal(idle.mode, 'measured'); assert.deepEqual(idle.streams, []);
});

test('chatter: only enabled capture, known senders, broadcast/multicast destinations', () => {
  const s = normalizeSample(full());
  const em = chatterEmitters(s.capture, new Set(['a', 'b']));
  assert.deepEqual(em.map((e) => [e.id, e.proto]), [['a', 'mdns']]);
  assert.deepEqual(chatterEmitters(s.capture, new Set(['b'])), []);
  assert.deepEqual(chatterEmitters({ ...s.capture, enabled: false }, new Set(['a'])), []);
  assert.deepEqual(chatterEmitters(null, new Set(['a'])), []);
  const uni = normalizeSample({ capture: { enabled: true, available: true, flows: [{ src: 'a', dst: 'b', proto: 'tcp', bps: 1e6 }] } }).capture;
  assert.deepEqual(chatterEmitters(uni, new Set(['a', 'b'])), []);
});

test('capture status uses the server wording and never invents a toggle', () => {
  assert.equal(captureStatus(null).state, 'unknown');
  const un = captureStatus({ enabled: false, available: false, reason: 'needs permission X' });
  assert.deepEqual([un.state, un.text], ['unavailable', 'needs permission X']);
  assert.equal(captureStatus({ enabled: false, available: false, reason: null }).state, 'unavailable');
  assert.equal(captureStatus({ enabled: false, available: true, reason: null }).state, 'off');
  assert.equal(captureStatus({ enabled: true, available: true, reason: null }).state, 'on');
  assert.ok(!/--|flag|sudo/i.test(captureStatus({ enabled: false, available: true, reason: null }).text));
});

test('trafficGroup: pings always, rates only when measured, honest note', () => {
  const s = normalizeSample(full());
  const a = trafficGroup({ id: 'a', rtt_ms: 4 }, s);
  const m = Object.fromEntries(a.rows);
  assert.equal(m.Latency, '4 ms'); assert.equal(m.Jitter, '1.4 ms'); assert.equal(m['Packet loss'], '0%');
  assert.equal(m['To this Mac'], '800 bps'); assert.equal(m['From this Mac'], '12 kbps');
  assert.match(a.note, /measured/i);
  const b = Object.fromEntries(trafficGroup({ id: 'b' }, s).rows);
  assert.ok(!('To this Mac' in b)); assert.equal(b['Packet loss'], '1%');
  assert.match(trafficGroup({ id: 'b' }, s).note, /not available without packet capture/);
  const none = trafficGroup({ id: 'q' }, null);
  assert.deepEqual(none.rows, [['Measured', 'nothing yet']]);
  const me = Object.fromEntries(trafficGroup({ id: 'me', is_self: true }, s).rows);
  assert.equal(me['Down (this Mac)'], '1.3 Mbps');
});

test('fake samples normalise cleanly and respect the capture switch', () => {
  const ids = ['a', 'b', 'c', 'd'];
  const on = normalizeSample(fakeSample(10, { ids, selfId: 'a' }));
  assert.equal(on.devices.size, 4); assert.ok(on.capture.enabled); assert.ok(on.host.link);
  assert.ok([...on.devices.values()].some((d) => d.measured));
  const off = normalizeSample(fakeSample(10, { ids, withCapture: false }));
  assert.ok(![...off.devices.values()].some((d) => d.measured));
  assert.equal(off.capture.available, false); assert.ok(off.capture.reason);
});

test('HUD open state is remembered, and storage failures are harmless', () => {
  const mem = new Map();
  const ok = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, v) };
  assert.equal(rememberedOpen(ok, 'legend', true), true);
  storeOpen(ok, 'legend', false);
  assert.equal(rememberedOpen(ok, 'legend', true), false);
  storeOpen(ok, 'legend', true);
  assert.equal(rememberedOpen(ok, 'legend', false), true);
  const broken = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.equal(rememberedOpen(broken, 'x', true), true);
  assert.doesNotThrow(() => storeOpen(broken, 'x', false));
  assert.equal(rememberedOpen(null, 'x', false), false);
  assert.equal(rememberedOpen({ getItem: () => 'garbage' }, 'x', true), true);
});
