import test from 'node:test';
import assert from 'node:assert/strict';
import { isLocalAgentOrigin, shouldUseDemo } from '../mode.js';
import { createDemoModel, applyMeta } from '../demo.js';
import { normalizeSample } from '../traffic.js';
import { reconcile, upsertDevice, nodeCategory, labelText } from '../graph-model.js';

test('local agent origins', () => {
  for (const o of ['http://127.0.0.1:7878', 'http://localhost:7878', 'http://localhost', 'http://127.0.0.1:80']) assert.ok(isLocalAgentOrigin(o), o);
  for (const o of ['https://user.github.io', 'http://192.168.0.5:7878', 'https://127.0.0.1:7878', 'null', '', undefined, 'http://127.0.0.1.evil.com', 'http://localhost.evil.com:7878']) assert.ok(!isLocalAgentOrigin(o), String(o));
});

test('demo activation: by origin, by ?demo, ?live overrides origin but not ?demo', () => {
  assert.equal(shouldUseDemo('http://127.0.0.1:7878', ''), false);
  assert.equal(shouldUseDemo('http://localhost:7878', '?debug'), false);
  assert.equal(shouldUseDemo('http://127.0.0.1:7878', '?demo'), true);
  assert.equal(shouldUseDemo('http://localhost:1234', '?x=1&demo=1'), true);
  assert.equal(shouldUseDemo('https://user.github.io', ''), true);
  assert.equal(shouldUseDemo('null', ''), true, 'file://');
  assert.equal(shouldUseDemo('https://tunnel.example', '?live'), false);
  assert.equal(shouldUseDemo('https://tunnel.example', '?live&demo'), true);
  assert.equal(shouldUseDemo(undefined, undefined), true);
});

const fixedClock = () => 1_800_000_000_000;

test('the synthetic network has the required mix and invented identifiers only', () => {
  const m = createDemoModel(fixedClock);
  const snap = m.snapshot();
  const d = snap.devices;
  assert.equal(d.filter((x) => x.is_gateway).length, 1);
  assert.equal(d.filter((x) => x.is_self).length, 1);
  assert.ok(d.filter((x) => x.online === false).length >= 2);
  assert.ok(d.filter((x) => x.randomized_mac).length >= 2);
  for (const k of ['tv', 'phone', 'printer', 'nas', 'iot', 'camera']) assert.ok(d.some((x) => x.kind === k), k);
  assert.ok(d.length >= 12);
  assert.equal(new Set(d.map((x) => x.id)).size, d.length);
  for (const x of d) {
    assert.match(x.mac, /^(d0:0d|02:de):00:00:00:[0-9a-f]{2}$/, x.mac);
    assert.match(x.ip, /^192\.168\.50\.\d+$/);
    assert.ok(labelText(x).length > 0);
  }
  assert.equal(snap.status.devices, d.length);
  assert.ok(snap.status.online < snap.status.devices);
  assert.deepEqual(snap.status.warnings, []);
});

test('over time: rtt events, a device goes offline and back, a new one joins, scans and traffic flow', () => {
  const m = createDemoModel(fixedClock);
  const map = new Map();
  reconcile(map, m.snapshot().devices);
  const kinds = new Map();
  let sawOffline = false, sawBack = false, joined = false, newFlagCleared = false;
  for (let i = 0; i < 100; i++) {
    for (const e of m.step()) {
      kinds.set(e.type, (kinds.get(e.type) || 0) + 1);
      if (e.type === 'device') {
        const wasOnline = map.has(e.data.id) && map.get(e.data.id).online;
        const added = upsertDevice(map, e.data);
        if (added) { joined = true; assert.equal(nodeCategory(e.data), 'new'); }
        if (wasOnline && e.data.online === false) sawOffline = true;
        if (sawOffline && e.data.online) sawBack = true;
        if (e.data.is_new === false && e.data.id.endsWith(':0f')) newFlagCleared = true;
      }
    }
  }
  assert.ok(sawOffline && sawBack && joined && newFlagCleared);
  assert.ok(kinds.get('traffic') === 100 && kinds.get('scan') >= 15 && kinds.get('device') > 20);
  assert.ok(map.size === m.devices.size);
});

test('traffic samples are valid, capture is unavailable, the host link is present', () => {
  const m = createDemoModel(fixedClock);
  const ev = m.step().find((e) => e.type === 'traffic');
  const s = normalizeSample(ev.data);
  assert.ok(s.host.link && s.host.rx_bps !== null);
  assert.equal(s.capture.enabled, false);
  assert.equal(s.capture.available, false);
  assert.match(s.capture.reason, /^Demo:/);
  assert.ok(![...s.devices.values()].some((d) => d.measured));
});

test('the demo is deterministic for a given seed and does not need a clock that moves', () => {
  const a = createDemoModel(fixedClock, 3), b = createDemoModel(fixedClock, 3);
  for (let i = 0; i < 30; i++) assert.deepEqual(a.step().filter((e) => e.type === 'device'), b.step().filter((e) => e.type === 'device'));
});

test('rename is simulated in memory with the real limits', () => {
  const m = createDemoModel(fixedClock);
  const id = 'd0:0d:00:00:00:03';
  const ok = m.rename(id, { custom_name: ' Den TV ', notes: 'bedroom' });
  assert.equal(ok.status, 200);
  assert.equal(ok.body.custom_name, 'Den TV');
  assert.equal(m.devices.get(id).notes, 'bedroom');
  assert.equal(m.rename(id, { custom_name: '', notes: null }).body.custom_name, null);
  assert.equal(m.rename(id, { custom_name: 'x'.repeat(65), notes: null }).status, 400);
  assert.equal(m.rename(id, { custom_name: null, notes: 'y'.repeat(501) }).status, 400);
  assert.equal(m.rename(id, { custom_name: 5 }).status, 400);
  assert.equal(m.rename('nope', {}).status, 404);
  assert.equal(applyMeta({}, null), 'bad request');
});
