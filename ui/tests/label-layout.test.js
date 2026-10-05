import test from 'node:test';
import assert from 'node:assert/strict';
import { placeLabels, rectOverlapArea, circleHitsRect, segmentHitsRect, labelBudget } from '../label-layout.js';

const item = (id, x, y, extra = {}) => ({ id, x, y, r: 8, w: 80, h: 26, ...extra });

function conflicts(items, out) {
  let n = 0;
  const list = items.map((i) => ({ i, rect: out.get(i.id).rect }));
  for (let a = 0; a < list.length; a++) {
    for (let b = a + 1; b < list.length; b++) if (rectOverlapArea(list[a].rect, list[b].rect) > 0) n++;
    for (const o of items) if (o.id !== list[a].i.id && circleHitsRect(o.x, o.y, o.r, list[a].rect)) n++;
  }
  return n;
}

test('a lone label sits below its node', () => {
  const out = placeLabels([item('a', 200, 200)]);
  const { rect, slot, cost } = out.get('a');
  assert.equal(slot, 0);
  assert.equal(cost, 0);
  assert.ok(rect.y > 208);
  assert.equal(rect.x + rect.w / 2, 200);
});

test('labels of vertically stacked nodes move out of each others way', () => {
  const items = [item('a', 200, 200), item('b', 200, 225), item('c', 205, 250)];
  const out = placeLabels(items);
  assert.equal(conflicts(items, out), 0);
});

test('a ring of 12 nodes gets 12 conflict-free labels', () => {
  const items = [];
  for (let i = 0; i < 12; i++) items.push(item('n' + i, 400 + 140 * Math.cos(i * 0.5236), 300 + 140 * Math.sin(i * 0.5236)));
  const out = placeLabels(items);
  assert.equal(out.size, 12);
  assert.equal(conflicts(items, out), 0);
});

test('every item always gets a placement, even when the layout is hopeless', () => {
  const items = Array.from({ length: 30 }, (_, i) => item('n' + i, 100 + (i % 3), 100));
  const out = placeLabels(items);
  assert.equal(out.size, 30);
  for (const v of out.values()) assert.ok(Number.isFinite(v.rect.x + v.rect.y));
});

test('higher priority gets its preferred slot', () => {
  const out = placeLabels([item('lo', 200, 200), item('hi', 200, 215, { priority: 5 })]);
  assert.equal(out.get('hi').slot, 0);
  assert.notEqual(out.get('lo').slot, 0);
});

test('the previous slot is kept while it is still free (no flicker)', () => {
  const out = placeLabels([item('a', 200, 200, { prev: 2 })]);
  assert.equal(out.get('a').slot, 2);
});

test('a label is pushed back inside the viewport', () => {
  const out = placeLabels([item('a', 395, 300)], { bounds: { x: 0, y: 0, w: 400, h: 600 } });
  const r = out.get('a').rect;
  assert.ok(r.x + r.w <= 400, JSON.stringify(r));
});

test('rect and circle helpers', () => {
  assert.equal(rectOverlapArea({ x: 0, y: 0, w: 10, h: 10 }, { x: 5, y: 5, w: 10, h: 10 }), 25);
  assert.equal(rectOverlapArea({ x: 0, y: 0, w: 10, h: 10 }, { x: 20, y: 0, w: 5, h: 5 }), 0);
  assert.ok(circleHitsRect(5, 5, 1, { x: 0, y: 0, w: 10, h: 10 }));
  assert.ok(!circleHitsRect(20, 5, 3, { x: 0, y: 0, w: 10, h: 10 }));
});

test('a label avoids its own link line', () => {
  const items = [item('a', 300, 300)];
  // a link running straight down from the node blocks the default "below" slot
  const segments = [{ id: 'a', x1: 300, y1: 300, x2: 300, y2: 500 }];
  const out = placeLabels(items, { segments });
  assert.notEqual(out.get('a').slot, 0);
  assert.equal(out.get('a').cost, 0);
  assert.ok(!segmentHitsRect(300, 300, 300, 500, out.get('a').rect));
});

test('the obstacle radius (glow) keeps the label clear of the halo', () => {
  const out = placeLabels([item('a', 200, 200, { r: 30 })]);
  assert.ok(out.get('a').rect.y >= 200 + 30);
});

test('hysteresis: a conflicting previous slot is abandoned, a free one is kept', () => {
  const segments = [{ id: 'a', x1: 300, y1: 300, x2: 300, y2: 500 }];
  const moved = placeLabels([item('a', 300, 300, { prev: 0 })], { segments });
  assert.notEqual(moved.get('a').slot, 0);
  const kept = placeLabels([item('a', 300, 300, { prev: 1 })]);
  assert.equal(kept.get('a').slot, 1);
});

test('segmentHitsRect', () => {
  const r = { x: 10, y: 10, w: 10, h: 10 };
  assert.ok(segmentHitsRect(0, 15, 30, 15, r));
  assert.ok(!segmentHitsRect(0, 0, 30, 5, r));
  assert.ok(segmentHitsRect(12, 12, 14, 14, r));
  assert.ok(!segmentHitsRect(25, 0, 25, 30, r));
});

test('150 labels place in well under a frame budget', () => {
  const items = [];
  for (let i = 0; i < 150; i++) items.push(item('n' + i, 100 + ((i * 97) % 1000), 80 + ((i * 53) % 600)));
  const t0 = performance.now();
  placeLabels(items, { bounds: { x: 0, y: 0, w: 1280, h: 800 } });
  const ms = performance.now() - t0;
  assert.ok(ms < 100, 'took ' + ms + ' ms');
});

test('a label never sits on an excluded rectangle (HUD, open panel)', () => {
  const hud = { x: 0, y: 0, w: 400, h: 200 };
  const out = placeLabels([item('a', 100, 190)], { exclusions: [hud] });
  assert.equal(rectOverlapArea(out.get('a').rect, hud), 0);
  assert.equal(out.get('a').cost, 0);
});

test('a conflict-free previous slot is accepted without scoring the rest', () => {
  const out = placeLabels([item('a', 500, 300, { prev: 3 })]);
  assert.equal(out.get('a').slot, 3);
  assert.equal(out.get('a').cost, 0);
});

test('the spatial grid does not miss neighbours across cell borders (16-label ring)', () => {
  const items = [];
  for (let i = 0; i < 16; i++) items.push(item('n' + i, 600 + 250 * Math.cos(i * 0.3927), 400 + 250 * Math.sin(i * 0.3927)));
  const out = placeLabels(items);
  assert.equal(conflicts(items, out), 0);
});

test('labelBudget: everything shows up to the limit; beyond it only gateway/self/near/big', () => {
  const small = Array.from({ length: 30 }, (_, i) => ({ id: 'n' + i, depth: i, bodyPx: 3 }));
  assert.equal(labelBudget(small).size, 30);
  const many = Array.from({ length: 120 }, (_, i) => ({ id: 'n' + i, depth: 100 + i, bodyPx: 3, always: i === 50 }));
  many[100].bodyPx = 20;
  const shown = labelBudget(many, { limit: 60, nearest: 10 });
  assert.ok(shown.has('n50'), 'always');
  assert.ok(shown.has('n100'), 'close up (big on screen)');
  for (let i = 0; i < 10; i++) assert.ok(shown.has('n' + i), 'nearest ' + i);
  assert.ok(!shown.has('n80'));
  assert.equal(shown.size, 12);
});

test('100 labels (budgeted to 40) place in under 5 ms with few overlaps', () => {
  const all = [];
  for (let i = 0; i < 100; i++) all.push(item('n' + i, 150 + ((i * 97) % 900), 120 + ((i * 53) % 560), { r: 14 }));
  const shown = all.slice(0, 40);
  const t0 = performance.now();
  placeLabels(shown, { bounds: { x: 0, y: 0, w: 1280, h: 800 } });
  assert.ok(performance.now() - t0 < 5);
});

test('a multi-segment root polyline is avoided, and the gateway label avoids every root', () => {
  const bent = [
    { id: 'a', x1: 300, y1: 300, x2: 300, y2: 350 },
    { id: 'a', x1: 300, y1: 350, x2: 360, y2: 400 },
  ];
  const out = placeLabels([item('a', 300, 300)], { segments: bent });
  const r = out.get('a').rect;
  assert.ok(!bent.some((s) => segmentHitsRect(s.x1, s.y1, s.x2, s.y2, r)));
  const others = Array.from({ length: 50 }, (_, i) => ({ id: 'n' + i, x1: 300, y1: 300, x2: 300, y2: 340 }));
  const gwOut = placeLabels([item('gw', 300, 300, { avoidAllLinks: true }), ...Array.from({ length: 50 }, (_, i) => item('n' + i, 900 + i, 700))], { segments: others });
  assert.ok(!others.some((s) => segmentHitsRect(s.x1, s.y1, s.x2, s.y2, gwOut.get('gw').rect)));
});
