import test from 'node:test';
import assert from 'node:assert/strict';
import { placeLabels, rectOverlapArea, circleHitsRect } from '../label-layout.js';

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
