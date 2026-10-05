import test from 'node:test';
import assert from 'node:assert/strict';
import { SHAPES, rootCurve, rootRadius, buildRootGeometry, rootMatrix, toWorld, clearance, chooseRoll, branchPoint } from '../roots.js';

const gw = { x: 0, y: 0, z: 0 };
const leaf = { x: 100, y: 0, z: 0 };

test('root curve runs from the gateway to the leaf and bows between', () => {
  for (const s of SHAPES) {
    assert.deepEqual(rootCurve(0, s).map((v) => Math.abs(v) < 1e-12), [true, true, true]);
    const e = rootCurve(1, s);
    assert.ok(Math.abs(e[0] - 1) < 1e-12 && Math.abs(e[1]) < 1e-12);
    assert.ok(Math.abs(rootCurve(0.5, s)[1]) > 0.02);
  }
});

test('roots taper from the gateway to the leaf', () => {
  assert.ok(rootRadius(0) > rootRadius(0.5));
  assert.ok(rootRadius(0.5) > rootRadius(1));
  assert.ok(rootRadius(1) > 0);
});

test('geometry is finite, indexed within range, and has side filaments', () => {
  for (const s of SHAPES) {
    const g = buildRootGeometry(s);
    assert.ok(g.positions.length % 3 === 0 && g.positions.every(Number.isFinite));
    const verts = g.positions.length / 3;
    assert.ok(g.index.length % 3 === 0 && g.index.every((i) => Number.isInteger(i) && i >= 0 && i < verts));
    assert.ok(verts > 14 * 5);
    // the side filaments leave the main plane
    assert.ok(g.positions.some((v, i) => i % 3 === 2 && Math.abs(v) > 0.01));
  }
  const b = branchPoint(SHAPES[0], 0, 0);
  const m = rootCurve(SHAPES[0].branches[0].t, SHAPES[0]);
  assert.ok(Math.abs(b[0] - m[0]) < 1e-9 && Math.abs(b[1] - m[1]) < 1e-9);
});

test('rootMatrix maps the unit root onto gateway-to-leaf for any roll and any direction', () => {
  for (const roll of [0, 1.3, 4]) {
    for (const l of [{ x: 100, y: 0, z: 0 }, { x: 0, y: 50, z: 0 }, { x: -30, y: 40, z: 70 }]) {
      const e = toWorld(gw, l, roll, [1, 0, 0]);
      assert.ok(Math.hypot(e.x - l.x, e.y - l.y, e.z - l.z) < 1e-9);
      const s = toWorld(gw, l, roll, [0, 0, 0]);
      assert.ok(Math.hypot(s.x, s.y, s.z) < 1e-9);
    }
  }
  const out = new Array(16);
  assert.ok(Math.abs(rootMatrix(out, gw, leaf, 0) - 100) < 1e-9);
  assert.equal(out[15], 1);
});

test('chooseRoll steers the bow away from a node in its way and keeps a clear roll', () => {
  const shape = SHAPES[0];
  const bowTop = toWorld(gw, leaf, 0, rootCurve(0.5, shape));
  const blocker = [{ x: bowTop.x, y: bowTop.y, z: bowTop.z, r: 12 }];
  assert.ok(clearance(gw, leaf, 0, shape, blocker) < 0);
  const r = chooseRoll(gw, leaf, shape, blocker, 0);
  assert.notEqual(r, 0);
  assert.ok(clearance(gw, leaf, r, shape, blocker) >= 0);
  assert.equal(chooseRoll(gw, leaf, shape, [{ x: 0, y: 500, z: 0, r: 5 }], 1.1), 1.1, 'clear roll is kept');
});

test('steering also keeps the side-filament spores out of other nodes\' glow', () => {
  const shape = SHAPES[0];
  const tip = toWorld(gw, leaf, 0, branchPoint(shape, 0, 1));
  const blocker = [{ x: tip.x, y: tip.y, z: tip.z, r: 8 }];
  assert.ok(clearance(gw, leaf, 0, shape, blocker) < 0);
  const r = chooseRoll(gw, leaf, shape, blocker, 0);
  assert.ok(clearance(gw, leaf, r, shape, blocker) >= 0);
  assert.equal(clearance(gw, leaf, 0, shape, blocker, blocker[0]), Infinity, 'own obstacle can be skipped');
});
