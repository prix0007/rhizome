// Screen-space label placement. Pure: no DOM, no three.js. Tested with `node --test ui/tests/`.

/**
 * Candidate anchors around a node, in the order they are tried. Each gives the
 * top-left corner of a w x h label box for a node of screen radius r at (x, y).
 */
export const SLOTS = [
  (x, y, r, w, h, g) => ({ x: x - w / 2, y: y + r + g }), // 0 below
  (x, y, r, w, h, g) => ({ x: x - w / 2, y: y - r - g - h }), // 1 above
  (x, y, r, w, h, g) => ({ x: x + r + g + 2, y: y - h / 2 }), // 2 right
  (x, y, r, w, h, g) => ({ x: x - r - g - 2 - w, y: y - h / 2 }), // 3 left
  (x, y, r, w, h, g) => ({ x: x - w / 2, y: y + r + g + h + 4 }), // 4 further below
  (x, y, r, w, h, g) => ({ x: x - w / 2, y: y - r - g - h * 2 - 4 }), // 5 further above
  (x, y, r, w, h, g) => ({ x: x + r * 0.7 + g, y: y + r * 0.7 + g }), // 6 below right
  (x, y, r, w, h, g) => ({ x: x - r * 0.7 - g - w, y: y + r * 0.7 + g }), // 7 below left
  (x, y, r, w, h, g) => ({ x: x + r * 0.7 + g, y: y - r * 0.7 - g - h }), // 8 above right
  (x, y, r, w, h, g) => ({ x: x - r * 0.7 - g - w, y: y - r * 0.7 - g - h }), // 9 above left
];

export function rectOverlapArea(a, b) {
  const w = Math.min(a.x + a.w, b.x + b.w) - Math.max(a.x, b.x);
  const h = Math.min(a.y + a.h, b.y + b.h) - Math.max(a.y, b.y);
  return w > 0 && h > 0 ? w * h : 0;
}

/** True when the disc (cx, cy, r) intersects the rectangle. */
export function circleHitsRect(cx, cy, r, rect) {
  const nx = Math.max(rect.x, Math.min(cx, rect.x + rect.w));
  const ny = Math.max(rect.y, Math.min(cy, rect.y + rect.h));
  return Math.hypot(cx - nx, cy - ny) < r;
}

function cost(rect, item, placed, discs, bounds, pad) {
  const padded = { x: rect.x - pad, y: rect.y - pad, w: rect.w + pad * 2, h: rect.h + pad * 2 };
  let c = 0;
  for (const p of placed) c += rectOverlapArea(padded, p.rect);
  for (const d of discs) {
    if (d.id !== item.id && circleHitsRect(d.x, d.y, d.r + pad, rect)) c += 400;
  }
  if (bounds) {
    if (rect.x < bounds.x) c += (bounds.x - rect.x) * rect.h + 50;
    if (rect.y < bounds.y) c += (bounds.y - rect.y) * rect.w + 50;
    if (rect.x + rect.w > bounds.x + bounds.w) c += (rect.x + rect.w - bounds.x - bounds.w) * rect.h + 50;
    if (rect.y + rect.h > bounds.y + bounds.h) c += (rect.y + rect.h - bounds.y - bounds.h) * rect.w + 50;
  }
  return c;
}

/**
 * Choose a slot for every label so that no label covers another label or any
 * node disc, where the geometry allows it.
 *
 * items: [{ id, x, y, r, w, h, priority?, prev? }]  (screen px; prev is the slot used last frame)
 * returns Map id -> { slot, rect: {x,y,w,h}, cost }   (cost 0 means conflict-free)
 *
 * Higher priority is placed first and gets its preferred slot. A previously
 * chosen slot is kept while it is still conflict-free, so labels do not flicker
 * between slots as the camera moves.
 */
export function placeLabels(items, { gap = 5, pad = 2, bounds = null } = {}) {
  const discs = items.map((i) => ({ id: i.id, x: i.x, y: i.y, r: i.r }));
  const order = [...items].sort((a, b) => (b.priority || 0) - (a.priority || 0) || a.y - b.y || (a.id < b.id ? -1 : 1));
  const placed = [];
  const out = new Map();
  for (const item of order) {
    const rectAt = (k) => ({ ...SLOTS[k](item.x, item.y, item.r, item.w, item.h, gap), w: item.w, h: item.h });
    let best = null;
    const tryOrder = [];
    if (Number.isInteger(item.prev) && SLOTS[item.prev]) tryOrder.push(item.prev);
    for (let k = 0; k < SLOTS.length; k++) if (k !== item.prev) tryOrder.push(k);
    for (const k of tryOrder) {
      const rect = rectAt(k);
      const c = cost(rect, item, placed, discs, bounds, pad);
      if (best === null || c < best.cost) best = { slot: k, rect, cost: c };
      if (c === 0) break;
    }
    placed.push(best);
    out.set(item.id, best);
  }
  return out;
}
