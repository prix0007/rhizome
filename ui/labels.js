// Always-on device labels as a DOM overlay positioned each frame.
// Text is only ever assigned with textContent: hostnames and vendors come from untrusted LAN hosts.
import { labelParts, nodeRadius, nodeStyle } from './graph-model.js';
import { placeLabels } from './label-layout.js';

const ALIGN = ['center', 'center', 'left', 'right', 'center', 'center', 'left', 'right', 'left', 'right'];

export function createLabels(container, graph) {
  const items = new Map(); // id -> { root, name, sub, key, w, h, x, y, slot, placed }
  let measureAll = true;
  if (document.fonts && document.fonts.ready) document.fonts.ready.then(() => { measureAll = true; });

  function ensure(id) {
    let it = items.get(id);
    if (it) return it;
    const root = document.createElement('div');
    root.className = 'label';
    const name = document.createElement('span');
    name.className = 'label-name';
    const sub = document.createElement('span');
    sub.className = 'label-sub';
    root.append(name, sub);
    container.append(root);
    it = { root, name, sub, key: null, w: 80, h: 28, x: 0, y: 0, slot: 0, placed: false, shown: false };
    items.set(id, it);
    return it;
  }

  function setText(it, d) {
    const key = [d.hostname, d.vendor, d.ip, d.mac, d.randomized_mac].join('\u0001');
    if (key === it.key) return false;
    it.key = key;
    const { primary, secondary } = labelParts(d);
    it.name.textContent = primary;
    it.sub.textContent = secondary || '';
    it.sub.hidden = !secondary;
    return true;
  }

  /** Project, place and draw. Call once per frame, after the graph has rendered. */
  function update(nodes, { selectedId = null, hoveredId = null, calm = false } = {}) {
    for (const [id, it] of items) {
      if (!nodes.has(id)) {
        it.root.remove();
        items.delete(id);
      }
    }
    const camera = graph.camera();
    const rect = container.getBoundingClientRect();
    const W = rect.width;
    const H = rect.height;
    if (!W || !H) return;
    camera.updateMatrixWorld();
    const e = camera.matrixWorldInverse.elements;
    const focal = H / 2 / Math.tan((camera.fov * Math.PI) / 360);
    const cp = camera.position;
    const refDist = Math.hypot(cp.x, cp.y, cp.z) || 1;

    const frameItems = [];
    const meta = new Map();
    for (const [id, d] of nodes) {
      const it = ensure(id);
      const textChanged = setText(it, d);
      if (textChanged || measureAll) {
        it.w = it.root.offsetWidth || it.w;
        it.h = it.root.offsetHeight || it.h;
      }
      const x = d.x || 0, y = d.y || 0, z = d.z || 0;
      const zv = e[2] * x + e[6] * y + e[10] * z + e[14];
      if (zv >= -1) {
        meta.set(id, null);
        continue;
      }
      const p = graph.graph2ScreenCoords(x, y, z);
      const r = Math.max(4, (nodeRadius(d) * focal) / -zv);
      meta.set(id, { zv });
      frameItems.push({
        id, x: p.x, y: p.y, r, w: it.w, h: it.h,
        priority: (d.is_gateway ? 3 : d.is_self ? 2 : 1) + (id === selectedId ? 4 : 0) + (id === hoveredId ? 4 : 0),
        prev: it.placed ? it.slot : undefined,
      });
    }
    measureAll = false;

    const placed = placeLabels(frameItems, { gap: 6, pad: 3, bounds: { x: 6, y: 44, w: W - 12, h: H - 80 } });
    const ease = calm ? 1 : 0.22;
    for (const [id, it] of items) {
      const pl = placed.get(id);
      if (!pl) {
        it.root.style.opacity = '0';
        it.placed = false;
        continue;
      }
      it.slot = pl.slot;
      if (!it.placed) {
        it.x = pl.rect.x;
        it.y = pl.rect.y;
        it.placed = true;
      } else {
        it.x += (pl.rect.x - it.x) * ease;
        it.y += (pl.rect.y - it.y) * ease;
      }
      const d = nodes.get(id);
      const depth = Math.max(0.5, Math.min(1, refDist / -meta.get(id).zv));
      const off = d.online === false;
      it.root.style.transform = `translate3d(${it.x.toFixed(1)}px, ${it.y.toFixed(1)}px, 0)`;
      it.root.style.textAlign = ALIGN[pl.slot];
      it.root.style.opacity = String((off ? 0.55 : 0.55 + 0.45 * depth).toFixed(2));
      it.root.style.setProperty('--c', nodeStyle(d).color);
      it.root.classList.toggle('gw', !!d.is_gateway);
      it.root.classList.toggle('active', id === selectedId || id === hoveredId);
    }
  }

  return { update, count: () => items.size };
}
