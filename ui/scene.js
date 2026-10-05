// The 3D look: bioluminescent cells on soil-dark space, joined by glowing filaments.
//
// three.js is not a global here (the vendored 3d-force-graph bundle keeps it
// private), and vendoring a second copy would load two instances of three.
// Instead the few constructors needed are recovered from objects the bundle
// builds itself (see probeKit). Nothing in this file touches the DOM.
import { nodeRadius, nodeStyle } from './graph-model.js';

const ADDITIVE = 2; // THREE.AdditiveBlending
const ACES_FILMIC = 4; // THREE.ACESFilmicToneMapping

/**
 * Feed the graph one throwaway node, wait for the bundle to build its default
 * mesh, and read the constructors off it. Resolves with the kit, or rejects
 * if the bundle never built one.
 */
export function probeKit(graph) {
  graph.graphData({ nodes: [{ id: '__probe' }], links: [] });
  return new Promise((resolve, reject) => {
    let frames = 0;
    const look = () => {
      let found = null;
      graph.scene().traverse((o) => {
        if (!found && o.isMesh && o.geometry && o.geometry.type === 'SphereGeometry' && o.material && o.material.emissive) found = o;
      });
      if (found) {
        const Mesh = found.constructor;
        resolve({
          Mesh,
          Object3D: Object.getPrototypeOf(Mesh),
          Sphere: found.geometry.constructor,
          Lambert: found.material.constructor,
          Color: found.material.color.constructor,
        });
      } else if (++frames > 180) {
        reject(new Error('could not obtain three.js constructors from the bundle'));
      } else {
        requestAnimationFrame(look);
      }
    };
    requestAnimationFrame(look);
  });
}

/** Tone mapping and lighting: a cool fill, a warm key from the camera side, a teal rim from behind. */
export function setupRenderer(graph) {
  const renderer = graph.renderer();
  renderer.toneMapping = ACES_FILMIC;
  renderer.toneMappingExposure = 0.95;
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
  graph.scene().traverse((o) => {
    if (o.isAmbientLight) {
      o.color.set('#7fa6b8');
      o.intensity = 0.9;
    } else if (o.isDirectionalLight && !o.userData.rhizomeRim) {
      o.color.set('#fff0d8');
      o.intensity = 1.5;
      const rim = o.clone();
      rim.userData.rhizomeRim = true;
      rim.color.set('#35e0c0');
      rim.intensity = 1.6;
      rim.position.set(-o.position.x - 60, -o.position.y - 40, -o.position.z - 120);
      (o.parent || graph.scene()).add(rim);
    }
  });
}

function mat(kit, color, opts) {
  return new kit.Lambert({ color, transparent: true, ...opts });
}

/** Builds node objects and animates them from node data every frame. */
export function createNodes(kit) {
  const unit = new kit.Sphere(1, 32, 22);
  const records = new Map();
  const tmp = new kit.Color();

  function dispose(rec) {
    for (const m of rec.materials) m.dispose();
  }

  /** `nodeThreeObject` accessor. The returned group is what the engine positions and drags. */
  function build(d) {
    const old = records.get(d.id);
    if (old) dispose(old);
    const style = nodeStyle(d);
    const g = new kit.Object3D();
    const body = new kit.Object3D();
    g.add(body);

    const shell = new kit.Mesh(unit, mat(kit, style.color, { opacity: 0.6, depthWrite: false }));
    const nucleus = new kit.Mesh(unit, mat(kit, '#000000', { emissive: style.color, opacity: 1, depthWrite: false }));
    const halos = [1, 2].map(() => {
      const h = new kit.Mesh(unit, mat(kit, '#000000', { emissive: style.color, opacity: 0.1, depthWrite: false, blending: ADDITIVE }));
      h.raycast = () => {}; // glow is not a click or drag target
      return h;
    });
    const pulse = new kit.Mesh(unit, mat(kit, '#000000', { emissive: style.color, opacity: 0, depthWrite: false, blending: ADDITIVE }));
    pulse.raycast = () => {};
    shell.renderOrder = 2;
    nucleus.renderOrder = 1;
    halos.forEach((h) => { h.renderOrder = 0; });
    pulse.renderOrder = 0;
    body.add(pulse, ...halos, nucleus, shell);

    const rec = {
      g, body, shell, nucleus, halos, pulse,
      materials: [shell.material, nucleus.material, pulse.material, ...halos.map((h) => h.material)],
      cur: new kit.Color(style.color),
      op: style.opacity,
      glow: style.glow,
      boost: 0,
      born: performance.now(),
      phase: Math.random() * Math.PI * 2,
    };
    records.set(d.id, rec);
    g.__rhizomeId = d.id;
    return g;
  }

  /**
   * Ease every node toward its current style and breathe. `nodes` is the id ->
   * device map; a status change therefore fades instead of snapping.
   */
  function animate(now, dt, nodes, { selectedId = null, hoveredId = null, calm = false } = {}) {
    const k = 1 - Math.exp(-dt * 5);
    for (const [id, rec] of records) {
      const d = nodes.get(id);
      if (!d) {
        dispose(rec);
        records.delete(id);
        continue;
      }
      const style = nodeStyle(d);
      const R = nodeRadius(d);
      tmp.set(style.color);
      rec.cur.lerp(tmp, k);
      rec.op += (style.opacity - rec.op) * k;
      rec.glow += (style.glow - rec.glow) * k;
      const wantBoost = (id === selectedId ? 1 : 0) + (id === hoveredId ? 0.6 : 0);
      rec.boost += (wantBoost - rec.boost) * k;

      const t = (now - rec.born) / 1000;
      const age = Math.min(1, (now - rec.born) / 900);
      const grow = age >= 1 ? 1 : 1 - Math.pow(1 - age, 3) * Math.cos(age * 7); // eased, slight overshoot
      const breathe = calm ? 0 : Math.sin(now / 1000 * 1.3 + rec.phase);

      rec.body.position.y = calm ? 0 : Math.sin(now / 1000 * 0.7 + rec.phase * 1.7) * 0.9;

      const s = R * grow * (1 + 0.025 * breathe);
      rec.shell.scale.setScalar(s);
      rec.shell.material.color.copy(rec.cur);
      rec.shell.material.emissive.copy(rec.cur).multiplyScalar(0.28);
      rec.shell.material.opacity = 0.62 * rec.op;

      rec.nucleus.scale.setScalar(s * 0.46);
      rec.nucleus.material.emissive.copy(rec.cur).multiplyScalar(0.8);
      rec.nucleus.material.opacity = rec.op;

      const gl = rec.glow * (1 + rec.boost * 0.9) * (1 + 0.18 * breathe);
      rec.halos[0].scale.setScalar(s * 1.55);
      rec.halos[0].material.emissive.copy(rec.cur);
      rec.halos[0].material.opacity = 0.17 * gl;
      rec.halos[1].scale.setScalar(s * 2.35);
      rec.halos[1].material.emissive.copy(rec.cur);
      rec.halos[1].material.opacity = 0.07 * gl;

      // A slow ripple leaves the gateway; a new device pings faster.
      const period = d.is_gateway ? 3.6 : d.is_new && d.online !== false ? 1.9 : 0;
      if (period && !calm) {
        const p = ((t + rec.phase) % period) / period;
        rec.pulse.scale.setScalar(s * (1.3 + p * (d.is_gateway ? 4.2 : 3.4)));
        rec.pulse.material.emissive.copy(rec.cur);
        rec.pulse.material.opacity = Math.pow(1 - p, 2.2) * 0.2;
        rec.pulse.visible = true;
      } else {
        rec.pulse.visible = false;
      }
    }
  }

  return { build, animate, records };
}

/** Link materials, cached by colour/opacity so thousands of frames allocate nothing. */
export function createLinkMaterials(kit) {
  const cache = new Map();
  return (color, strength) => {
    const key = color + '|' + strength.toFixed(2);
    let m = cache.get(key);
    if (!m) {
      m = mat(kit, '#000000', { emissive: color, opacity: strength, depthWrite: false, blending: ADDITIVE });
      cache.set(key, m);
    }
    return m;
  };
}

/** Faint motes drifting through the volume: parallax and depth when the camera moves. */
export function createSpores(kit, scene, count = 240) {
  const geo = new kit.Sphere(1, 6, 4);
  const mats = [0, 1, 2].map((i) => mat(kit, '#000000', { emissive: ['#9fe8d0', '#b9d9ff', '#e8f6c8'][i], opacity: 0.4, depthWrite: false, blending: ADDITIVE }));
  const group = new kit.Object3D();
  let seed = 1234567;
  const rand = () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);
  const motes = [];
  for (let i = 0; i < count; i++) {
    const m = new kit.Mesh(geo, mats[i % 3]);
    const u = rand() * 2 - 1;
    const a = rand() * Math.PI * 2;
    const rr = 140 + Math.pow(rand(), 0.7) * 520;
    const s = Math.sqrt(1 - u * u);
    m.position.set(rr * s * Math.cos(a), rr * u, rr * s * Math.sin(a));
    m.scale.setScalar(0.35 + rand() * 0.6);
    m.raycast = () => {};
    group.add(m);
    motes.push({ m, ox: m.position.x, oy: m.position.y, oz: m.position.z, p: rand() * 6.28, sp: 0.1 + rand() * 0.25 });
  }
  scene.add(group);
  return {
    animate(now, calm) {
      mats.forEach((m, i) => { m.opacity = calm ? 0.4 : 0.28 + 0.22 * (0.5 + 0.5 * Math.sin(now / 1000 * (0.4 + i * 0.23) + i * 2)); });
      if (calm) return;
      const t = now / 1000;
      for (const o of motes) {
        o.m.position.x = o.ox + Math.sin(t * o.sp + o.p) * 9;
        o.m.position.y = o.oy + Math.cos(t * o.sp * 0.8 + o.p) * 9;
        o.m.position.z = o.oz + Math.sin(t * o.sp * 0.6 + o.p * 2) * 9;
      }
    },
  };
}
