# Round 3 evaluation (final scored round): Rhizome 3D network map

**Evaluation mode:** `code-only` plus the supplied real-GPU screenshots. I did not run a live browser. `node --test ui/tests/` passes 70 of 70. I did not run cargo, as instructed.

## 1. Scores

| Criterion | Score | Weight | Weighted |
|---|---|---|---|
| Design Quality | 7.0 | 0.35 | 2.45 |
| Originality | 7.5 | 0.30 | 2.25 |
| Craft | 7.0 | 0.25 | 1.75 |
| Functionality | 8.5 | 0.10 | 0.85 |
| **Total** | | | **7.3 / 10** |

**Verdict: FAIL against 7.5 (6.7 in round 1, 7.0 in round 2, 7.3 now).** No automatic fail applies. Every device has a label and the vendored fonts are the only assets. All requests go to 127.0.0.1, `index.html` and the CSS reference no remote URL, and the CSP is untouched. The Rust tests were not run, so that part is unverified.

**Design Quality (7.0).**
- The scene is coherent and now unmistakably this product: an amber gateway at the centre of a root system, a blue ringed "this Mac", legible 13 px labels, the offline node greyed out.
- Held back at the focal point. Sigmastar sits inside the gateway glow. The "TP-LINK SYSTEMS" label sits on the ring line and its IP is crossed by a root. A root passes over the offline node. The two Mac rings touch. Side filaments end in mid-air beside other nodes.
- The graph fills only about 37% of the viewport width (x 477 to 1054 of 1561), against about 65% in round 2. I cannot tell whether that is a real framing regression or a mid-tween capture. The camera was not recorded.
- The offline node's label (192.168.0.148) is faint at 0.5 opacity.

**Originality (7.5).**
- Tapered root tubes with side filaments and spores, pulses flowing outward, bows steered away from other nodes, and the one-hop ring are a genuine idea suited to "rhizome". They are not a library default.
- The new logo is an asymmetric root system with a separate 16 px mark.
- Not higher because the topology is still a star, and the ring does not tie to any data. Leaves sit at 0.8x to 1.2x of it.

**Craft (7.0).**
- Real improvements: a keyed fit timer, the previous-slot early accept plus a 100 px grid, HUD and panel exclusion zones, and measured dense-graph numbers (0.82 ms placement at 150 devices).
- Remaining problems:
  - The label placer's link obstacles are straight lines, but the roots are curved with side filaments.
  - Collision ignores the ring.
  - The root code allocates every frame (see below).
  - A wall-clock cooldown can freeze an unsettled layout.
  - Frame rate is unmeasured.
  - Dense screenshots were not reviewed after the roots were thinned.

**Functionality (8.5).** Unchanged from round 2: save-path failure handling, a keyboard device list, a recenter button and R key (typing in the form is isolated with `stopPropagation`), and `?debug` gating. `role="status"` is gone from the status bar. It is still on `#edit-msg`, which is correct for a form message.

## 2. Round 2 items

**Resolved**
- **2.5 s fit never ran.** Timers are now keyed (`early`, `late`, `later`, `settle`, `update`, `recenter`).
- **Placement 10x too costly.** The previous slot is accepted at cost 0, with a spatial grid on top.
- **Labels under the HUD and panel.** Exclusion rectangles now cover both.
- **Halo factor.** `HALO_FACTOR` is 2.0.
- **Per-frame gateway lookup.** The reference is cached.
- **Shell cost.** The shell geometry is shared, with the count applied on rebuild by quality tier.
- **Recenter.** The button and R key exist.
- **Dense-graph label legibility.** 6 overlapping pairs at 150 devices, with the label budget active.
- **`og:image`.** Dropped.
- **Link character.** The rhizome idea is now delivered.
- **Logo.** Redrawn, with a simplified `favicon.svg` and a 16 px PNG.

**Partly resolved**
- **Link crossing halos and nodes.** `chooseRoll` helps, but a root still passes over the offline node.
- **Halo banding.** Admitted, still present close up.

**Not resolved**
- Frame rate and SSE-update feel remain unmeasured.

## 3. The half-grown capture

**It is a capture artefact, with one real edge case.**

Node growth is time-based. `grow` is computed from `now - rec.born`, where `now` is the rAF timestamp and `born` is `performance.now()`, both on the same clock. A user returning to a backgrounded tab gets full-size nodes on the first frame back. The tangled roots in your first capture are the seed layout (random positions at `seedDistance` 66) before the simulation has run, plus nodes at age 0.

The real edge case is the wall-clock cooldown. The bundle's `tickFrame` stops the engine when `new Date - startTickTime > cooldownTime`. The app sets `cooldownTime(60000)`. If the page loads in a background tab and rAF is paused (for example, opened from a link in another window), then on first foreground more than 60 s later the engine stops on its first frame. The layout stays at its seed positions and roots stay tangled until some structural SSE event calls `graphData` and resets the countdown. Fix 1 below removes this.

## 4. What is still wrong, ranked

### Small, fix directly

1. **Layout can freeze unsettled after a long background load.**
   - File and function: `ui/app.js`, graph construction.
   - Change `.cooldownTime(60000)` to `.cooldownTime(Infinity)`. `d3AlphaMin(0.002)` already ends the simulation, as the bundle's tick checks `alpha() < d3AlphaMin`.
2. **Collision ignores the this-Mac ring.**
   - File and function: `ui/graph-model.js`, `collisionRadius` (and the `separate` tests in `ui/tests/graph-model.test.js`).
   - Use `d.is_self ? nodeRadius(d) * 2.15 + 4 : nodeRadius(d) + COLLIDE_PADDING`. The ring is drawn at 2.05x the body radius, so two Macs at the old minimum (24) have touching rings (24.6). The new minimum is about 33.8.
   - Update any test that asserts the old Mac value.
3. **Label placement treats roots as straight lines.**
   - Files and functions: `ui/labels.js` `update` (where `segments` is built) and `ui/scene.js` `createRoots`.
   - Add `roots.points(id, ts, out)`, returning world points via `toWorld(gwPos, leaf, rec.roll, rootCurve(t, SHAPES[rec.shape]))`.
   - In `labels.update`, project t = 0.25, 0.5, 0.75 and the leaf, and push consecutive segments `{id, x1, y1, x2, y2}` instead of the single gateway-to-node segment.
   - This also fixes the gateway label's IP being crossed (own-link cost applies per leaf's polyline).
   - For the gateway item, also pass the full set of root segments with `checkOthers` forced on.
4. **Framing may be too loose.** In `ui/app.js` `scheduleFit`, replace `graph.zoomToFit(1200, 100)` with an explicit sphere fit:
   - Compute `R = max over nodes (hypot(n - gw) + 14)`.
   - Use `half = min(fov/2, atan(tan(fov/2) * W/H))` and `dist = R / sin(half) * 1.1`.
   - Take `dir` as the normalised vector from `controls().target` to the camera.
   - Call `graph.cameraPosition({x: gw.x + dir.x * dist, y: gw.y + dir.y * dist, z: gw.z + dir.z * dist}, gw, 1200)`.
   - This removes the dependence on the library's bounding box. First confirm with `?debug` whether the graph really spans under 55% of the viewport after 11 s. If it already fits, leave this alone.
5. **Per-frame allocation in the root update.**
   - Files and functions: `ui/roots.js` `basis`, `rootMatrix`, `toWorld`, `clearance`, and `ui/scene.js` `createRoots.update`.
   - Replace `new Array(16)` in `toWorld` and `clearance` with module-level scratch arrays.
   - Hoist the per-leaf `{x,y,z}` objects into the record.
   - Replace `obstacles.filter(...)` (6 per frame) with a reused array that skips index `i + 1`.
   - Avoid `Math.hypot(...u)` spread and the `.map` in `basis`.
   - Call `Date.now()` once per frame, not per leaf and per pulse.
   - Measured placement is fine, but this is about 1000 short-lived allocations per frame at 150 devices.
6. **Offline label is too faint.** `ui/labels.js` `update`: raise the offline opacity from 0.5 to 0.7. In `ui/style.css`, give `.label.off .label-sub` the lighter `#9db8b1`.
7. **Dense-graph check.** Inject 100 devices with `?debug` and `__rhizome.inject`, take one screenshot, and look at root thinning above 30 devices. This is not a code change unless it looks wrong.

### Needs design work

1. **Line-of-sight overlaps at the gateway** (Sigmastar in the glow, a root over the offline node).
   - Almost certainly projection overlap: the 3D separation is at least 25 against a glow radius of about 18, so the collision force is not failing.
   - Options: flatten the layout slightly toward the horizontal plane so a pitched camera sees fewer stacked nodes, a weak y-force, or screen-space nudging of a leaf's roll.
   - Verify with `__rhizome.screenOf` first.
2. **Side filaments ending in mid-air near other nodes.** Shorten or drop a branch whose spore would land within a node's glow (needs a per-root branch scale in the geometry or shader).
3. **Halo banding up close.** Move to a baked radial-gradient sprite or a smoother shader falloff.
4. **The ring still encodes nothing.** Leaves sit 0.8x to 1.2x of it. Either place leaves by latency or hop relative to it, or fade it out of the default view.
5. **Frame rate and per-frame cost at 100 or more devices.** Measure it in a foreground window. Until then the roots update (every leaf, every frame) and the node animation are the likely hot spots.

## 5. Not judged

- Frame rate, drag and orbit feel, and whether the camera is mid-tween in the supplied screenshot.
- SSE-update behaviour on a settled layout.
- The grouped panel with real new-field data, and the save round trip (the backend is not ready).
- Responsive layouts at 375 and 768 px.
- The `?debug&nokit` fallback rendering.
- Any dense-graph screenshot after the root thinning above 30 devices.
- `cargo test`.
