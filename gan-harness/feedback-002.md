# Round 2 evaluation: Rhizome 3D network map

**Evaluation mode:** `code-only` plus the supplied screenshots and measurements. I did not run a live browser. `node --test ui/tests/` passes 58 of 58. I did not run `cargo`, as instructed.

## 1. Scores

| Criterion | Score | Weight | Weighted |
|---|---|---|---|
| Design Quality | 7.0 | 0.35 | 2.45 |
| Originality | 6.5 | 0.30 | 1.95 |
| Craft | 7.0 | 0.25 | 1.75 |
| Functionality | 8.5 | 0.10 | 0.85 |
| **Total** | | | **7.0 / 10** |

**Verdict: FAIL against 7.5 (up from 6.7 in round 1).** No automatic fail applies:
- Every one of the 11 devices has a label.
- All requests go to 127.0.0.1.
- The CSP is untouched; `src/web/headers.rs` is not in the round 2 diff.
- Labels and the panel use `textContent`.
- JS tests are green. Rust tests were not run, so that part is unverified.

**Design Quality (7.0).**
- The scene now reads as intentional. The gateway is a large amber sphere. This Mac is blue with a camera-facing ring, a shape cue as well as a hue, and it is clearly separated from the green devices.
- Labels at 13 px and 11 px are legible, and none cross their own link in the screenshot.
- The 3D rings around the gateway foreshorten and look good.
- Held back by weak, pale links that carry little visual weight.
- Nodes are lit but still shade fairly flat.
- The gateway halo bands up close, which the Generator admits.
- The `.173` label sits tight against its own ring.
- The link from 192.168.0.21 runs straight through the `.173` node.

**Originality (6.5).**
- The bioluminescent look, 3D range rings, camera-facing ring and spores are more than library defaults.
- The topology and link treatment are still a star of curves, with no rhizome or mycelial idea in them.
- The ring radii (1.0x, 1.6x, 2.2x link distance) mean nothing, since leaves sit at 0.8x to 1.2x.
- The logo is a well-made but generic hub-and-spokes app tile.

**Craft (7.0).**
- In the screenshot, labels do not overlap each other or any node. Minimum node distance is 50.1 against about 21 collision distance, and the graph is framed and centred on the gateway.
- Label tracking is fixed (see section 2).
- Pulled down by the fit-timer bug, the label-placement performance defect, and the admitted 150-device failure (448 overlapping label pairs, never re-measured).
- Frame rate was never measured.

**Functionality (8.5).**
- Click opens a grouped panel.
- The save path handles a 404, a non-OK response, a network failure, a bad JSON body, and double-submit.
- The panel does not overwrite a form the user is typing in.
- Accessibility is real: landmarks, a hidden keyboard device list, the closed panel is `visibility:hidden` so its form is not focusable, the debug hook is gated behind `?debug`, and the `nokit` fallback path is now exercisable.
- Deductions: the `role="status"` on the status bar will chatter for screen readers on every scan, and `og:image` uses a relative URL.

**Logo.**
- At 192 px and in the 1200x630 card it is clean and on-palette. The dark tile carries contrast on light and dark pages.
- At 16 px it degrades to an amber dot with faint lines. The device dots (radius 2.2 to 4.4 in a 64-unit viewBox) go sub-pixel, and the 3 px stroke is under 1 px.
- The 32 px favicon is just readable.
- Add a simplified favicon variant: a larger gateway, thicker roots, 3 dots.

## 2. Round 1 items: resolved or not

**Resolved**
- **Labels trailing their nodes.** The label is now drawn at the live projected anchor, and only the slot offset eases, using `dt`. This is genuinely fixed.
- **Gateway re-pin snap.** Re-pinning only happens on a role change.
- **Identical Mac labels.** Duplicates get a ` .172` tag. It repeats the IP shown on the sub-line, which is redundant but not wrong.
- **Debug hook.** `window.__rhizome` exists only with `?debug`.
- **This Mac vs online separation.** Solved by the blue colour plus the ring.
- **Label legibility and FOV.** Labels are 13 px and 11 px, FOV is 50, and the edge ellipses are gone.
- **Range rings.** They are now real 3D rings centred on the gateway.
- **`probeKit` upgrade risk.** The hard-coded enums are documented in `VERSIONS`, and the fallback is exercisable with `?debug&nokit`.

**Partly resolved**
- **Initial framing.** The screenshot looks good, but the 2.5 s fit never fires (defect 1).
- **Label vs halo and link.** The own-link cost and halo factor were added. But `HALO_FACTOR` is 1.5 while halos reach 2.0x, and other-link avoidance switches off above 40 items.
- **Per-frame cost.** Allocation and DOM reads are reduced, but steady-state placement is 10x too costly (defect 2) and there is no bucketing.
- **Layout scale.** The `cbrt(n/10)` scaling and per-link length jitter are sound, but nothing was measured at 100 or more devices.

**Not resolved**
- Links crossing other nodes' halos (the 21-to-gateway link crosses `.173`).
- Rhizome-like link character.
- Halo banding.
- Dense-graph label legibility.
- Frame rate and SSE-update behaviour, still unmeasured.

## 3. Remaining changes, most valuable first

### Defects

1. **The 2.5 s fit never runs.**
   - In `app.js`, `.then()` calls `scheduleFit(2500)` and then `scheduleFit(6000)`. `scheduleFit` begins with `clearTimeout(fitTimer)`, so the first timer is cancelled.
   - Until about 6 s (or engine stop, whichever comes first) the camera sits at the hard-coded `(0,120,290)`, then flies in over 1.2 s.
   - Fix: keep a separate timer per call, or have one function that fits at 2.5 s and re-arms at 6 s.
2. **Steady-state label placement costs 10x what it should.**
   - In `label-layout.js` the loop does `if (c === 0 && !hasPrev) break;`. Any label with a previous slot scores all 10 slots every placement.
   - Fix: score `prev` first. If its cost is 0, accept it immediately and `continue`.
   - Also add a spatial grid (about 100 px cells) for discs and placed rects. `cost()` is O(items) per slot, so 10 x n x 3n per placement.
3. **Labels at 150 devices are unreadable and were not re-measured.** Re-measure with `?debug` and `inject()` on 60, 100 and 150 nodes. Targets: placement under about 2 ms, and fewer than 20 overlapping label pairs at 100 nodes. Past 60, consider showing labels only for the gateway, this Mac, the hovered or selected node, and nodes nearest the camera.
4. **Labels can sit under the HUD and the panel.** `bounds` is only a margin: `y:56`, `x:6`. Add exclusion rectangles for the legend and brand (top-left) and the open panel (right, 320 px).
5. **Halo obstacle radius is too small.** `HALO_FACTOR` is 1.5 and the outer halo shell reaches 2.02x. Use about 2.0x for glowing nodes.
6. **Per-frame allocations remain.**
   - `[...nodeMap.values()].find(...)` in `frame()` and `[...items.values()].some(...)` in `labels.update` run every frame.
   - Cache the gateway reference and a "needs first placement" counter.
7. **Node count and GPU cost.** Each node has about 7 meshes of 36x24 spheres, with 5 additive shells. The shell count is fixed at build time, so crossing 60 devices does not reduce already-built nodes. The `shells` setting should apply on rebuild, or use a shared low-poly sphere (16x12) for the shells.
8. **Camera auto-fit latches off permanently.** `userMoved` is never reset, so after one drag or scroll, new devices can land off-screen. Offer a "recenter" key or button, or re-fit when a new node projects outside the viewport.
9. **Smaller items.**
   - The `role="status"` on the status bar is chatty.
   - TrackballControls' window keydown listener sees typing in the name field. This is mostly harmless but worth a quick check.
   - The 404 message "cannot store names yet" also covers a vanished device.
   - Make `og:image` URLs absolute, or drop them.

### Design improvements

1. **Give the links a rhizome character, the biggest originality lever.**
   - Thicker links near the gateway that taper toward the leaf. Vary width or brightness by RTT and recency.
   - Add branching or secondary filaments (a short side-root with a spore at the end) or a faint ground-glow along the link.
   - At minimum, make the links visibly brighter than they are now, with a flowing pulse tied to `rtt_ms` once the backend sends it.
2. **Make the ring distances mean something.** Place leaves on or between rings by latency or hop, or by kind, or drop to one ring.
3. **Soften halo banding.** Use a smoother radial falloff, for example a single sprite with a baked radial gradient, or 8 or more shells at lower opacity with jitter.
4. **Avoid link-through-node crossings.** In `linkCurveRotation`, pick the curve rotation that keeps the control point clear of other nodes' screen discs, or bias the layout (a weak tangential force) so leaves do not line up behind each other.
5. **Make the lit spheres read as 3D.** Raise the key light or specular and add a rim term. The sphere shading is subtle at the current exposure.
6. **Logo.** Add the simplified favicon variant. Put the hub-and-spokes in a more rhizome-like shape (an asymmetric root system) so it stops looking like a stock network icon.

## 4. What I could not judge

- Frame rate, drag feel, orbit smoothness, and the visible camera fly at 6 s. The tab was in the background.
- Behaviour on an SSE update to a settled layout, and `settled` flipping early.
- Label cost at 100 or more devices. I judged the cost from code only; the 150-node overlap figure is the Generator's own.
- The panel with live data. The new fields are absent, so the grouped sections, the long-value wrapping, and the 320 px panel height on short windows were not seen.
- The save round trip (the backend is not ready).
- Responsive layouts at 375 and 768 px.
- The `?debug&nokit` fallback rendering.
- Keyboard focus order and the screen-reader experience.
- `cargo test`, which I was told not to run. I only know the Rust side compiled well enough for the supplied 127.0.0.1 evidence.

## 5. Is a third round worth it?

I would fix defects 1 to 6 directly now. They are small and mechanical: one timer line, an early exit, HUD and panel exclusion zones, the halo factor, two cached references.

The remaining gap to 7.5 is mostly Originality (6.5) and Design (7.0), and neither is fixable mechanically. Do one short third round, limited to visuals, with design improvements 1 to 4 above as the brief. Score it with the dense-graph measurements from defect 3 included.

If that round does not move links and layout meaning off "generic star", the loop is unlikely to clear 7.5 on its own.
