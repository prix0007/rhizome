# Round 1 evaluation: Rhizome 3D network map

**Evaluation mode:** `code-only` plus the supplied real-GPU screenshots and measurements. I did not run a live browser.

Tests pass: `node --test ui/tests/` gives 45 of 45, and `cargo test` gives 183 plus 8 passed. The round diff (HEAD~1 to HEAD) touches no file under `src/`. `src/web/headers.rs` is untouched and the CSP is unchanged. The new fonts are vendored same-origin and recorded in `VERSIONS` with a licence.

## 1. Scores (rubric weights)

| Criterion | Score | Weight | Weighted |
|---|---|---|---|
| Design Quality | 6.5 | 0.35 | 2.28 |
| Originality | 6.5 | 0.30 | 1.95 |
| Craft | 6.5 | 0.25 | 1.63 |
| Functionality | 8.5 | 0.10 | 0.85 |
| **Total** | | | **6.7 / 10** |

**Verdict: FAIL against 7.5.** No automatic fail applies. There are no remote assets, the CSP is unchanged, labels use `textContent` (the tooltip HTML is escaped by `labelFor`), 11 of 11 nodes have labels, and the tests are green.

- **Design Quality (6.5).** The change from flat spheres on black is large: teal-dark ground, amber gateway, glowing halos, curved links, Plex Mono HUD. In the screenshot the nodes read as flat concentric discs, like a target or bullseye, not lit 3D bodies. ACES tone mapping plus the shell, nucleus and two additive halos washes the mint "online" nodes toward pale grey-green. They sit too close to the cyan "this Mac" nodes for an at-a-glance distinction. Labels are about 11.5 px and 9.5 px (the IP sub-line is dim), which is very small at the default distance. Several labels sit on their own link line (QDI, GIGA-BYTE).
- **Originality (6.5).** The bioluminescent look, range rings, spores and gateway ripple are more than library defaults. The "rhizome" idea itself is barely used: the graph is a star of single curved links with no mycelial character. The range rings are static CSS, not tied to the gateway.
- **Craft (6.5).**
  - Collision is satisfied (minimum centre distance 82.4 against about 21 collision distance), but only by link and charge spacing; the collide force never engages.
  - Labels have real placement logic, but they ignore links and halos, trail their nodes during camera motion, and the two Mac interfaces carry an identical primary label.
  - The framing logic (below) is stale-prone and untested.
  - No frame rate was measured.
- **Functionality (8.5).** Click opens the panel and recentres the camera. Legend counts match the categories. Tests pass, there is one request origin, and there are no page console errors. The fallback path and SSE behaviour are untested.

## 2. Screenshot observations: confirmed or dismissed

- **Panel open for 192.168.0.114 without a click: dismissed as a bug.** The panel is only opened by `onNodeClick`, and hover only sets `hoveredId`. The node sits at dead centre of the viewport (784, 378), which is what `selectNode` does (`cameraPosition(..., n, 1100)`). So the capture tool clicked it.
- **Graph cut off top-left: dismissed as evidence of bad framing.** The camera was recentred on the selected node, which also explains the off-centre gateway. Initial framing is still suspect from code (see defect 2).
- **QDI label overlapping its halo: confirmed.** Label placement uses only the body radius, `nodeRadius * focal / -zv`, so the 2.35x halo is ignored. The label also lands on the link line, because slot 2 ("right") points toward the gateway.
- **Identical "Example-MacBook-Pro" labels: confirmed.** They are distinguished only by the dim IP sub-line.
- **GIGA-BYTE label crosses its own link.** The link runs through the "GIGA-BYTE" text.
- **Edge ellipses.** The halos at screen edges are stretched ellipses (the 192.168.0.21 halo, for example), which suggests a wide FOV.

## 3. Hard-constraint review

- **Remote URLs, CSP, textContent:** compliant. Labels are DOM `span`s set with `textContent`. The panel uses `textContent`, and `clean()` strips control and bidi characters. Identity is preserved, since `upsertDevice` uses `Object.assign` and `toGraphData` reuses the node objects. The legend categories are intact.
- **`probeKit` fragility: moderate.** It injects a throwaway `__probe` node and polls up to 180 frames for a mesh with `SphereGeometry` and an `emissive` material.
  - It depends on bundle internals: the default node mesh type, the material class having `.emissive`, and `Object.getPrototypeOf(Mesh)` being Object3D. A bundle upgrade could change any of these.
  - The constants `ADDITIVE = 2` and `ACES_FILMIC = 4` are hardcoded three.js enum values, which silently break if three renumbers.
  - The reject path is sound: it falls back to library spheres, and `scheduleRender(true)` replaces the probe graph. But that path is never exercised or tested. The error message also gets overwritten by the next `showStatus`.
  - In a background tab, the 180-frame budget only counts visible frames, so this is fine.
  - Suggestion: add a `VERSIONS` note and a test or manual check that fails loudly if the probe finds nothing. Optionally use `renderer.constructor` and `graph.scene().constructor` for sanity checks.
- **`window.__rhizome` should not ship.** It exposes the live `nodeMap`, a reheat function and `screenOf`. The risk is low (same origin, local), but it is test scaffolding. Gate it behind `location.search.includes('debug')`, or remove it.

## 4. Ranked changes for round 2

### Defects (bugs and constraint risks)

1. **Labels trail their nodes during camera motion.** In `labels.js` the label position eases toward the target rect at a fixed 0.22 per frame, so labels lag the node by roughly 4 frames on orbit, drag and fly-to. This is the "floaty and sticky" feel the user asked to remove, and it is frame-rate dependent.
   - Fix: ease only the slot change, not the absolute position. Store an offset relative to the node anchor, ease the offset on slot switch (using `dt`), and always add the live projected anchor.
   - Better: labels stay glued to nodes and only the slot transition animates.
2. **Camera framing fires too early and only once.** `setTimeout(fitOnce, 3500)` runs while the layout is still cooling. With `alphaDecay` 0.014 the layout takes about 7 s or about 440 ticks, so `fitted` is set at 3.5 s and never refits as the graph expands.
   - Fix: refit after `onEngineStop` or when alpha drops below about 0.05. Refit again (eased) when the node count changes, if the user has not touched the camera.
   - Make framing include halo radius and the label margin.
3. **SSE gateway update snaps the pinned gateway.** `upsertDevice` calls `applyPin(existing, true)` on every gateway event and resets `fx/fy/fz` to 0. This fights `easeGatewayHome` and jumps a gateway the user is dragging.
   - Fix: only pin when the node is first created or the gateway status changes.
4. **Label vs link and halo collisions.**
   - Add the node-to-gateway projected segment as an obstacle cost in `placeLabels`.
   - Use the halo radius (about 1.55x to 2.35x body, scaled by glow) for the label disc.
   - Penalise "sticky" `prev` slots when a different slot has strictly lower cost (add real hysteresis, for example a 20% margin), so QDI and GIGA-BYTE leave their link-covered slots.
5. **Per-frame cost at 100+ devices.** `labels.update` allocates `frameItems`, a `meta` Map, `discs`, slot objects, a sorted copy and a Vector3 per node (`graph2ScreenCoords`) every frame. It also calls `getBoundingClientRect` every frame, forcing layout after the previous frame's style writes.
   - `placeLabels` is O(n^2) with a worst case of about 10 slots x n placed x n discs. That is roughly 1.2M tests per frame at n = 250.
   - Fixes: cache the container rect via `ResizeObserver`. Project with the camera matrix directly and reuse arrays. Spatially bucket the discs and placed rects. Skip re-placement when nothing moved beyond about 1 px, and re-place at 20 to 30 Hz while the camera is moving.
   - `separate()` allocates `nodes.map(...)` each tick and is O(n^2) x 2 iterations. Cache the radii, use a grid, and consider `softness` about 0.4 so the collide force eases instead of removing 70% of an overlap per tick.
6. **Layout will not scale.** `linkDistance` 74 with `charge` -75 and `distanceMax` 340 puts all leaves on one shell. A shell of radius 74 fits only about 49 packed leaves of collision radius 10.5. At 100+ devices the collide force will fight link strength 0.45.
   - Fix: scale `linkDistance` by about cbrt(n), or add per-device jitter. Test with a synthetic 150-node set.
7. **Identical labels for the two Mac interfaces.** Distinguish the two Mac nodes in `labelParts` (for example append the interface or a "(2)" marker, or promote the IP into the primary line when a duplicate primary exists).
8. **Never exercised, so risk remains:** the `probeKit` reject path, an SSE `device` event during settle, and the `damped` Proxy behaviour with `d3-force-3d` (initialize arguments pass through, which looks right). Add a test or manual check for each.
9. **Debug hook.** Remove or gate `window.__rhizome`.

### Design improvements

1. **Make nodes read as lit 3D spheres, not bullseyes.**
   - Cut the halo opacity and radius (the two halos are about 0.17 and 0.07 of glow, 1.55x and 2.35x radius) and stop depth-writing flat discs.
   - Give the shell a Fresnel-style rim, or more directional light, so there is a visible terminator.
   - Reduce ACES exposure, or desaturate less.
2. **Separate "online" and "this Mac" more strongly.** Mint `#6ee7a8` against cyan `#3ddcff` collapses after tone mapping. Make this Mac a distinct shape (a ring or a larger double halo) or a clearly bluer or whiter hue. Keep the legend matching.
3. **Raise label legibility.** Increase to about 13 px for the name and 11 px for the IP, raise the sub-line contrast from `--dim`, and add a size boost for the selected or hovered node. Consider fading distant labels by depth more strongly.
4. **Lower the camera FOV to about 45 to 55** to reduce the edge ellipses.
5. **Use the rhizome idea.** Branching or mycelial links, link thickness or brightness driven by `last_seen` recency, and a gateway-anchored ring system.
   - The range rings are currently static CSS centred on the screen, not the gateway. After any camera move they mislead (the screenshot shows them centred on the selected node). Draw them in 3D around the gateway, or remove them.
6. **Links crossing other nodes' halos.** The Tuya link passes near the Espressif node. Vary `linkCurveRotation` or the curvature to avoid crossing.

## 5. What I could not judge

- **Frame rate and motion feel.** The tab was in the background (no `requestAnimationFrame`), so I could not judge frame rate, drag feel, or whether the lower `velocityDecay` of 0.26 oscillates or settles.
- **SSE update behaviour.** I could not see what a `structureChanged` event does to a settled layout. The alpha cap (`reheatCap` 0.28) only damps link and charge, and `graphData()` still resets alpha to 1. The `settled` flag could also flip early if the probe-only graph cools before the first snapshot arrives.
- **Initial framing.** The screenshot was taken after a click had recentred the camera, so I could not see the real post-load framing. The code suggests it is stale-prone, but I did not confirm it.
- **Responsive behaviour.** No 375 px or 768 px view was supplied.
- **Keyboard navigation.** I could not check keyboard focus or navigation, or the hover transitions, from the evidence given.
- **Per-frame label cost.** I did not measure it, so it is judged from code only.
- **The `probeKit` reject path.** It was not run.
