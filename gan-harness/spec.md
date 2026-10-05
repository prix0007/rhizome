# Design brief: Rhizome 3D network map

Rhizome shows every device on the local network as a live 3D graph: the
gateway at the centre, every other device linked to it. The frontend is a
no-build page in `ui/` (`index.html`, `app.js`, `graph-model.js`, `style.css`)
using the vendored `ui/vendor/3d-force-graph.min.js` (v1.80.1, bundles three.js
and d3-force-3d). The Rust agent serves it at http://127.0.0.1:7878 and pushes
device updates over SSE. In debug builds `ui/` is read from disk, so a browser
reload picks up edits without rebuilding.

## What the user asked for

1. **Better graphics.** The current view is flat-shaded spheres on black with
   near-invisible links. Make it look deliberate and distinctive.
2. **Smoother, less sticky motion.** Dragging, settling and updates should feel
   fluid: no abrupt stops, no jumps when an SSE update arrives.
3. **Collision.** Nodes must never overlap, including their labels as far as
   practical.
4. **A label on every device**, always visible without hovering: hostname if
   known, else vendor, else IP.

## Hard constraints

- No CDN or remote assets. Anything new (fonts, textures, extra libraries) is
  vendored into `ui/vendor/` with its licence and recorded in
  `ui/vendor/VERSIONS`. The page must load only from 127.0.0.1.
- CSP is `script-src 'self'`: no eval, no inline scripts, no blob workers.
  Inline styles are allowed. Do not change the CSP.
- Device strings (hostname, vendor, SSDP fields) come from untrusted LAN hosts.
  Render labels as canvas/sprite text or `textContent`. Never build HTML from
  them.
- Keep node object identity across updates so positions survive (see
  `reconcile` in `graph-model.js`).
- Keep the existing meaning of the colours' categories: gateway, this Mac,
  online, new, offline must stay distinguishable, and the legend must match.
- Keep the details panel on click and the status bar.
- `node --test ui/tests/` and `cargo test` stay green. Pure logic added to
  `graph-model.js` gets tests.
- Three.js is only available through the bundle. Check what the bundle exposes
  before assuming `THREE` is a global; if it is not, vendoring a matching
  three.js module is acceptable under the constraints above.

## Out of scope

Backend changes, new API fields, new features (search, filters, rescan).
