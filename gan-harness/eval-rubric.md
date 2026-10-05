# Evaluation rubric (design mode)

Score each criterion 0-10, multiply by its weight, sum. Pass at 7.5.
Judge from the screenshots and measurements supplied with each round, and
from the code in `ui/`. Be a harsh critic: 5 is "works but generic", 7 is
"good", 9 is "would be shown off".

## Design Quality (0.35)
- Does the scene read as a coherent, intentional visual design (palette,
  lighting, depth, background, link treatment)?
- Is the hierarchy clear at a glance: gateway vs this Mac vs other devices,
  online vs offline vs new?
- Are labels legible at the default camera distance and not fighting the nodes?

## Originality (0.30)
- Does it look like more than the library's defaults with new colours?
- Is there a distinctive idea suited to "a living map of my network"?

## Craft (0.25)
- No overlapping nodes (measured: minimum centre distance vs sum of radii).
- Labels on every device, no clipped or overlapping text in the screenshots.
- Motion: frame rate, no jump on SSE updates, graph settles without snapping
  (measured where possible, otherwise judged from code: forces, alpha decay,
  velocity decay, cooldown, drag handlers).
- UI chrome (legend, status bar, details panel) is consistent with the scene.

## Functionality (0.10)
- Click opens details; legend matches colours; tests pass; no console errors
  from the page; only 127.0.0.1 requests; CSP unchanged.

## Automatic fails (cap total at 5.0)
- Any remote asset, CSP change, or HTML built from device strings.
- A device with no visible label.
- Tests failing.
