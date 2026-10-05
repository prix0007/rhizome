#!/bin/sh
# Dev-time only: vendor 3d-force-graph into ui/vendor. Never run at runtime.
set -eu
PIN="${1:-1.80.1}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
cd "$TMP"
npm pack "3d-force-graph@$PIN" >/dev/null
tar xzf 3d-force-graph-*.tgz
mkdir -p "$ROOT/ui/vendor"
cp package/dist/3d-force-graph.min.js "$ROOT/ui/vendor/3d-force-graph.min.js"
cp package/LICENSE "$ROOT/ui/vendor/LICENSE-3d-force-graph"
SUM="$(shasum -a 256 "$ROOT/ui/vendor/3d-force-graph.min.js" | cut -d' ' -f1)"
printf '3d-force-graph %s\nsha256 %s  3d-force-graph.min.js\nfetched %s\n' "$PIN" "$SUM" "$(date -u +%Y-%m-%d)" > "$ROOT/ui/vendor/VERSIONS"
