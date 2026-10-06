#!/bin/sh
# Dev-time only: refresh data/oui.csv from the IEEE registry.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
URL1="https://standards-oui.ieee.org/oui/oui.csv"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
curl -fsSL --retry 2 --max-time 120 -A "Mozilla/5.0 rhizomon-dev" -o "$TMP" "$URL1"
head -1 "$TMP" | grep -q 'Registry' || { echo "unexpected content" >&2; exit 1; }
cp "$TMP" "$ROOT/data/oui.csv"
SUM="$(shasum -a 256 "$ROOT/data/oui.csv" | cut -d' ' -f1)"
printf 'source %s\nfetched %s\nsha256 %s\n' "$URL1" "$(date -u +%Y-%m-%d)" "$SUM" > "$ROOT/data/OUI_SOURCE"
