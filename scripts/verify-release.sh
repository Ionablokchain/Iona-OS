#!/usr/bin/env bash
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"
ROOT="${ROOT_DIR:-$(cd "$SDIR/.." && pwd)}"
DIST="${DIST:-$ROOT/dist}"
[ -f "$DIST/iona-os-kernel.elf" ] || die "missing kernel elf"
[ -f "$DIST/iona-disk.img" ] || die "missing iona-disk.img"
[ -f "$DIST/release-manifest.json" ] || die "missing release manifest"
[ -f "$DIST/iona-os-version.json" ] || die "missing version manifest"
python3 - <<PY
import json,sys
for path in [sys.argv[1], sys.argv[2]]:
    with open(path,'r',encoding='utf-8') as f:
        json.load(f)
print('json manifests parse OK')
PY "$DIST/release-manifest.json" "$DIST/iona-os-version.json"
ok "Release artifacts verified"
