#!/usr/bin/env bash
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"
mkdir -p "$ROOT_DIR/backup"
case "${1:-build}" in
  --verify)
    [ -f "$DIST/iona-os-kernel.elf" ] || die "Missing dist/iona-os-kernel.elf"
    [ -f "$DIST/iona-disk.img" ] || die "Missing dist/iona-disk.img"
    [ -f "$DIST/release-manifest.json" ] || die "Missing dist/release-manifest.json"
    [ -f "$DIST/iona-os-version.json" ] || die "Missing dist/iona-os-version.json"
    ok "Artifacts verified"
    ;;
  --check)
    [ -f "$DIST/iona-os-version.json" ] && cat "$DIST/iona-os-version.json" || echo '{"version":"unknown"}'
    ;;
  --rollback)
    LAST=$(ls -t "$ROOT_DIR"/backup/iona-os-*.zip 2>/dev/null | head -1)
    [ -n "$LAST" ] || die "No backup found"
    log "Rolling back dist payload from $LAST..."
    "$SDIR/installer.sh" --apply "$LAST"
    [ -f "$DIST/iona-os-version.json" ] && fail "NOTE: dist payload rolled back; installed systems need installer.sh --live <dev> to update on-disk copies"
    ok "Rollback complete"
    ;;
  *)
    TS=$(date +%Y%m%d-%H%M%S)
    BACKUP="$ROOT_DIR/backup/iona-os-$TS.zip"
    [ -d "$DIST" ] && zip -q -r "$BACKUP" "$DIST/" 2>/dev/null || true
    log "Rebuilding full artifacts..."
    "$ROOT_DIR/build-all.sh"
    ok "Update complete (backup: $BACKUP)"
    ;;
esac
