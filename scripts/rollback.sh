#!/usr/bin/env bash
# IONA OS rollback — revert to previous known-good version
#
# Usage: ./scripts/rollback.sh [--to <version-tag>]
#
# Rollback mechanism:
#   1. During boot: if /var/boot-fail-count >= 3 → auto-rollback
#   2. Manual: operator runs this script
#   3. Update failure: supervisor triggers rollback automatically

set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

ROLLBACK_DIR="${ROLLBACK_DIR:-$ROOT_DIR/dist/rollback}"
TARGET="${1:-}"

# ── Boot failure detection ────────────────────────────────────────────────────
check_boot_failures() {
    local fail_count=0
    if [ -f "$DIST/boot-fail-count" ]; then
        fail_count=$(cat "$DIST/boot-fail-count")
    fi
    echo "$fail_count"
}

increment_boot_fail() {
    local count=$(check_boot_failures)
    echo $((count + 1)) > "$DIST/boot-fail-count"
}

reset_boot_fail() {
    echo "0" > "$DIST/boot-fail-count"
}

# ── List available rollback targets ─────────────────────────────────────────
list_rollback_targets() {
    log "Available rollback targets:"
    if [ -d "$ROLLBACK_DIR" ]; then
        ls -1t "$ROLLBACK_DIR/" | while read -r ver; do
            local ts
            ts=$(stat -c %Y "$ROLLBACK_DIR/$ver" 2>/dev/null || echo 0)
            log "  $ver ($(date -d @$ts +%Y-%m-%d 2>/dev/null || echo unknown))"
        done
    else
        log "  No rollback targets available"
        log "  Run: ./scripts/save-rollback.sh to save current version"
    fi
}

# ── Save current version as rollback target ──────────────────────────────────
save_current() {
    local version
    version=$(cat "$DIST/iona-os-version.json" 2>/dev/null | \
              grep -o '"version":"[^"]*"' | grep -o '[0-9][^"]*' || echo "unknown")
    local tag="${version}-$(date +%Y%m%d%H%M%S)"

    mkdir -p "$ROLLBACK_DIR/$tag"
    cp "$DIST/iona-os-kernel.elf" "$ROLLBACK_DIR/$tag/" 2>/dev/null || true
    cp "$DIST/iona-disk.img"      "$ROLLBACK_DIR/$tag/" 2>/dev/null || true
    cp "$DIST/release-manifest.json" "$ROLLBACK_DIR/$tag/" 2>/dev/null || true

    log "Saved rollback target: $tag"
    echo "$tag"
}

# ── Perform rollback ─────────────────────────────────────────────────────────
do_rollback() {
    local target="$1"
    local rollback_path="$ROLLBACK_DIR/$target"

    [ -d "$rollback_path" ] || die "Rollback target not found: $target"

    log "Rolling back to: $target"
    log "Backup current state..."

    # Backup current before rollback
    cp "$DIST/iona-os-kernel.elf" "$DIST/iona-os-kernel.elf.pre-rollback" 2>/dev/null || true
    cp "$DIST/iona-disk.img"      "$DIST/iona-disk.img.pre-rollback" 2>/dev/null || true

    # Apply rollback
    cp "$rollback_path/iona-os-kernel.elf" "$DIST/"
    cp "$rollback_path/iona-disk.img"      "$DIST/"
    cp "$rollback_path/release-manifest.json" "$DIST/" 2>/dev/null || true

    reset_boot_fail
    ok "Rollback complete — reboot to apply: qemu.sh or reboot"
}

# ── Main ─────────────────────────────────────────────────────────────────────
case "${1:-list}" in
    list)    list_rollback_targets ;;
    save)    save_current ;;
    to)      do_rollback "${2:-}" ;;
    auto)
        # Auto-rollback if too many boot failures
        fails=$(check_boot_failures)
        log "Boot fail count: $fails"
        if [ "$fails" -ge 3 ]; then
            log "AUTO-ROLLBACK triggered (${fails} consecutive boot failures)"
            LATEST=$(ls -1t "$ROLLBACK_DIR/" 2>/dev/null | head -1)
            [ -n "$LATEST" ] && do_rollback "$LATEST" || log "No rollback target available"
        fi
        ;;
    *)
        # Treat as rollback target name
        do_rollback "$1"
        ;;
esac
