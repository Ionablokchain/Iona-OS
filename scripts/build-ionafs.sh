#!/usr/bin/env bash
# IONA OS disk image builder
#
# Build modes:
#   dev (default):    continue on non-critical inject failures, warn only
#   strict:           STRICT_BUILD=1 — abort on any inject failure
#
# Usage: ./scripts/build-ionafs.sh
#        STRICT_BUILD=1 ./scripts/build-ionafs.sh   # strict/release mode
#
set -euo pipefail
# Auto-enable strict mode if IONA_BUILD_MODE=prod
if [ "${IONA_BUILD_MODE:-dev}" = "prod" ]; then
    export STRICT_BUILD=1
    log "STRICT_BUILD enabled (IONA_BUILD_MODE=prod)"
fi
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"
OUTPUT="$DIST/iona-disk.img"
log "IONAFS image 256MB..."
dd if=/dev/zero of="$OUTPUT" bs=1M count=256 status=none
python3 -c "
import sys,struct
with open(sys.argv[1],'r+b') as f:
    f.seek(0); f.write(b'IONA'+struct.pack('<I',0)+b'\x00'*504)
    print('  superblock OK')
" "$OUTPUT"
# inst: install optional config file — failure is logged but not fatal
inst() {
    local t; t=$(mktemp); printf '%s' "$2" > "$t"
    python3 "$SDIR/install-to-ionafs.py" --disk "$OUTPUT" --file "$t" --path "$1" 2>/dev/null ||         log "  WARNING: optional file $1 inject failed (non-fatal)"
    rm -f "$t"
}

# inst_required: install required file — failure aborts in STRICT_BUILD mode
inst_required() {
    local path="$1"; local content="$2"
    local t; t=$(mktemp); printf '%s' "$content" > "$t"
    if ! python3 "$SDIR/install-to-ionafs.py" --disk "$OUTPUT" --file "$t" --path "$path" 2>&1; then
        log "  ERROR: required file $path inject failed"
        [ "${STRICT_BUILD:-0}" = "1" ] && die "Strict mode: required file $path missing"
    fi
    rm -f "$t"
}
inst_required /etc/iona-node.json '{"validator_id":0,"gossip_port":9000,"admin_port":7777,"peers":[],"first_boot":true}'
inst /etc/resolv.conf 'nameserver 8.8.8.8'
inst /etc/iona-release 'IONA OS v0.6.0'
inst /etc/hostname 'iona-os'
inst /etc/motd 'Welcome to IONA OS\n'
install_bin() {
    local name="$1"; shift
    local path=""
    for cand in "$@"; do
        if [ -f "$ROOT_DIR/$cand" ]; then path="$ROOT_DIR/$cand"; break; fi
    done
    [ -n "$path" ] || { log "  SKIP /bin/$name (not built)"; return 0; }
    if python3 "$SDIR/install-to-ionafs.py" --disk "$OUTPUT" --file "$path" --path "/bin/$name" 2>&1; then
        log "  installed /bin/$name ($(du -sh "$path" | cut -f1))"
    else
        log "  WARNING: /bin/$name inject failed"
        [ "${STRICT_BUILD:-0}" = "1" ] && die "Strict mode: /bin/$name required"
    fi
}
# Useful runtime dirs/markers
inst /var/iona-node/.keep ''
inst /var/crash/.keep ''
inst /var/log/.keep ''
inst /etc/network.conf 'dhcp=1'
install_bin iona-node   target/x86_64-unknown-none/release/iona-node   userspace/iona-node/target/x86_64-unknown-none/release/iona-node   userspace/iona-node/target/release/iona-node
install_bin iona-shell   target/x86_64-unknown-none/release/iona-shell   userspace/iona-shell/target/x86_64-unknown-none/release/iona-shell   userspace/iona-shell/target/release/iona-shell
install_bin iona-utils   target/x86_64-unknown-none/release/iona-utils   userspace/iona-utils/target/x86_64-unknown-none/release/iona-utils   userspace/iona-utils/target/release/iona-utils
# ── Inject iona-node ELF ─────────────────────────────────────────────
IONA_NODE_ELF=""
for candidate in \
    "userspace/iona-node/target/x86_64-unknown-none/release/iona-node" \
    "userspace/iona-node/target/x86_64-unknown-iona/release/iona-node" \  # legacy target — can be removed
    "userspace/iona-node/target/release/iona-node" \
    "target/x86_64-unknown-none/release/iona-node"; do
    [ -f "$ROOT_DIR/$candidate" ] && { IONA_NODE_ELF="$ROOT_DIR/$candidate"; break; }
done

if [ -z "$IONA_NODE_ELF" ]; then
    log "iona-node ELF not found — building now..."
    if [ -f "$ROOT_DIR/userspace/iona-node/Cargo.toml" ]; then
        # Try bare-metal target first (correct for IONA OS userspace)
        BUILT_ELF=""
        if (cd "$ROOT_DIR/userspace/iona-node" &&             cargo build --target x86_64-unknown-none --release 2>&1 | tail -5); then
            BUILT_ELF="$ROOT_DIR/userspace/iona-node/target/x86_64-unknown-none/release/iona-node"
        elif (cd "$ROOT_DIR/userspace/iona-node" &&               cargo build --release 2>&1 | tail -5); then
            BUILT_ELF="$ROOT_DIR/userspace/iona-node/target/release/iona-node"
            log "  NOTICE: built with host target — binary may not run on bare metal"
        fi

        # Validate the built binary is actually an ELF
        if [ -n "$BUILT_ELF" ] && [ -f "$BUILT_ELF" ]; then
            ELF_MAGIC=$(xxd -l 4 "$BUILT_ELF" 2>/dev/null | awk '{print $2$3}' || echo "")
            if [ "$ELF_MAGIC" = "7f454c46" ]; then
                IONA_NODE_ELF="$BUILT_ELF"
                log "  iona-node ELF validated: $(du -sh "$BUILT_ELF" | cut -f1)"
            else
                log "  WARNING: built binary is not a valid ELF — ignoring"
                [ "${STRICT_BUILD:-0}" = "1" ] && die "Strict mode: invalid ELF"
            fi
        else
            log "  WARNING: iona-node build failed — /bin/iona-node will be absent"
            [ "${STRICT_BUILD:-0}" = "1" ] && die "Strict mode: iona-node required"
        fi
    fi
fi

# Sanity check: warn if stale x86_64-unknown-none and host binaries both exist
STALE_HOST="$ROOT_DIR/userspace/iona-node/target/release/iona-node"
CORRECT_ELF="$ROOT_DIR/userspace/iona-node/target/x86_64-unknown-none/release/iona-node"
if [ -f "$STALE_HOST" ] && [ -f "$CORRECT_ELF" ] && [ "$IONA_NODE_ELF" = "$STALE_HOST" ]; then
    log "  WARNING: using host binary but x86_64-unknown-none binary also exists"
    log "  Prefer: $CORRECT_ELF"
fi

if [ -n "$IONA_NODE_ELF" ] && [ -f "$IONA_NODE_ELF" ]; then
    if python3 "$SDIR/install-to-ionafs.py"         --disk "$OUTPUT" --file "$IONA_NODE_ELF" --path "/bin/iona-node" 2>&1; then
        ok "  /bin/iona-node injected ($(du -sh "$IONA_NODE_ELF" | cut -f1))"
    else
        log "  WARNING: iona-node inject failed — check install-to-ionafs.py"
        [ "${STRICT_BUILD:-0}" = "1" ] && die "Strict mode: iona-node inject required"
    fi
else
    log "  WARNING: /bin/iona-node absent — userspace won't start"
    log "  Fix: cargo build -p iona-node && ./scripts/build-ionafs.sh"
fi

ok "IONAFS: $OUTPUT"

if [ -f "$DIST/release-manifest.json" ]; then
    python3 "$SDIR/install-to-ionafs.py" --disk "$OUTPUT" --file "$DIST/release-manifest.json" --path "/etc/iona-artifacts.json" 2>/dev/null || true
    log "  installed /etc/iona-artifacts.json"
fi
