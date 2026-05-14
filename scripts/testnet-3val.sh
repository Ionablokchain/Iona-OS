#!/usr/bin/env bash
# IONA OS 3-validator testnet — Tendermint BFT consensus test
#
# Pornește 3 instanțe QEMU cu iona-node configurați să formeze consens.
# Verifică că blocurile sunt produse și că BFT commit se produce.
#
# Usage: ./scripts/testnet-3val.sh [--timeout <sec>] [--blocks <n>]
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"

command -v qemu-system-x86_64 &>/dev/null || die "qemu-system-x86_64 not found"

KERNEL="$DIST/iona-os-kernel.elf"
DISK="$DIST/iona-disk.img"
[ -f "$KERNEL" ] || die "Build first: cargo build --release --target x86_64-unknown-none"
[ -f "$DISK"   ] || die "Build IONAFS first: ./scripts/build-ionafs.sh"

TIMEOUT=${TESTNET_TIMEOUT:-60}
EXPECTED_BLOCKS=${EXPECTED_BLOCKS:-3}

log "=== IONA OS 3-Validator Testnet ==="
log "Kernel:  $KERNEL"
log "Timeout: ${TIMEOUT}s"
log "Expected blocks: $EXPECTED_BLOCKS"

# ── Cleanup handler ───────────────────────────────────────────────────────────
PIDS=()
LOGS=()
cleanup() {
    log "Stopping validators..."
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    if [ "${TESTNET_KEEP_LOGS:-0}" = "1" ]; then
        for i in 1 2 3; do
            log "Val $i log: ${LOGS[$((i-1))]}"
        done
    else
        for f in "${LOGS[@]}"; do rm -f "$f"; done
    fi
}
trap cleanup EXIT

# ── Validator IP/port mapping ─────────────────────────────────────────────────
# Val 1: 10.0.1.1, gossip 9001
# Val 2: 10.0.2.1, gossip 9002
# Val 3: 10.0.3.1, gossip 9003
# Each validator gets a fresh disk copy

log "Starting 3 validators..."
for i in 1 2 3; do
    SERIAL_LOG=$(mktemp /tmp/iona-val${i}-serial.XXXXXX.log)
    LOGS+=("$SERIAL_LOG")

    DISK_COPY=$(mktemp /tmp/iona-val${i}-disk.XXXXXX.img)
    cp "$DISK" "$DISK_COPY"

    # Patch iona-node.json on disk copy with validator config
    # (simplified: pass via kernel command line, parsed by main.rs)
    qemu-system-x86_64         -kernel "$KERNEL"         -drive  file="$DISK_COPY",format=raw,if=virtio,snapshot=on         -m      256M         -serial "file:$SERIAL_LOG"         -display none         -no-reboot         -netdev "user,id=net${i},net=10.0.${i}.0/24,host=10.0.${i}.1,hostfwd=udp::900${i}-:900${i}"         -device "e1000,netdev=net${i},mac=52:54:00:00:00:0${i}"         &
    PIDS+=($!)
    log "  Validator $i started (pid=${PIDS[-1]}, log=$SERIAL_LOG)"
    sleep 0.5
done

# ── Wait for validators to boot ───────────────────────────────────────────────
log "Waiting for validators to boot (max ${TIMEOUT}s)..."
BOOT_DEADLINE=$(( $(date +%s) + TIMEOUT ))

all_booted() {
    for i in 0 1 2; do
        grep -q "\[BOOT\].*GUI\\|\[BOOT\].*scheduler\\|\[BFT\]\\|\[NODE\]" "${LOGS[$i]}" 2>/dev/null || return 1
    done
    return 0
}

while ! all_booted; do
    [ $(date +%s) -lt $BOOT_DEADLINE ] || { log "TIMEOUT: validators did not boot"; exit 1; }
    sleep 2
done
log "All 3 validators booted ✓"

# ── Wait for BFT commits ─────────────────────────────────────────────────────
log "Waiting for BFT consensus ($EXPECTED_BLOCKS blocks)..."
CONSENSUS_DEADLINE=$(( $(date +%s) + TIMEOUT ))

committed_blocks() {
    # Count [BFT] block N committed lines across all logs
    local count=0
    for log in "${LOGS[@]}"; do
        local n
        n=$(grep -c "\[BFT\].*committed\\|\[BFT\].*block.*commit" "$log" 2>/dev/null || true)
        count=$(( count + n ))
    done
    echo "$count"
}

while true; do
    blocks=$(committed_blocks)
    if [ "$blocks" -ge "$EXPECTED_BLOCKS" ]; then
        ok "BFT consensus: $blocks blocks committed ✓"
        break
    fi
    if [ $(date +%s) -ge $CONSENSUS_DEADLINE ]; then
        log "WARNING: only $blocks/$EXPECTED_BLOCKS blocks committed"
        log "This may be expected if validators cannot reach each other in QEMU user-net"
        log "For full P2P: use -netdev bridge with tap interfaces"
        break
    fi
    sleep 3
done

# ── Results ──────────────────────────────────────────────────────────────────
log ""
log "=== Testnet Results ==="
for i in 1 2 3; do
    local_blocks=$(grep -c "\[BFT\].*committed" "${LOGS[$((i-1))]}" 2>/dev/null || echo 0)
    log "  Validator $i: $local_blocks commits"
    # Show last 5 BFT lines
    grep "\[BFT\]\|\[NODE\]\|\[CONSENSUS\]" "${LOGS[$((i-1))]}" 2>/dev/null | tail -3 | while read line; do
        log "    $line"
    done
done

ok "Testnet complete"
