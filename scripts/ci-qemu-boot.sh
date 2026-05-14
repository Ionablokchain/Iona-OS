#!/usr/bin/env bash
# CI: Boot IONA OS in QEMU, verify kernel + GUI startup within 30s
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"
command -v qemu-system-x86_64 &>/dev/null || die "qemu-system-x86_64 not found"

KERNEL="$DIST/iona-os-kernel.elf"
DISK="$DIST/iona-disk.img"
[ -f "$KERNEL" ] || die "Build first: ./build-all.sh"

SERIAL_LOG=$(mktemp /tmp/iona-serial.XXXXXX.log)
log "Booting IONA OS in QEMU (30s timeout)..."
timeout 30 qemu-system-x86_64 \
    -kernel "$KERNEL" \
    -drive file="$DISK",format=raw,if=virtio \
    -m 512M \
    -serial file:"$SERIAL_LOG" \
    -display none \
    -no-reboot \
    2>/dev/null || true

# Verify boot markers in serial output
PASSED=0; FAILED=0
check() {
    local desc="$1" pattern="$2"
    if grep -q "$pattern" "$SERIAL_LOG" 2>/dev/null; then
        ok "$desc"
        PASSED=$((PASSED+1))
    else
        fail "$desc (pattern: $pattern)"
        FAILED=$((FAILED+1))
    fi
}

check "Kernel booted"           "IONA OS"
check "Memory initialized"      "\[BOOT\].*MM"
check "PCI scan"                "\[PCI\]"
check "IONAFS mounted"          "\[IONAFS\]"
check "Network initialized"     "\[NET\]"
check "GUI initialized"         "\[GUI\]"
check "Consensus engine"        "\[BFT\]"

log "Results: $PASSED passed, $FAILED failed"
rm -f "$SERIAL_LOG"
[ $FAILED -eq 0 ] || exit 1
ok "CI boot test passed"
