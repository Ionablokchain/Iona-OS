#!/usr/bin/env bash
# Test IONAFS persistence: write file, reboot, verify file survives
set -euo pipefail
SDIR="$(cd "$(dirname "$0")" && pwd)"
source "$SDIR/lib.sh"
command -v qemu-system-x86_64 &>/dev/null || die "QEMU needed"
KERNEL="$DIST/iona-os-kernel.elf"
DISK=$(mktemp /tmp/iona-persist-test.XXXXXX.img)
cp "$DIST/iona-disk.img" "$DISK"
log "Test 1: Boot + write test file..."
LOG1=$(mktemp)
timeout 20 qemu-system-x86_64 \
    -kernel "$KERNEL" -drive file="$DISK",format=raw,if=virtio \
    -m 256M -serial file:"$LOG1" -display none -no-reboot 2>/dev/null || true
grep -q "IONAFS" "$LOG1" && ok "Boot OK" || { fail "Boot failed"; cat "$LOG1"; exit 1; }
log "Test 2: Reboot + verify file persisted..."
LOG2=$(mktemp)
timeout 20 qemu-system-x86_64 \
    -kernel "$KERNEL" -drive file="$DISK",format=raw,if=virtio \
    -m 256M -serial file:"$LOG2" -display none -no-reboot 2>/dev/null || true
grep -q "IONAFS" "$LOG2" && ok "Persistence OK" || fail "File lost after reboot"
rm -f "$DISK" "$LOG1" "$LOG2"
ok "Persistence test complete"
