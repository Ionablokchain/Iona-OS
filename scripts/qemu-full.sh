#!/usr/bin/env bash
# QEMU cu kernel + virtio-blk + virtio-net + serial output
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="$ROOT/dist"

BIOS="$DIST/iona-bios.img"
DISK="$DIST/iona-disk.img"

[ -f "$BIOS" ] || { echo "Run ./build-all.sh first"; exit 1; }
[ -f "$DISK" ] || dd if=/dev/zero of="$DISK" bs=1M count=256 status=none

GDB_FLAGS=()
if [[ "${1:-}" == "--gdb" ]]; then
    GDB_FLAGS=(-s -S)
    echo "GDB server on :1234"
fi

exec qemu-system-x86_64 \
    -machine q35 \
    -cpu qemu64 \
    -m 512M \
    -smp 2 \
    -drive "format=raw,file=$BIOS" \
    -drive "file=$DISK,format=raw,if=virtio,id=disk0" \
    -netdev "user,id=net0,hostfwd=tcp::7777-:7777,hostfwd=tcp::9001-:9001" \
    -device "virtio-net-pci,netdev=net0" \
    -serial stdio \
    -display none \
    -no-reboot \
    "${GDB_FLAGS[@]}"
