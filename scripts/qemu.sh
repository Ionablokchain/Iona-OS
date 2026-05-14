#!/usr/bin/env bash
# Lansează IONA OS Kernel în QEMU
#
# Prerequisite:
#   cargo build --target x86_64-unknown-none
#   (build.rs generează disk images în target/x86_64-unknown-none/debug/build/)
#
# Usage:
#   ./scripts/qemu.sh            # BIOS boot (default)
#   ./scripts/qemu.sh --uefi     # UEFI boot
#   ./scripts/qemu.sh --gdb      # cu GDB server la :1234

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$SCRIPT_DIR/.."
TARGET="x86_64-unknown-none"
PROFILE="${PROFILE:-debug}"
BUILD_DIR="$ROOT/target/$TARGET/$PROFILE"

# Găsim disk image-ul generat de build.rs
BIOS_IMG=$(find "$BUILD_DIR/build" -name "iona-bios.img" 2>/dev/null | head -1)
UEFI_IMG=$(find "$BUILD_DIR/build" -name "iona-uefi.img" 2>/dev/null | head -1)
OVMF="/usr/share/ovmf/OVMF.fd"

# Flags QEMU comune
QEMU_COMMON=(
    -machine q35
    -cpu qemu64
    -m 256M
    -smp 2
    -serial stdio          # COM1 → terminal (serial_println! output)
    -display none          # headless pentru CI/test
    -no-reboot
    -no-shutdown
)

# Dacă vrem framebuffer vizual, adaugă:
# QEMU_COMMON+=(-display gtk -vga virtio)

QEMU_GDB=()
if [[ "${1:-}" == "--gdb" ]]; then
    QEMU_GDB=(-s -S)  # -s: GDB pe :1234, -S: oprire la start
    echo "GDB server pe localhost:1234"
    echo "Conectare: gdb -ex 'target remote :1234' target/$TARGET/$PROFILE/iona-os-kernel"
fi

if [[ "${1:-}" == "--uefi" ]]; then
    if [[ ! -f "$UEFI_IMG" ]]; then
        echo "✗ UEFI image negăsit. Rulează: cargo build"
        exit 1
    fi
    if [[ ! -f "$OVMF" ]]; then
        echo "✗ OVMF firmware negăsit. Instalează: sudo apt install ovmf"
        exit 1
    fi
    echo "Boot UEFI: $UEFI_IMG"
    exec qemu-system-x86_64 "${QEMU_COMMON[@]}" "${QEMU_GDB[@]}" \
        -bios "$OVMF" \
        -drive "format=raw,file=$UEFI_IMG"
else
    if [[ ! -f "$BIOS_IMG" ]]; then
        echo "✗ BIOS image negăsit. Rulează: cargo build"
        echo "  (build.rs generează imaginea în target/)"
        exit 1
    fi
    echo "Boot BIOS: $BIOS_IMG"
    exec qemu-system-x86_64 "${QEMU_COMMON[@]}" "${QEMU_GDB[@]}" \
        -drive "format=raw,file=$BIOS_IMG"
fi
