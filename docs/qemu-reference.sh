#!/usr/bin/env bash
# IONA OS QEMU reference configurations
KERNEL="${1:-dist/iona-os-kernel.elf}"
DISK="${2:-dist/iona-disk.img}"
MODE="${3:-virtio}"

case "$MODE" in
virtio)
    # Primary: virtio-net + virtio-blk (fastest, used in CI)
    qemu-system-x86_64 \
        -kernel "$KERNEL" \
        -drive file="$DISK",format=raw,if=virtio \
        -netdev user,id=net0,hostfwd=tcp::7777-:7777,hostfwd=tcp::9000-:9000 \
        -device virtio-net-pci,netdev=net0 \
        -m 512M -serial stdio -display gtk -vga std
    ;;
e1000)
    # e1000 NIC — closer to real hardware
    qemu-system-x86_64 \
        -kernel "$KERNEL" \
        -drive file="$DISK",format=raw,if=ide \
        -netdev user,id=net0,hostfwd=tcp::7778-:7777 \
        -device e1000,netdev=net0 \
        -m 512M -serial stdio -display gtk -vga std
    ;;
uefi)
    # UEFI boot — requires OVMF
    OVMF="/usr/share/ovmf/OVMF.fd"
    [ -f "$OVMF" ] || OVMF="/usr/share/OVMF/OVMF_CODE.fd"
    qemu-system-x86_64 \
        -bios "$OVMF" \
        -drive format=raw,file="dist/iona-uefi.img" \
        -drive file="$DISK",format=raw,if=virtio \
        -m 512M -serial stdio -display gtk
    ;;
debug)
    # Debug: GDB stub on :1234, verbose serial
    qemu-system-x86_64 \
        -kernel "$KERNEL" \
        -drive file="$DISK",format=raw,if=virtio \
        -m 512M -serial stdio -display none \
        -s -S
    # Connect: gdb dist/iona-os-kernel.elf -ex "target remote :1234"
    ;;
*)
    echo "Usage: $0 [kernel] [disk] [virtio|e1000|uefi|debug]"
    ;;
esac
