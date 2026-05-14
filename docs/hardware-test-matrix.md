# IONA OS Hardware Test Matrix

## Target hardware (strategic selection)

### VM / CI reference
| Config | Command |
|--------|---------|
| QEMU virtio | `qemu-system-x86_64 -kernel dist/iona-os-kernel.elf -drive file=dist/iona-disk.img,if=virtio -m 512M -serial stdio` |
| QEMU e1000  | `qemu-system-x86_64 -kernel dist/iona-os-kernel.elf -device e1000 -m 512M` |
| QEMU UEFI   | `qemu-system-x86_64 -bios /usr/share/ovmf/OVMF.fd -drive format=raw,file=dist/iona-uefi.img -m 512M` |

### Desktop (x86_64 — recommended)
- Intel Core i5/i7 8th gen+ cu UEFI Secure Boot dezactivat
- 8GB+ RAM
- NVMe SSD (prioritar) sau SATA SSD
- Intel e1000/I219 NIC sau RTL8169
- HDMI/DP output — orice rezoluție ≥1280×720

### Laptop (test secundar)
- ThinkPad X1 Carbon gen 6-9 (bun driver support)
- Dell XPS 13/15 sau Latitude
- Evită: Apple Silicon (ARM), Chromebook

## Boot checklist per hardware

```
[ ] POST → UEFI screen vizibil
[ ] USB recunoscut ca EFI bootable device
[ ] Kernel loads (serial: "IONA OS Kernel v0.6.0")
[ ] Framebuffer init (ecran ≠ blank)
[ ] Memory detected (serial: "[BOOT] MM")
[ ] PCI scan (NVMe / AHCI / NIC)
[ ] IONAFS mounted (serial: "[IONAFS] mounted")
[ ] Network up (serial: "[NET] dhcp")
[ ] GUI renders (topbar + sidebar + taskbar)
[ ] Terminal responds to keyboard
[ ] Node starts (serial: "[BFT] height=1")
[ ] Installer runs (for install test)
[ ] Reboot into installed system
```

## Known issues per platform
| Platform | Issue | Workaround |
|----------|-------|------------|
| QEMU <7.0 | virtio-net missing | use `-device e1000` |
| AMD GPUs | framebuffer may not init | add `-vga std` |
| Secure Boot ON | refuses unsigned kernel | disable in BIOS |
| AHCI mode off | NVMe only shown | enable AHCI in BIOS |
