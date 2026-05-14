# IONA OS — Runbook complet

## Build rapid
```bash
./build-all.sh
# Output: dist/iona-uefi.img  dist/iona-disk.img  dist/iona-os-kernel.elf
```

## Test în QEMU
```bash
./docs/qemu-reference.sh                  # virtio default
./docs/qemu-reference.sh dist/iona-os-kernel.elf dist/iona-disk.img e1000
./docs/qemu-reference.sh _ _ uefi         # UEFI boot
./docs/qemu-reference.sh _ _ debug        # GDB debug
```

## Instalare pe stick USB
```bash
sudo ./scripts/installer.sh /dev/sdX
# Reboot → UEFI boot menu → IONA OS
```

## Update sistem
```bash
./scripts/update.sh             # rebuild + backup + apply
./scripts/update.sh --check     # versiune curentă
./scripts/update.sh --rollback  # revenire la ultimul backup
```

## Testnet 3 validatori
```bash
./scripts/testnet-3val.sh
```

## CI manual
```bash
./scripts/ci-qemu-boot.sh
```

## Recovery mode
1. La boot GRUB: selectează "IONA OS Recovery"
2. SAU: `touch /etc/recovery-mode` în IONAFS și rebootează
3. Recovery shell pe serial (115200 baud)

## Snapshot / Rollback IONAFS
```
syscall 500 (fs_snapshot) → salvează tot IONAFS într-un fișier arhivă
syscall 501 (fs_restore)  → restaurează din arhivă
```

## Kernel panic
- Ecranul arată BSOD cu mesajul de eroare
- Serial: backtrace complet
- Auto-reboot după 30s dacă /etc/reboot-on-panic există

## Structura dist/
```
dist/
  iona-uefi.img         GPT + ESP FAT32 + IONAFS partition
  iona-bios.img         MBR legacy boot
  iona-disk.img         IONAFS standalone (data)
  iona-efi.iso          ISO hybrid pentru VM
  iona-os-kernel.elf    ELF kernel binary
  iona-os-version.json  Build metadata
```


## Verify artifacts

```bash
./scripts/verify-release.sh
```
