# IONA OS Recovery

## Recovery boot
Add `recovery=1` to GRUB cmdline:
multiboot2 /boot/iona-os-kernel.elf recovery=1

Kernel detects flag and boots into recovery shell
(minimal terminal, no GUI, no node).

## Rollback
./scripts/update.sh --rollback

Restore last backup from backup/*.zip.

## Kernel panic recovery
On panic: screen shows BSOD with error message.
Automatically reboot after 30s if reboot_on_panic=1 in config.

## Factory reset
Delete /etc/iona-os-firstboot.done and restart firstboot wizard.
