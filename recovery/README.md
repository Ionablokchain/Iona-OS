# IONA OS Recovery

## Recovery boot
Adaugă `recovery=1` la cmdline GRUB:
  multiboot2 /boot/iona-os-kernel.elf recovery=1

Kernelul detectează flagul și pornește în recovery shell
(terminal minimal, fără GUI, fără node).

## Rollback
  ./scripts/update.sh --rollback

Restaurează ultimul backup din backup/*.zip.

## Kernel panic recovery
La panic: ecranul arată BSOD cu mesajul de eroare.
Reboot automat după 30s dacă reboot_on_panic=1 în config.

## Factory reset
Șterge /etc/iona-os-firstboot.done și restartează firstboot wizard.
