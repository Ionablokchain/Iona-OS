# IONA OS — Architecture Document

## Overview
IONA OS is a bare-metal x86_64 operating system written in Rust that runs a
Tendermint BFT blockchain node natively, without Linux.

## Boot sequence
```
BIOS/UEFI → bootloader_api → kernel entry (_start)
  → GDT/IDT/APIC init
  → Memory: frame allocator → heap → virtual memory
  → PCI enumeration → virtio-blk + virtio-net + NVMe + e1000
  → IONAFS mount from disk
  → Network: virtio-net init → DHCP negotiate
  → Security: ASLR init → seccomp policies → keystore cold_init
  → GUI: WM init → compositor → shell v0.7
  → Userspace: ELF /bin/iona-node → ring3 launch (SYSRET)
  → Scheduler start → consensus engine tick loop
```

## Memory layout
```
0x000000 - 0x0FFFFF   BIOS/reserved
0x100000 - ?          Kernel .text (entry point)
?        - ?          .rodata, .data, .bss
heap_start            32MB kernel heap (linked_list_allocator)
0xFFFF800000000000+   Physical memory identity map (PHYS_OFFSET)
```

## Key subsystems

### Scheduler (src/sched/)
- Round-robin with 8 priority levels
- blocked_tasks BTreeMap for wait queues
- sleep_ms() via HLT idle (C1 state)
- Per-event wake: wake_on_event(WaitEvent)

### IONAFS (src/fs/ionafs/)
- WAL journaled, LBA-addressed
- In-memory BTreeMap cache
- Persistence via virtio-blk/NVMe write_sectors
- Layout: superblock(LBA0) + index(LBA1-15) + journal(LBA16-63) + data(LBA64+)

### Consensus (src/consensus/)
- Tendermint BFT v0.34 spec
- KernelConsensusState global (height, round, peers)
- fast_quorum=true: sub-second finality
- Syscall 400: advance_tick → commit_block

### GUI (src/gui/)
- Shell v0.7: topbar + sidebar + taskbar + 12 apps
- Compositor: dirty-rect aware, 9 region flags
- WM: drag/resize/snap/focus management
- IPC: per-window event queues

## Syscall ABI
rax=nr, rdi=a1, rsi=a2, rdx=a3, r10=a4, r8=a5, r9=a6
Return in rax (negative = error code)
