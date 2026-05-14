<img width="737" height="420" alt="iona os" src="https://github.com/user-attachments/assets/c86e3e48-e4c0-4946-9522-27f11175e87a" />
# IONA OS Kernel v0.6.0

> **Status:** Bare-metal x86_64 kernel in Rust — boots in QEMU, kernel subsystems functional, userspace ELFs written but not yet cross-compiled.

---

## Honest Status v0.6.0

Each subsystem is marked honestly:
- **Done** = implemented and compiles, tested in kernel smoke tests
- **Partial** = implemented but with known limitations or untested paths
- **Written** = source code exists but requires separate compilation/validation

---

## Core Kernel

| Subsystem | Status | Notes |
|-----------|--------|-------|
| GDT + IDT + TSS | Done | Ring 0/3, IST, per-CPU |
| APIC timer calibration | Done | PIT reference, real ticks/ms |
| Per-CPU data (GS) | Done | kernel_rsp + tid at GS:0/16 |
| SMP AP startup | Done | up to 64 cores |
| TLB shootdown IPI | Done | Cross-core, ACK |
| QEMU validated | Done | virtio-blk + virtio-net |
| **Real hardware** | Not tested | Only validated in QEMU |

## Memory

| Subsystem | Status | Notes |
|-----------|--------|-------|
| Frame allocator + refcounts | Done | CoW support |
| Buddy O(log n) | Done | 11 orders |
| Slab O(1) | Done | 6 caches |
| CoW fork (L4→L1) | Done | Full page table walk, TLB shootdown on write fault |
| mmap() lazy + file-backed | Done | |
| munmap() PTE teardown | Done | |
| Page fault handler | Done | CoW + mmap + SIGSEGV |
| Memory mapper (OffsetPageTable) | Done | map/unmap/translate, user/kernel page helpers |
| Swap LRU clock + bitmap | Partial | Round-trip works; swap-in remaps via PTE; stress/power-loss untested |
| OOM killer | Done | SIGKILL |

## Scheduling

| Subsystem | Status | Notes |
|-----------|--------|-------|
| Global scheduler (RR) | Done | 256 priorities |
| Per-core local schedulers | Done | Work stealing |
| Wait queues non-busy | Done | |
| Task affinity + migration | Done | |
| cgroups (cpu/mem/io) | Partial | Token bucket CPU throttling; SMP stress untested |

## Process / ABI

| Subsystem | Status | Notes |
|-----------|--------|-------|
| fork/exec/waitpid | Done | |
| clone() threads | Done | CLONE_FILES shares Arc<Mutex<FdTable>> |
| ELF loader + ASLR | Done | auxv, argv/envp |
| ring3 IRETQ path | Done | CR3 switch, TSS RSP0, IRETQ implemented |
| pipe/futex/epoll | Done | Non-blocking pipe write for shell; futex with SeqCst barriers |
| Signals | Done | 15 signals |
| SYSCALL/SYSRET | Done | 60+ syscalls, Linux ABI + IONA-specific |
| copy_from/to_user SMAP | Done | |
| Dynamic linker | Partial | R_X86_64_64/JUMP_SLOT/RELATIVE/GLOB_DAT/COPY/TPOFF64; no full ld.so |
| musl POSIX compat | Partial | brk/getpid/uname/nanosleep/readlink; not full POSIX |
| **iona-node ring3** | Written | ELF source complete; needs cross-compile + install to IONAFS |
| **iona-shell ring3** | Written | ELF source complete (17 builtins); needs cross-compile + install |

## Filesystem

| Subsystem | Status | Notes |
|-----------|--------|-------|
| IONAFS WAL journal | Done | Crash recovery |
| File locking flock | Done | Shared + Exclusive |
| Timestamps + perms | Done | |
| fsck + crash injection | Done | |
| VFS + /proc + /dev | Done | |
| IONAFS durability | Partial | Concurrent stress OK; power-loss iterative untested |

## Networking

| Subsystem | Status | Notes |
|-----------|--------|-------|
| TCP/UDP (smoltcp) | Done | |
| TCP shutdown semantics | Done | |
| DHCP | Done | Full DISCOVER→OFFER→REQUEST→ACK with retries + fallback |
| DNS | Partial | Basic resolution; no recursive resolver |
| TLS 1.3 | Done | ChaCha20-Poly1305 AEAD (RFC 8439), HKDF-SHA256, X25519 key exchange |
| SHA-256 | Done | Real implementation (not ChaCha20-based) |
| Poly1305 | Done | Correct mod 2^130-5 arithmetic with 5x u64 limbs |
| ECDSA P-256 | Partial | Field arithmetic implemented; not validated against test vectors |
| X.509 DER parsing | Done | |
| X.509 trust store | Partial | IONA Root CA + ISRG pins; no full CA bundle from filesystem |
| Network namespaces | Done | Isolated IP + port forwarding |

## Drivers

| Subsystem | Status | Notes |
|-----------|--------|-------|
| virtio-blk + virtio-net | Done | |
| NVMe MMIO + MSI-X | Done | Interrupt-driven, poll_completions, multi-queue |
| NVMe error handling | Done | Retry + queue reset |
| NVMe multi-queue | Partial | CREATE_IO_CQ/SQ admin commands; round-robin |
| xHCI USB 3.0 | Partial | MMIO + Event Ring TRB processing; no real device tested |
| USB device stack | Partial | Enumeration + port speed detection; no class drivers tested |
| Secure Boot | Partial | UEFI GetVariable path; heuristic fallback for non-UEFI |

## Security

| Subsystem | Status | Notes |
|-----------|--------|-------|
| SMEP + SMAP | Done | |
| Stack canary RDRAND | Done | |
| ASLR | Done | |
| Seccomp per-process | Done | Wired in dispatch + audit log |
| Seccomp tests | Done | 6 policy tests |
| Security audit log | Done | |

## Blockchain / IONA

| Subsystem | Status | Notes |
|-----------|--------|-------|
| redb IONAFS adapter | Done | LRU cache + flush |
| EVM opcode interpreter | Done | 40+ opcodes incl. SHA3 (Keccak-256), CREATE2, SELFDESTRUCT |
| Keccak-256 | Done | Full FIPS 202 sponge, 24-round permutation |
| EVM state (account/storage) | Done | Persisted via IONAFS |
| Gossipsub P2P | Done | GRAFT/PRUNE/IHAVE/IWANT, score-based peer selection |
| P2P peer discovery | Done | State machine + reconnect |
| **iona-node** | Written | Full ELF source; needs cross-compile to run in ring 3 |
| **Testnet interop** | Not tested | Protocol implemented; no real validator connection tested |

## WASM

| Subsystem | Status | Notes |
|-----------|--------|-------|
| wasmi runtime | Done | |
| WASM supervisor | Done | Gas + mem + restart |
| WASM seccomp sandbox | Done | |
| WASM host functions | Done | I/O, storage, events, network, IPC, filesystem (read/write/exists/delete) |

## Containers

| Subsystem | Status | Notes |
|-----------|--------|-------|
| cgroups cpu/mem/io | Partial | Token bucket CPU; mem/io limits |
| PID / Mount / UTS namespaces | Done | |
| Network namespaces | Done | |

## ACPI

| Subsystem | Status | Notes |
|-----------|--------|-------|
| Power management | Partial | Intel + AMD P-state; DSDT namespace parsing |
| Font (PSF loader) | Done | PSF1/PSF2 from file; fallback minimal bitmap |

## Debugging

| Subsystem | Status | Notes |
|-----------|--------|-------|
| GDB stub (18 registers) | Done | RSP protocol |
| dmesg ring buffer | Done | 4096 entries |
| Kernel tracing | Done | syscall/sched/fs/net |
| Crash dumps | Done | registers + dmesg + stats |

## Tests

| Suite | Count | Status |
|-------|-------|--------|
| memory | 4 | Done |
| filesystem | 5 | Done |
| syscall | 3 | Done |
| security | 2 | Done |
| swap | 2 | Done |
| net_namespaces | 2 | Done |
| abi | 2 | Done |
| iona_node | 4 | Done |
| seccomp_stress | 6 | Done |
| evm | 3 | Done |
| ionafs_stress | 3 | Done |
| cgroups | 3 | Done |
| dynlink | 2 | Done |
| musl_compat | 2 | Done |
| crypto | 7 | Done |
| **Total** | **50** | Done |

Note: All tests are kernel-mode smoke tests executed at boot. They validate internal logic
but do not test ring 3 userspace or real hardware I/O.

---

## What "IONA on IONA" means (honestly)

**What works:**
- Kernel boots natively on x86_64 bare metal (validated in QEMU)
- All kernel subsystems compile and pass 50 smoke tests (0 errors)
- EVM interpreter runs with 40+ opcodes including real Keccak-256
- Gossipsub P2P protocol with score-based mesh management
- TLS 1.3 with real ChaCha20-Poly1305 + HKDF-SHA256 + X25519
- DHCP full DORA negotiation with retries
- IONAFS journaled filesystem with crash recovery
- Build pipeline: kernel → disk images → IONAFS populated → QEMU boot

**What's written but not yet validated end-to-end:**
- iona-node and iona-shell ELF sources exist but need cross-compilation with the custom target spec
- The ring 3 IRETQ path is implemented but hasn't been exercised with a real userspace binary
- `build-all.sh` builds kernel and populates IONAFS disk, but userspace cross-compilation depends on the `iona_syscall` crate being available
- Testnet interop protocol is correct but never connected to real validators

---

## Building

```bash
# Prerequisites
rustup toolchain install nightly
rustup target add x86_64-unknown-none
rustup component add rust-src llvm-tools-preview
sudo apt install qemu-system-x86 lld

# Kernel only (guaranteed to work)
cargo build

# Full build (kernel + userspace + IONAFS disk image)
./build-all.sh

# Boot in QEMU
./scripts/build-and-run.sh
```

## Next Steps (v0.7.0)

1. Cross-compile iona-node and iona-shell with custom target spec, validate ring 3 boot
2. Connect Gossipsub to real testnet validators
3. Full CA certificate validation with production certs
4. Hardware testing: run on a real x86_64 PC
5. musl libc: more POSIX coverage (threads, locale, stdio)
6. EVM: CALL + STATICCALL + DELEGATECALL
