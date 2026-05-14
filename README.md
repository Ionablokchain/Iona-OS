
<img width="737" height="420" alt="iona os" src="https://github.com/user-attachments/assets/c86e3e48-e4c0-4946-9522-27f11175e87a" />
# IONA OS

**A sovereign operating system kernel written from scratch in Rust.**

IONA OS is a bare-metal, monolithic kernel for x86_64, designed to provide a secure,
post-quantum, and fully autonomous computing environment. It is the foundation of
the IONA ecosystem, which spans desktop, mobile, blockchain, AI, and custom
programming languages — all built by a single founder over 10 years.

> ⚠️ **Important:** This repository contains the public kernel (v0.7.0), published
> to demonstrate architecture, build reproducibility, and subsystem maturity.
> The full IONA OS desktop environment — with GUI, compositor, Windows/Linux
> binary compatibility, 3D engine, on-device AI agent, mesh networking, and
> hundreds of native apps — is significantly more advanced. A live demo can be
> arranged upon request.

---

## Why IONA OS

| Differentiator | What it means |
| :--- | :--- |
| **Built from scratch** | Own kernel, own memory manager, own scheduler, own filesystem. No Linux. No BSD. No Windows. |
| **Post-quantum cryptography** | Dilithium3, Kyber-768, SPHINCS+ — integrated at the kernel level, not bolted on. |
| **Memory-safe (Rust)** | ~90% of the kernel is written in Rust. Zero buffer overflows, zero use-after-free. |
| **EVM-compatible** | Native L1 blockchain with ZK-EVM, DAG-based consensus, and on-chain governance. |
| **Dual-use by design** | Consumer, enterprise, and government-grade security — air-gappable, onion-routed, auditable. |
| **Sovereign by default** | No telemetry, no cloud dependency, no foreign code. Every line was written by the founder. |

<img width="764" height="432" alt="test" src="https://github.com/user-attachments/assets/02914fcc-a35c-4816-9bb9-4e90b3ce07b5" />
---

## Architecture (v0.7.0)

### Core Kernel
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| GDT / IDT | ✅ Done | Global/interrupt descriptor tables, 256 interrupt vectors |
| Memory management | ✅ Done | PMM, VMM, frame allocator, buddy, slab, mmap/shm |
| SMP / APIC / IOMMU | ✅ Done | Multi-core support, APIC timer, interrupt routing, DMA isolation |
| Scheduler | ✅ Done | EDF real-time + CFS, priority inheritance, work queues |
| Fork / Exec / ELF loader | ✅ Done | Process creation, ELF64 parsing, PIE + ASLR |
| IPC | ✅ Done | Pipes, futex, epoll, message queues |
| Signals | ✅ Done | POSIX signals, signal handlers, sigaltstack |
| Syscall table | ✅ Done | 32+ syscalls, seccomp enforcement, IONA-specific extensions |

### Filesystem
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| IONAFS | ✅ Done | Custom filesystem with WAL journaling, encryption, integrity |
| VFS / Procfs / Devfs | ✅ Done | Virtual filesystem layer, /proc, /dev |
| ext4 / FAT32 | ✅ Partial | Read support for external filesystems |

### Networking
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| TCP / UDP stack | ✅ Done | Custom network stack with IPv4/IPv6 |
| TLS 1.3 | ✅ Done | ECDSA + post-quantum key exchange |
| Mesh networking | ✅ Done | Peer-to-peer mesh with onion routing |
| WireGuard / SSH | ✅ Done | VPN and remote access |

### Security
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| Post-quantum crypto | ✅ Done | Dilithium3, Kyber-768, SPHINCS+ (NIST test vectors verified) |
| Secure Boot | ✅ Done | Verified boot with Merkle tree, anti-rollback |
| ASLR / Stack Canary | ✅ Done | Kernel address space layout randomization |
| SMEP / SMAP | ✅ Done | Supervisor mode execution/access prevention |
| Seccomp / Sandboxing | ✅ Done | Per-process syscall filtering, WASM sandbox |

### IONA Protocol (Blockchain)
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| Consensus engine | ✅ Done | BFT consensus with fast finality |
| EVM | ✅ Done | 40+ opcodes, precompiles, state trie |
| Governance | ✅ Done | On-chain voting, proposal lifecycle |
| Validators | ✅ Done | Validator set management, slashing |

### AI / ML
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| On-device LLM | ✅ Done | INT4 quantized transformer, GPU-accelerated |
| NN Compiler | ✅ Done | ONNX parser, RDNA2 ISA backend |
| RAG / Whisper | ✅ Done | Retrieval-augmented generation, speech-to-text |

### Build & Test
| Subsystem | Status | Description |
| :--- | :--- | :--- |
| QEMU boot | ✅ Done | Build and boot in QEMU with a single script |
| Test suite | ✅ Done | 50+ kernel tests, all passing |
| CI/CD | ✅ Done | GitHub Actions, reproducible builds |

---

## Build

### Prerequisites
- Rust nightly (see `rust-toolchain.toml`)
- QEMU (for emulation)
- Make

### Build the kernel
```bash
cargo build --release
Build ISO
bash
./build-all.sh
Run in QEMU
bash
./run_qemu.sh
Screenshots
IONA OS boot screen	IONA OS running Rust toolchain
https://screen_boot_qemu64.png	https://screen_gui.png
License
MIT

Links
IONA OS Phone — Sovereign mobile OS

IONA Protocol — L1 blockchain

Carpel Language — Custom systems language

Flux Language — Temporal-quantum language

Nihilo OS — The next paradigm

Website https://www.iona-protocol.org/

Contact
For inquiries, demos, or partnership opportunities: ericbulai@gmail.com
