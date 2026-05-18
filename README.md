
<img width="737" height="420" alt="iona os" src="https://github.com/user-attachments/assets/c86e3e48-e4c0-4946-9522-27f11175e87a" />


# IONA OS — The Sovereign Operating System

> **Building a complete sovereign digital ecosystem — OS (PC + Phone), L1 blockchain, programming languages, and AI — from scratch.**

**IONA OS** is a bare-metal, monolithic operating system kernel for x86_64, written from scratch in Rust. It is the secure foundation of the IONA ecosystem, designed to provide a verifiably autonomous, post-quantum computing environment. It features its own kernel, filesystem, GUI, network stack, and AI agent, eliminating any dependence on Linux, BSD, or Windows code.

**Mission:** To provide a memory-safe, secure-by-design, and fully sovereign compute layer for nations, critical infrastructure, and individuals.

<img width="764" height="432" alt="test" src="https://github.com/user-attachments/assets/02914fcc-a35c-4816-9bb9-4e90b3ce07b5" />

> ⚠️ **Note:** This repository contains the public version of the IONA OS kernel (v0.7.0), published to demonstrate architecture, build reproducibility, and subsystem maturity. The full IONA OS desktop environment — with compositor, Windows/Linux binary compatibility, 3D engine, on-device AI agent, mesh networking, and hundreds of native apps — is significantly more advanced. A live demo can be arranged upon request.

---

## 🛡️ Executive Summary

IONA OS is not a Linux distribution. It is a new operating system architecture, built entirely from scratch. The kernel, memory manager, scheduler, filesystem, and drivers are all original work, written in Rust to eliminate entire classes of memory-safety vulnerabilities. It integrates post-quantum cryptography as a default, not an afterthought, and is designed to run existing Windows and Linux applications natively.

The kernel currently boots on real hardware (AMD Barcelo, Intel Alder Lake) and in QEMU, with over 50 subsystem tests passing.

---

## ⚡ Key Differentiators

| Capability | Description |
| :--- | :--- |
| **Built From Scratch** | Own kernel, own memory manager, own scheduler, own filesystem. No Linux. No BSD. No Windows. |
| **Memory-Safe (Rust)** | ~90% of the kernel is written in Rust. Zero buffer overflows, zero use-after-free. |
| **Post-Quantum by Default** | NIST-standardized algorithms (Dilithium3, Kyber-768, SPHINCS+) integrated at the kernel level. |
| **Full Binary Compatibility** | Runs existing Windows (.exe) and Linux (ELF) applications natively. |
| **Sovereign AI** | On-device, private AI agent with deep OS integration and kernel-level self-healing. |
| **Dual-Use Ready** | Hardened kernel, air-gap capable, with integrated encrypted mesh networking. |

---

## 🧩 Architecture & Subsystems

The kernel is organized into distinct functional modules, each with a clear responsibility. The table below details the maturity of each subsystem in the current public build.

### Core Kernel

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| GDT / IDT | ✅ | Global/interrupt descriptor tables, 256 interrupt vectors |
| Memory Management | ✅ | PMM, VMM, frame allocator, buddy, slab, mmap/shm |
| SMP / APIC / IOMMU | ✅ | Multi-core support, APIC timer, interrupt routing, DMA isolation |
| Scheduler | ✅ | EDF real-time + CFS, priority inheritance, work queues |
| Fork / Exec / ELF Loader | ✅ | Process creation, ELF64 parsing, PIE + ASLR |
| IPC | ✅ | Pipes, futex, epoll, message queues |
| Signals | ✅ | POSIX signals, signal handlers, sigaltstack |
| Syscall Table | ✅ | 32+ syscalls, seccomp enforcement, IONA-specific extensions |

### Filesystem

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| IONAFS | ✅ | Custom filesystem with WAL journaling, encryption, and integrity |
| VFS / Procfs / Devfs | ✅ | Virtual filesystem layer, /proc, /dev |
| ext4 / FAT32 | 🟡 | Read support for external filesystems |

### Networking

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| TCP / UDP Stack | ✅ | Custom network stack with IPv4/IPv6 |
| TLS 1.3 | ✅ | ECDSA + post-quantum key exchange |
| Mesh Networking | ✅ | Peer-to-peer mesh with onion routing |
| WireGuard / SSH | ✅ | VPN and remote access |

### Security

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| Post-Quantum Crypto | ✅ | Dilithium3, Kyber-768, SPHINCS+ (NIST vectors verified) |
| Secure Boot | ✅ | Verified boot with Merkle tree, anti-rollback |
| ASLR / Stack Canary | ✅ | Kernel address space layout randomization |
| SMEP / SMAP | ✅ | Supervisor mode execution/access prevention |
| Seccomp / Sandboxing | ✅ | Per-process syscall filtering, WASM sandbox |

### IONA Protocol (Blockchain)

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| Consensus Engine | ✅ | BFT consensus with fast finality |
| EVM | ✅ | 40+ opcodes, precompiles, state trie |
| Governance | ✅ | On-chain voting, proposal lifecycle |
| Validator Management | ✅ | Validator set management, slashing |

### AI / ML

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| On-Device LLM | ✅ | INT4 quantized transformer, GPU-accelerated |
| NN Compiler | ✅ | ONNX parser, RDNA2 ISA backend |
| RAG / Whisper | ✅ | Retrieval-augmented generation, speech-to-text |

### Compatibility Layer

| Subsystem | Status | Description |
| :--- | :---: | :--- |
| Windows (.exe) | ✅ | Win32 API, GDI, threading, DLL loader |
| Linux (ELF) | ✅ | ~300 syscalls implemented, X11 server, SDL2 port |
| DirectX | ✅ | D3D9/10/11, DXBC→SPIR-V converter |
| Vulkan | ✅ | Native Vulkan ICD loader |

---

## 📊 Project at a Glance

| Metric | Data |
| :--- | :--- |
| **Total Size** | Over **7 GB** of data, including source, binaries, graphics, and NIST test vectors |
| **Total Files** | **~5,800** files |
| **Organization** | Over **1,000** folders, representing distinct functional modules |
| **Primary Language** | ~90% Rust, with additional components in Python, Shell, and C |

---

## 🚀 Build & Run

### Prerequisites
- Rust nightly (see `rust-toolchain.toml`)
- QEMU (for emulation)

### Build the kernel
```bash
cargo build --release
Build ISO
bash
./build-all.sh
Run in QEMU
bash
./run_qemu.sh
The kernel boots to a shell with 50+ subsystem tests passing.

📜 License
Apache 2.0



📧 Contact
For inquiries, demos, or partnership opportunities: ericbulai@gmail.com

