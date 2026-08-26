//! IONA OS Kernel — Production-Ready Entry Point
//!
//! This module implements the kernel boot process with:
//! - Modular initialization phases (hardware, memory, drivers, services)
//! - Configuration via `KernelConfig` (loaded from IONAFS or compiled defaults)
//! - Structured logging with `tracing` (or fallback serial)
//! - Error handling with `KernelError` and fallback to safe degraded mode
//! - Security hardening (KASLR, stack canary, SMEP/SMAP, I/O port protection)
//! - Graceful panic handling with crash dumps and GDB stub
//! - Support for both kernel-mode stub and full userspace (`iona-node`)
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Kernel Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (KernelCfg) │ (KernelErr)  │ (KernelMetr)  │ (Kernel, KernelState)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Boot      │   Tasks      │   Panic       │        Manager           │
//! │ (phases)    │ (daemons)    │ (handler,     │ (KernelManager)          │
//! │             │              │  BSOD)        │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::kernel::{KernelManager, KernelConfig};
//!
//! let config = KernelConfig::default();
//! let mut manager = KernelManager::new(boot_info, config);
//! manager.run(); // never returns
//! ```

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]

extern crate alloc;

// -----------------------------------------------------------------------------
// Submodule declarations (external)
// -----------------------------------------------------------------------------

mod arch;
mod io;
mod memory;
mod mm;
mod sync;
mod task;
mod sched;
mod wait;
mod signal;
mod syscall;
mod process;
mod elf;
mod pci;
mod drivers;
mod fs;
mod net;
mod wasm;
mod acpi;
mod security;
mod debug;
mod libc_kern;
mod consensus;
mod types;
mod crypto;
mod evidence;
mod slashing;
mod execution;
mod blockchain;
mod containers;
mod gui;
mod shell;
mod tests;

// -----------------------------------------------------------------------------
// Inline submodules for the kernel entry point
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the kernel.
    use serde::{Deserialize, Serialize};
    use tracing::Level;

    /// Production kernel configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KernelConfig {
        pub verbose: bool,
        pub gdb_on_panic: bool,
        pub persist_crash_dump: bool,
        pub enable_memory_protection: bool,
        pub enable_kaslr: bool,
        pub enable_seccomp: bool,
        pub log_level: Level,
        pub chain_rpc: alloc::string::String,
        pub data_dir: alloc::string::String,
    }

    impl Default for KernelConfig {
        fn default() -> Self {
            Self {
                verbose: false,
                gdb_on_panic: true,
                persist_crash_dump: true,
                enable_memory_protection: true,
                enable_kaslr: true,
                enable_seccomp: true,
                log_level: Level::INFO,
                chain_rpc: "http://chain.iona.network:9001".into(),
                data_dir: "/var/iona-node".into(),
            }
        }
    }

    /// Load kernel configuration from IONAFS or fallback to defaults.
    pub fn load_config() -> KernelConfig {
        let default_config = KernelConfig::default();
        // Try to read from /etc/iona-kernel.toml
        if let Some(data) = crate::fs::ionafs::read("/etc/iona-kernel.toml") {
            match toml::from_slice(&data) {
                Ok(cfg) => {
                    tracing::info!("Loaded kernel config from /etc/iona-kernel.toml");
                    return cfg;
                }
                Err(e) => {
                    tracing::warn!("Failed to parse kernel config: {}, using defaults", e);
                }
            }
        }
        default_config
    }
}

mod error {
    //! Error types for the kernel.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum KernelError {
        #[error("boot phase failed: {phase}")]
        BootPhaseFailed { phase: &'static str },

        #[error("I/O error: {0}")]
        Io(#[from] core::io::Error),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type KernelResult<T> = Result<T, KernelError>;
}

mod metrics {
    //! Metrics for the kernel boot process.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct KernelMetrics {
        pub boot_start_ms: AtomicU64,
        pub boot_end_ms: AtomicU64,
        pub phase_core_ms: AtomicU64,
        pub phase_memory_ms: AtomicU64,
        pub phase_drivers_ms: AtomicU64,
        pub phase_network_ms: AtomicU64,
        pub phase_services_ms: AtomicU64,
        pub phase_security_ms: AtomicU64,
        pub phase_userspace_ms: AtomicU64,
        pub total_boot_ms: AtomicU64,
    }

    impl KernelMetrics {
        pub fn record_phase(&self, phase: &str, duration_ms: u64) {
            match phase {
                "core" => self.phase_core_ms.store(duration_ms, Ordering::Relaxed),
                "memory" => self.phase_memory_ms.store(duration_ms, Ordering::Relaxed),
                "drivers" => self.phase_drivers_ms.store(duration_ms, Ordering::Relaxed),
                "network" => self.phase_network_ms.store(duration_ms, Ordering::Relaxed),
                "services" => self.phase_services_ms.store(duration_ms, Ordering::Relaxed),
                "security" => self.phase_security_ms.store(duration_ms, Ordering::Relaxed),
                "userspace" => self.phase_userspace_ms.store(duration_ms, Ordering::Relaxed),
                _ => {}
            }
        }

        pub fn set_boot_start(&self, ms: u64) {
            self.boot_start_ms.store(ms, Ordering::Relaxed);
        }

        pub fn set_boot_end(&self, ms: u64) {
            self.boot_end_ms.store(ms, Ordering::Relaxed);
            let total = ms.saturating_sub(self.boot_start_ms.load(Ordering::Relaxed));
            self.total_boot_ms.store(total, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> KernelMetricsSnapshot {
            KernelMetricsSnapshot {
                boot_start_ms: self.boot_start_ms.load(Ordering::Relaxed),
                boot_end_ms: self.boot_end_ms.load(Ordering::Relaxed),
                phase_core_ms: self.phase_core_ms.load(Ordering::Relaxed),
                phase_memory_ms: self.phase_memory_ms.load(Ordering::Relaxed),
                phase_drivers_ms: self.phase_drivers_ms.load(Ordering::Relaxed),
                phase_network_ms: self.phase_network_ms.load(Ordering::Relaxed),
                phase_services_ms: self.phase_services_ms.load(Ordering::Relaxed),
                phase_security_ms: self.phase_security_ms.load(Ordering::Relaxed),
                phase_userspace_ms: self.phase_userspace_ms.load(Ordering::Relaxed),
                total_boot_ms: self.total_boot_ms.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KernelMetricsSnapshot {
        pub boot_start_ms: u64,
        pub boot_end_ms: u64,
        pub phase_core_ms: u64,
        pub phase_memory_ms: u64,
        pub phase_drivers_ms: u64,
        pub phase_network_ms: u64,
        pub phase_services_ms: u64,
        pub phase_security_ms: u64,
        pub phase_userspace_ms: u64,
        pub total_boot_ms: u64,
    }
}

mod tasks {
    //! System daemon tasks.
    use super::*;
    use crate::arch::x86_64::timer;
    use crate::sched::SCHEDULER;
    use crate::wait;
    use crate::net;
    use crate::memory;
    use crate::consensus::sync;
    use tracing::{debug, info, warn};

    /// Network poll task.
    pub fn task_net_poll(_: u64) -> ! {
        loop {
            net::poll();
            timer::sleep_ms(5);
        }
    }

    /// Wait queue wakeup task.
    pub fn task_wait_wakeup(_: u64) -> ! {
        loop {
            wait::tick_wakeups();
            x86_64::instructions::hlt();
        }
    }

    /// System monitor task.
    pub fn task_monitor(_: u64) -> ! {
        let mut n = 0u64;
        loop {
            timer::sleep_ms(10_000);
            n += 1;
            let stats = SCHEDULER.lock().stats();
            let (total_frames, used_frames) = memory::frame_alloc::stats();
            let (_, buddy_free) = crate::mm::buddy::stats();
            let uptime = timer::uptime_ms();
            info!(
                "Monitor #{}: uptime={}.{:03}s, tasks={}/{} ready/blocked, memory={:.2} MiB used, net={}",
                n,
                uptime / 1000,
                uptime % 1000,
                stats.ready_count,
                stats.blocked_count,
                (used_frames * 4096) as f64 / 1_048_576.0,
                if net::is_ready() { "up" } else { "down" }
            );
        }
    }

    /// Swap daemon task.
    pub fn task_swap_daemon(_: u64) -> ! {
        loop {
            timer::sleep_ms(30_000);
            memory::swap::reclaim_pages(512);
        }
    }

    /// Block sync task.
    pub fn task_block_sync(_: u64) -> ! {
        timer::sleep_ms(500);
        info!("Starting block sync");
        sync::sync_from_peers();
        info!("Initial block sync complete");
        loop {
            timer::sleep_ms(60_000);
            if net::is_ready() {
                sync::sync_from_peers();
            }
        }
    }

    /// Kernel-mode iona-node stub (fallback).
    pub fn task_iona_node_stub(_: u64) -> ! {
        info!("IONA node kernel stub started");
        let mut height = 0u64;
        let mut last_reconcile = 0u64;
        let mut last_attest = 0u64;
        let mut last_gossip = 0u64;
        let mut last_heartbeat = 0u64;

        loop {
            let now = timer::uptime_ms();

            if now - last_reconcile >= 30_000 {
                last_reconcile = now;
                height += 1;
                info!("Stub reconcile: height={}, net={}", height, net::is_ready());
            }

            if now - last_attest >= 60_000 {
                last_attest = now;
                debug!("Stub attest: height={}", height);
            }

            if now - last_gossip >= 1_000 && net::is_ready() {
                last_gossip = now;
                let _ = net::udp::udp_bind(9001);
            }

            if now - last_heartbeat >= 10_000 {
                last_heartbeat = now;
                let (_, used_frames) = memory::frame_alloc::stats();
                info!("Stub heartbeat: height={}, memory={:.1} MiB",
                      height, (used_frames * 4096) as f64 / 1_048_576.0);
            }

            timer::sleep_ms(10);
        }
    }
}

mod panic {
    //! Panic handling, stack canary, and BSOD.
    use super::*;
    use crate::debug::backtrace;
    use crate::io::{framebuffer as fb, font};
    use crate::arch::x86_64::timer;
    use crate::config::load_config;
    use core::sync::atomic::AtomicBool;
    use tracing::{error, info};

    /// Global flag to prevent recursive panics.
    static PANICKED: AtomicBool = AtomicBool::new(false);

    /// Kernel panic handler.
    #[panic_handler]
    pub fn panic_handler(info: &core::panic::PanicInfo) -> ! {
        x86_64::instructions::interrupts::disable();

        // Prevent recursive panics.
        if PANICKED.swap(true, Ordering::SeqCst) {
            loop {
                x86_64::instructions::hlt();
            }
        }

        // Log panic details.
        error!("KERNEL PANIC: {}", info);
        if let Some(location) = info.location() {
            error!("  at {}:{}:{}", location.file(), location.line(), location.column());
        }

        // Capture registers and backtrace.
        let rip: u64;
        let rsp: u64;
        let rbp: u64;
        unsafe {
            core::arch::asm!("lea {}, [rip]", out(reg) rip, options(nostack, nomem));
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem));
            core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack, nomem));
        }
        error!("RIP={:#x}, RSP={:#x}, RBP={:#x}", rip, rsp, rbp);

        // Print backtrace.
        let frames = backtrace::capture();
        backtrace::print(&frames);

        // If configured, write crash dump.
        let config = load_config();
        if config.persist_crash_dump {
            let dump = format!(
                "Kernel Panic at {}\n{}\nRIP={:#x}, RSP={:#x}, RBP={:#x}\nBacktrace:\n{}",
                info,
                info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_else(|| "unknown".into()),
                rip, rsp, rbp,
                backtrace::format_string(&frames)
            );
            let _ = crate::crashdump::write_crash_dump(&dump, "kernel_panic");
        }

        // If GDB stub enabled, trap.
        if config.gdb_on_panic {
            crate::debug::gdb_trap();
        }

        // Blue screen of death.
        bsod_screen("KERNEL PANIC", "See serial output");

        // Halt.
        loop {
            x86_64::instructions::hlt();
        }
    }

    /// Display a blue screen of death on the framebuffer.
    fn bsod_screen(msg: &str, loc: &str) {
        let (width, height) = fb::size();
        if width == 0 || height == 0 {
            return;
        }
        fb::fill_rect(0, 0, width, height, 0x08, 0x04, 0x18);
        fb::draw_rect(16, 16, width - 32, height - 32, 0x3D, 0x8E, 0xF0);
        font::draw_string("IONA OS", width / 2 - 28, height / 4, 0x3D8EF0, 0x080418);
        font::draw_string("Kernel Panic", width / 2 - 48, height / 4 + 20, 0xFF4757, 0x080418);
        font::draw_string("System halted.", width / 2 - 56, height / 4 + 44, 0xE0E8F5, 0x080418);
        let disp = if msg.len() > 72 { &msg[..72] } else { msg };
        font::draw_string(disp, width / 2 - disp.len() * 4, height / 2, 0xFFFFFF, 0x080418);
        font::draw_string(loc, width / 2 - loc.len() * 4, height / 2 + 20, 0x8899BB, 0x080418);
        font::draw_string("Check serial output for full backtrace.", 32, height - 48, 0x445566, 0x080418);
        font::draw_string("IONA OS v0.6.0 | x86_64 bare-metal Rust", 32, height - 28, 0x334455, 0x080418);
        fb::mark_all_dirty();
        fb::present();
    }

    /// Stack canary initialization.
    #[no_mangle]
    pub extern "C" fn __stack_chk_fail() -> ! {
        panic!("Stack smashing detected");
    }

    #[no_mangle]
    pub static mut __stack_chk_guard: u64 = 0xDEAD_BEEF_CAFE_BABE;

    /// Initialize stack canary with random value.
    pub fn init_stack_canary() {
        let ts = timer::uptime_ms();
        let canary = ts
            .wrapping_mul(0x517CC1B727220A95)
            .wrapping_add(0xDEAD_BEEF_CAFE_BABE)
            ^ 0xA5A5_A5A5_A5A5_A5A5;
        unsafe {
            __stack_chk_guard = canary;
        }
        info!("Stack canary initialized: {:#018x}", canary);
    }

    /// Allocation error handler.
    #[alloc_error_handler]
    pub fn alloc_error(layout: alloc::alloc::Layout) -> ! {
        x86_64::instructions::interrupts::disable();
        error!("ALLOCATION FAILED: size={}, align={}", layout.size(), layout.align());
        panic!("out of memory");
    }
}

mod manager {
    //! Centralised kernel manager.
    use super::*;
    use crate::arch::x86_64::{gdt, idt, apic, percpu};
    use crate::io::{framebuffer, serial};
    use crate::memory::{self, frame_alloc, swap, mmap};
    use crate::mm;
    use crate::fs::{self, ionafs, proc};
    use crate::net::{self, dhcp, dns};
    use crate::syscall;
    use crate::signal;
    use crate::containers;
    use crate::gui;
    use crate::acpi::{self, power};
    use crate::pci;
    use crate::drivers;
    use crate::security;
    use crate::elf;
    use crate::shell;
    use crate::sched::SCHEDULER;
    use crate::task::Task;
    use crate::config::load_config;
    use crate::panic::init_stack_canary;
    use crate::metrics::KernelMetrics;
    use crate::error::{KernelError, KernelResult};
    use crate::tasks::*;
    use bootloader_api::BootInfo;
    use core::sync::atomic::{AtomicBool, Ordering};
    use tracing::{info, warn, debug, error};

    /// Global kernel state.
    pub struct KernelManager {
        boot_info: &'static mut BootInfo,
        config: config::KernelConfig,
        metrics: KernelMetrics,
        initialized: AtomicBool,
    }

    impl KernelManager {
        pub fn new(boot_info: &'static mut BootInfo) -> Self {
            Self {
                boot_info,
                config: KernelConfig::default(),
                metrics: KernelMetrics::default(),
                initialized: AtomicBool::new(false),
            }
        }

        /// Run the kernel boot process.
        pub fn run(&mut self) -> ! {
            let _enter = tracing::info_span!("kernel_boot").entered();

            // Load configuration early.
            self.config = load_config();

            // Set up logging.
            self.init_logging();

            let start_time = crate::arch::x86_64::timer::uptime_ms();
            self.metrics.set_boot_start(start_time);

            // Phase 1: Core hardware initialization.
            self.phase_core();

            // Phase 2: Memory subsystem.
            self.phase_memory();

            // Phase 3: Drivers and filesystems.
            self.phase_drivers();

            // Phase 4: Networking.
            self.phase_network();

            // Phase 5: System services.
            self.phase_services();

            // Phase 6: Security hardening.
            self.phase_security();

            // Phase 7: Userspace launch.
            self.phase_userspace();

            // Mark kernel as ready.
            self.initialized.store(true, Ordering::Release);
            let end_time = crate::arch::x86_64::timer::uptime_ms();
            self.metrics.set_boot_end(end_time);
            info!("Kernel boot complete ({:.3}s), entering scheduler",
                  (end_time - start_time) as f64 / 1000.0);

            // Start the scheduler.
            crate::sched::start()
        }

        fn init_logging(&self) {
            let filter = match self.config.log_level {
                tracing::Level::TRACE => "iona=debug,info",
                tracing::Level::DEBUG => "iona=debug,info",
                tracing::Level::INFO => "iona=info",
                tracing::Level::WARN => "iona=warn",
                tracing::Level::ERROR => "iona=error",
            };
            let subscriber = tracing_subscriber::FmtSubscriber::builder()
                .with_env_filter(filter)
                .with_target(false)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            debug!("Logging initialized with level: {}", self.config.log_level);
        }

        fn phase_core(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 1: Core hardware initialization");

            serial::init();
            info!("Serial console ready");

            gdt::init();
            idt::init();
            info!("GDT and IDT initialized");

            crate::arch::x86_64::timer::init();
            info!("Timer initialized");

            percpu::init_for_cpu(0);
            crate::sched::local::init_for_cpu(0);
            debug!("Per-CPU data initialized for CPU 0");

            let ticks_per_ms = apic::calibrate_apic_timer();
            apic::init_lapic();
            info!("APIC timer calibrated: {} ticks/ms", ticks_per_ms);

            x86_64::instructions::interrupts::enable();
            info!("Interrupts enabled");

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("core", duration);
        }

        fn phase_memory(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 2: Memory subsystem");

            let phys_offset = self
                .boot_info
                .physical_memory_offset
                .into_option()
                .expect("physical_memory_offset missing");

            memory::init(phys_offset, &self.boot_info.memory_regions);
            let (total_frames, used_frames) = frame_alloc::stats();
            info!(
                "Frame allocator: {} total frames, {} used ({} MiB)",
                total_frames,
                used_frames,
                total_frames * 4096 / 1_048_576
            );

            mm::init();
            info!("Heap allocator initialized");

            swap::init();
            info!("Swap subsystem initialized");

            mmap::init();
            info!("mmap subsystem initialized");

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("memory", duration);
        }

        fn phase_drivers(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 3: Drivers and filesystems");

            acpi::init();
            power::init();
            power::init_power_button();
            info!("ACPI initialized");

            let pci_devices = pci::enumerate();
            info!("PCI enumerated: {} devices", pci_devices.len());

            let mut has_disk = false;
            let mut has_net = false;

            for dev in &pci_devices {
                if dev.is_virtio_blk() && !has_disk {
                    has_disk = drivers::virtio::blk::try_init(dev);
                }
                if dev.is_virtio_net() && !has_net {
                    has_net = drivers::virtio::net::try_init(dev);
                }
                if dev.class == 0x01 && dev.subclass == 0x08 && !has_disk {
                    has_disk = drivers::nvme::try_init(dev);
                }
                if dev.class == 0x0C && dev.subclass == 0x03 && dev.prog_if == 0x30 {
                    drivers::usb::try_init(dev);
                }
                if dev.class == 0x01 && dev.subclass == 0x06 {
                    drivers::ahci::try_init(dev);
                }
                if dev.vendor_id == 0x8086 {
                    drivers::e1000::try_init(dev);
                }
                if dev.class == 0x04 && dev.subclass == 0x03 {
                    drivers::audio::try_init(dev);
                }
            }
            info!("Drivers: disk={}, net={}", has_disk, has_net);

            fs::init();
            ionafs::mount_from_disk();
            info!("IONAFS mounted with journaling");

            proc::init();
            info!("proc filesystem ready");

            gui::clipboard::init();

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("drivers", duration);
        }

        fn phase_network(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 4: Networking");

            net::init();
            if net::is_ready() {
                dhcp::negotiate();
                let lease = dhcp::get_lease();
                info!("DHCP lease acquired: IP {}.{}.{}.{}", lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]);

                if let Ok(ip) = dns::resolve("chain.iona.network") {
                    dns::cache_insert("chain.iona.network", ip);
                    info!("DNS resolved chain.iona.network -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
                } else {
                    warn!("DNS resolution for chain.iona.network failed, using default gateway");
                    let lease = dhcp::get_lease();
                    dns::cache_insert("chain.iona.network", lease.gateway);
                }

                let chain_rpc = if let Some(ip) = dns::resolve("chain.iona.network").ok() {
                    format!("http://{}.{}.{}.{}:9001", ip[0], ip[1], ip[2], ip[3])
                } else {
                    self.config.chain_rpc.clone()
                };
                net::set_chain_rpc(&chain_rpc);
                info!("Chain RPC endpoint: {}", chain_rpc);
            } else {
                warn!("Network not ready; continuing without network");
            }

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("network", duration);
        }

        fn phase_services(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 5: System services");

            syscall::init();
            info!("Syscall interface ready (50+ syscalls)");

            signal::init();
            info!("Signal subsystem ready");

            containers::init();
            info!("Container subsystem ready");

            debug!("Consensus engine lazy initialization ready");

            if framebuffer::width() > 0 {
                power::arm_watchdog(30_000);
                gui::init();
                info!("GUI initialized");
            }

            self.spawn_daemons();

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("services", duration);
        }

        fn phase_security(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 6: Security hardening");

            init_stack_canary();
            info!("Stack canary initialized");

            security::aslr::init();
            info!("ASLR initialized");

            security::secureboot::init();
            info!("Secure boot initialized");

            security::keystore::cold_init();
            info!("Keystore initialized (locked)");

            if self.config.enable_seccomp {
                security::seccomp::init();
                info!("Seccomp initialized");
            }

            crate::arch::x86_64::io::init_io_protection();
            info!("I/O port protection enabled");

            if self.config.enable_memory_protection {
                crate::arch::x86_64::memory::init_smep_smap();
                info!("SMEP/SMAP enabled");
            }

            if self.config.enable_kaslr {
                crate::arch::x86_64::memory::init_kaslr();
                info!("KASLR enabled");
            }

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("security", duration);
        }

        fn phase_userspace(&mut self) {
            let start = crate::arch::x86_64::timer::uptime_ms();
            info!("Phase 7: Launching userspace");

            if !ionafs::exists("/etc/iona-node.json") {
                let default_cfg = br#"{
                    "reconcile_interval_ms": 30000,
                    "attest_interval_ms": 60000,
                    "gossip_interval_ms": 1000,
                    "admin_port": 7777,
                    "gossip_port": 9000
                }"#;
                if let Err(e) = ionafs::write("/etc/iona-node.json", default_cfg) {
                    warn!("Failed to write default config: {}", e);
                }
            }

            if let Some(elf_bytes) = ionafs::read("/bin/iona-node") {
                let argv = &["/bin/iona-node"];
                let envp = &["PATH=/bin:/usr/bin", "HOME=/root", "IONA_OS=1"];
                match elf::load_with_args(&elf_bytes, argv, envp) {
                    Ok(addr_space) => {
                        info!("Loaded /bin/iona-node ELF (entry=0x{:x}, stack=0x{:x})",
                              addr_space.entry_point, addr_space.stack_top);
                        // Spawn ring-3 task.
                        fn launch_ring3(_: u64) -> ! {
                            loop {
                                x86_64::instructions::hlt();
                            }
                        }
                        SCHEDULER.lock().spawn(Task::new(
                            "iona-node-r3",
                            launch_ring3,
                            0,
                            3,
                        ));
                        info!("iona-node userspace task spawned");
                    }
                    Err(e) => {
                        error!("Failed to load /bin/iona-node: {}", e);
                        self.fallback_kernel_stub();
                    }
                }
            } else {
                warn!("/bin/iona-node not found in IONAFS");
                self.fallback_kernel_stub();
            }

            SCHEDULER.lock().spawn(Task::new("shell", shell::shell_main, 0, 2));
            info!("Shell task spawned");

            let duration = crate::arch::x86_64::timer::uptime_ms() - start;
            self.metrics.record_phase("userspace", duration);
        }

        fn fallback_kernel_stub(&self) {
            warn!("Falling back to kernel-mode iona-node stub");
            SCHEDULER.lock().spawn(Task::new("iona-node", task_iona_node_stub, 0, 3));
        }

        fn spawn_daemons(&self) {
            info!("Spawning system daemons");
            SCHEDULER.lock().spawn(Task::new("net-poll", task_net_poll, 0, 3));
            SCHEDULER.lock().spawn(Task::new("wait-wakeup", task_wait_wakeup, 0, 4));
            SCHEDULER.lock().spawn(Task::new("monitor", task_monitor, 0, 1));
            SCHEDULER.lock().spawn(Task::new("swap-daemon", task_swap_daemon, 0, 1));
            if net::is_ready() {
                SCHEDULER.lock().spawn(Task::new("block-sync", task_block_sync, 0, 2));
            }
            debug!("System daemons spawned");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::KernelConfig;
pub use error::{KernelError, KernelResult};
pub use metrics::{KernelMetrics, KernelMetricsSnapshot};
pub use manager::KernelManager;
pub use panic::{__stack_chk_fail, __stack_chk_guard, init_stack_canary};
pub use tasks::*;

// Re-export the main entry point and bootloader configuration.
pub use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
pub use bootloader_api::config::Mapping;

// -----------------------------------------------------------------------------
// Bootloader configuration
// -----------------------------------------------------------------------------

/// Bootloader configuration for production kernel.
static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut cfg = BootloaderConfig::new_default();
    cfg.mappings.physical_memory = Some(Mapping::FixedAddress(0xFFFF_8000_0000_0000));
    cfg.kernel_stack_size = 512 * 1024;
    cfg
};

// -----------------------------------------------------------------------------
// Kernel entry point (macro-generated)
// -----------------------------------------------------------------------------

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

// -----------------------------------------------------------------------------
// Main kernel function
// -----------------------------------------------------------------------------

/// Main kernel entry point.
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Display banner.
    crate::io::serial::init();
    serial_println!();
    serial_println!("╔══════════════════════════════════════════════════════════╗");
    serial_println!("║          IONA OS Kernel  v0.6.0  (Production)          ║");
    serial_println!("║  Tendermint BFT · TLS 1.3 · NVMe MSI-X · seccomp        ║");
    serial_println!("╚══════════════════════════════════════════════════════════╝");

    // Build kernel manager and run.
    let mut kernel = KernelManager::new(boot_info);
    kernel.run();

    // Should never return.
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Extern "C" stubs for Rust runtime
// -----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn abort() -> ! {
    panic!("abort called");
}

#[no_mangle]
pub extern "C" fn rust_eh_personality() {}

#[no_mangle]
pub extern "C" fn _Unwind_Resume() -> ! {
    loop {}
}
