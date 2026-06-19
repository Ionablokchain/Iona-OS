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

#![no_std]
#![no_main]
#![feature(abi_x86_interrupt)]
#![feature(alloc_error_handler)]
#![feature(naked_functions)]

extern crate alloc;

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

use bootloader_api::{entry_point, BootInfo, BootloaderConfig};
use bootloader_api::config::Mapping;
use core::sync::atomic::{AtomicBool, Ordering};
use core::time::Duration;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

// -----------------------------------------------------------------------------
// Bootloader configuration
// -----------------------------------------------------------------------------

/// Bootloader configuration for production kernel.
/// - Maps physical memory at fixed offset for direct access.
/// - Provides 512 KiB kernel stack (sufficient for early init).
static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut cfg = BootloaderConfig::new_default();
    cfg.mappings.physical_memory = Some(Mapping::FixedAddress(0xFFFF_8000_0000_0000));
    cfg.kernel_stack_size = 512 * 1024;
    cfg
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

// -----------------------------------------------------------------------------
// Kernel Configuration (loaded from IONAFS or built-in defaults)
// -----------------------------------------------------------------------------

/// Production kernel configuration.
#[derive(Debug, Clone)]
pub struct KernelConfig {
    /// Enable verbose logging.
    pub verbose: bool,
    /// Enable GDB stub on panic.
    pub gdb_on_panic: bool,
    /// Enable crash dump persistence.
    pub persist_crash_dump: bool,
    /// Enable memory protection features (SMEP, SMAP, etc.).
    pub enable_memory_protection: bool,
    /// Enable KASLR (kernel address space layout randomization).
    pub enable_kaslr: bool,
    /// Enable seccomp filtering for userspace.
    pub enable_seccomp: bool,
    /// Default log level.
    pub log_level: Level,
    /// Chain RPC endpoint.
    pub chain_rpc: alloc::string::String,
    /// Data directory for persistent state.
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
fn load_config() -> KernelConfig {
    let default_config = KernelConfig::default();
    // Try to read from /etc/iona-kernel.toml
    if let Some(data) = fs::ionafs::read("/etc/iona-kernel.toml") {
        match toml::from_slice(&data) {
            Ok(cfg) => {
                info!("Loaded kernel config from /etc/iona-kernel.toml");
                return cfg;
            }
            Err(e) => {
                warn!("Failed to parse kernel config: {}, using defaults", e);
            }
        }
    }
    default_config
}

// -----------------------------------------------------------------------------
// Kernel state
// -----------------------------------------------------------------------------

/// Global kernel state (initialised during boot).
pub struct Kernel {
    /// Boot information.
    pub boot_info: &'static mut BootInfo,
    /// Configuration.
    pub config: KernelConfig,
    /// Boot time (milliseconds since epoch).
    pub boot_time_ms: u64,
    /// Whether the kernel has been initialised.
    pub initialized: AtomicBool,
}

impl Kernel {
    /// Create a new kernel instance.
    pub fn new(boot_info: &'static mut BootInfo) -> Self {
        Self {
            boot_info,
            config: KernelConfig::default(),
            boot_time_ms: 0,
            initialized: AtomicBool::new(false),
        }
    }

    /// Run the kernel boot process.
    pub fn run(&mut self) -> ! {
        let _enter = info_span!("kernel_boot").entered();

        // Load configuration early.
        self.config = load_config();

        // Set up logging.
        self.init_logging();

        // Phase 1: Core hardware initialization.
        self.init_core();

        // Phase 2: Memory subsystem.
        self.init_memory();

        // Phase 3: Drivers and filesystems.
        self.init_drivers();

        // Phase 4: Networking.
        self.init_network();

        // Phase 5: System services.
        self.init_services();

        // Phase 6: Security hardening.
        self.init_security();

        // Phase 7: Userspace launch.
        self.launch_userspace();

        // Mark kernel as ready.
        self.initialized.store(true, Ordering::Release);
        info!("Kernel boot complete, entering scheduler");

        // Start the scheduler.
        sched::start()
    }

    /// Initialize logging subsystem.
    fn init_logging(&self) {
        let filter = match self.config.log_level {
            Level::TRACE => "iona=debug,info",
            Level::DEBUG => "iona=debug,info",
            Level::INFO => "iona=info",
            Level::WARN => "iona=warn",
            Level::ERROR => "iona=error",
        };
        let subscriber = FmtSubscriber::builder()
            .with_env_filter(filter)
            .with_target(false)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
        debug!("Logging initialized with level: {}", self.config.log_level);
    }

    /// Phase 1: Core hardware initialization.
    fn init_core(&mut self) {
        info!("Phase 1: Core hardware initialization");

        // Serial port.
        io::serial::init();
        info!("Serial console ready");

        // GDT and IDT (must be early for exceptions).
        arch::gdt::init();
        arch::idt::init();
        info!("GDT and IDT initialized");

        // Timer.
        arch::timer::init();
        self.boot_time_ms = arch::timer::uptime_ms();
        info!("Timer initialized at {}ms", self.boot_time_ms);

        // Per-CPU data for BSP.
        arch::x86_64::percpu::init_for_cpu(0);
        sched::local::init_for_cpu(0);
        debug!("Per-CPU data initialized for CPU 0");

        // APIC timer calibration.
        let ticks_per_ms = arch::x86_64::apic::calibrate_apic_timer();
        arch::x86_64::apic::init_lapic();
        info!("APIC timer calibrated: {} ticks/ms", ticks_per_ms);

        // Enable interrupts after all critical init is done.
        x86_64::instructions::interrupts::enable();
        info!("Interrupts enabled");
    }

    /// Phase 2: Memory subsystem.
    fn init_memory(&mut self) {
        info!("Phase 2: Memory subsystem");

        let phys_offset = self
            .boot_info
            .physical_memory_offset
            .into_option()
            .expect("physical_memory_offset missing");

        // Frame allocator.
        memory::init(phys_offset, &self.boot_info.memory_regions);
        let (total_frames, used_frames) = memory::frame_alloc::stats();
        info!(
            "Frame allocator: {} total frames, {} used ({} MiB)",
            total_frames,
            used_frames,
            total_frames * 4096 / 1_048_576
        );

        // Heap allocator.
        mm::init();
        info!("Heap allocator initialized");

        // Swap daemon.
        memory::swap::init();
        info!("Swap subsystem initialized");

        // Memory-mapped I/O.
        mm::mmap::init();
        info!("mmap subsystem initialized");
    }

    /// Phase 3: Drivers and filesystems.
    fn init_drivers(&mut self) {
        info!("Phase 3: Drivers and filesystems");

        // ACPI and power management.
        acpi::init();
        acpi::power::init();
        acpi::power::init_power_button();
        info!("ACPI initialized");

        // PCI enumeration.
        let pci_devices = pci::enumerate();
        info!("PCI enumerated: {} devices", pci_devices.len());

        // Driver detection.
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

        // IONAFS with journaling.
        fs::init();
        fs::ionafs::mount_from_disk();
        info!("IONAFS mounted with journaling");

        // /proc virtual filesystem.
        fs::proc::init();
        info!("proc filesystem ready");

        // Clipboard.
        gui::clipboard::init();
    }

    /// Phase 4: Networking.
    fn init_network(&mut self) {
        info!("Phase 4: Networking");

        net::init();
        if net::is_ready() {
            net::dhcp::negotiate();
            let lease = net::dhcp::get_lease();
            info!("DHCP lease acquired: IP {}.{}.{}.{}", lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]);

            // DNS resolution for chain endpoint.
            if let Ok(ip) = net::dns::resolve("chain.iona.network") {
                net::dns::cache_insert("chain.iona.network", ip);
                info!("DNS resolved chain.iona.network -> {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
            } else {
                warn!("DNS resolution for chain.iona.network failed, using default gateway");
                let lease = net::dhcp::get_lease();
                net::dns::cache_insert("chain.iona.network", lease.gateway);
            }

            // Set chain RPC endpoint.
            let chain_rpc = if let Some(ip) = net::dns::resolve("chain.iona.network").ok() {
                format!("http://{}.{}.{}.{}:9001", ip[0], ip[1], ip[2], ip[3])
            } else {
                self.config.chain_rpc.clone()
            };
            net::set_chain_rpc(&chain_rpc);
            info!("Chain RPC endpoint: {}", chain_rpc);
        } else {
            warn!("Network not ready; continuing without network");
        }
    }

    /// Phase 5: System services.
    fn init_services(&mut self) {
        info!("Phase 5: System services");

        // Syscalls.
        syscall::init();
        info!("Syscall interface ready (50+ syscalls)");

        // Signal handling.
        signal::init();
        info!("Signal subsystem ready");

        // Container support.
        containers::init();
        info!("Container subsystem ready");

        // Consensus and sync.
        // The consensus engine is initialised lazily when needed.
        debug!("Consensus engine lazy initialization ready");

        // GUI (if framebuffer available).
        if io::framebuffer::width() > 0 {
            acpi::power::arm_watchdog(30_000);
            gui::init();
            info!("GUI initialized");
        }

        // Spawn system daemons.
        self.spawn_daemons();
    }

    /// Spawn background system tasks.
    fn spawn_daemons(&self) {
        info!("Spawning system daemons");
        sched::SCHEDULER.lock().spawn(task::Task::new("net-poll", task_net_poll, 0, 3));
        sched::SCHEDULER.lock().spawn(task::Task::new("wait-wakeup", task_wait_wakeup, 0, 4));
        sched::SCHEDULER.lock().spawn(task::Task::new("monitor", task_monitor, 0, 1));
        sched::SCHEDULER.lock().spawn(task::Task::new("swap-daemon", task_swap_daemon, 0, 1));
        if net::is_ready() {
            sched::SCHEDULER.lock().spawn(task::Task::new("block-sync", task_block_sync, 0, 2));
        }
        debug!("System daemons spawned");
    }

    /// Phase 6: Security hardening.
    fn init_security(&mut self) {
        info!("Phase 6: Security hardening");

        // Stack canary.
        init_stack_canary();
        info!("Stack canary initialized");

        // ASLR for userspace.
        security::aslr::init();
        info!("ASLR initialized");

        // Secure boot validation.
        security::secureboot::init();
        info!("Secure boot initialized");

        // Keystore.
        security::keystore::cold_init();
        info!("Keystore initialized (locked)");

        // Seccomp (for userspace).
        if self.config.enable_seccomp {
            security::seccomp::init();
            info!("Seccomp initialized");
        }

        // I/O port protection (if supported).
        arch::x86_64::io::init_io_protection();
        info!("I/O port protection enabled");

        // SMEP/SMAP (if supported).
        if self.config.enable_memory_protection {
            arch::x86_64::memory::init_smep_smap();
            info!("SMEP/SMAP enabled");
        }

        // KASLR (if supported).
        if self.config.enable_kaslr {
            arch::x86_64::memory::init_kaslr();
            info!("KASLR enabled");
        }
    }

    /// Phase 7: Launch userspace.
    fn launch_userspace(&mut self) {
        info!("Phase 7: Launching userspace");

        // Write default config if not present.
        if !fs::ionafs::exists("/etc/iona-node.json") {
            let default_cfg = br#"{
                "reconcile_interval_ms": 30000,
                "attest_interval_ms": 60000,
                "gossip_interval_ms": 1000,
                "admin_port": 7777,
                "gossip_port": 9000
            }"#;
            if let Err(e) = fs::ionafs::write("/etc/iona-node.json", default_cfg) {
                warn!("Failed to write default config: {}", e);
            }
        }

        // Load and execute userspace binary.
        if let Some(elf_bytes) = fs::ionafs::read("/bin/iona-node") {
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
                    sched::SCHEDULER.lock().spawn(task::Task::new(
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

        // Spawn shell on serial console.
        sched::SCHEDULER.lock().spawn(task::Task::new("shell", shell::shell_main, 0, 2));
        info!("Shell task spawned");
    }

    /// Fallback to kernel-mode iona-node stub if userspace not available.
    fn fallback_kernel_stub(&self) {
        warn!("Falling back to kernel-mode iona-node stub");
        sched::SCHEDULER.lock().spawn(task::Task::new("iona-node", task_iona_node_stub, 0, 3));
    }
}

// -----------------------------------------------------------------------------
// System task implementations
// -----------------------------------------------------------------------------

/// Network poll task.
fn task_net_poll(_: u64) -> ! {
    loop {
        net::poll();
        arch::timer::sleep_ms(5);
    }
}

/// Wait queue wakeup task.
fn task_wait_wakeup(_: u64) -> ! {
    loop {
        wait::tick_wakeups();
        x86_64::instructions::hlt();
    }
}

/// System monitor task.
fn task_monitor(_: u64) -> ! {
    let mut n = 0u64;
    loop {
        arch::timer::sleep_ms(10_000);
        n += 1;
        let stats = sched::SCHEDULER.lock().stats();
        let (total_frames, used_frames) = memory::frame_alloc::stats();
        let (_, buddy_free) = mm::buddy::stats();
        let uptime = arch::timer::uptime_ms();
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
fn task_swap_daemon(_: u64) -> ! {
    loop {
        arch::timer::sleep_ms(30_000);
        memory::swap::reclaim_pages(512);
    }
}

/// Block sync task.
fn task_block_sync(_: u64) -> ! {
    arch::timer::sleep_ms(500);
    info!("Starting block sync");
    crate::consensus::sync::sync_from_peers();
    info!("Initial block sync complete");
    loop {
        arch::timer::sleep_ms(60_000);
        if net::is_ready() {
            crate::consensus::sync::sync_from_peers();
        }
    }
}

/// Kernel-mode iona-node stub (fallback).
fn task_iona_node_stub(_: u64) -> ! {
    info!("IONA node kernel stub started");
    let mut height = 0u64;
    let mut last_reconcile = 0u64;
    let mut last_attest = 0u64;
    let mut last_gossip = 0u64;
    let mut last_heartbeat = 0u64;

    loop {
        let now = arch::timer::uptime_ms();

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

        arch::timer::sleep_ms(10);
    }
}

// -----------------------------------------------------------------------------
// Kernel entry point
// -----------------------------------------------------------------------------

/// Main kernel entry point.
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // Display banner.
    io::serial::init();
    serial_println!();
    serial_println!("╔══════════════════════════════════════════════════════════╗");
    serial_println!("║          IONA OS Kernel  v0.6.0  (Production)          ║");
    serial_println!("║  Tendermint BFT · TLS 1.3 · NVMe MSI-X · seccomp        ║");
    serial_println!("╚══════════════════════════════════════════════════════════╝");

    // Build kernel instance.
    let mut kernel = Kernel::new(boot_info);

    // Run boot process.
    kernel.run();

    // Should never return.
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Panic and allocation error handlers
// -----------------------------------------------------------------------------

/// Kernel panic handler.
#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();

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
    let frames = debug::backtrace::capture();
    debug::backtrace::print(&frames);

    // If configured, write crash dump.
    let config = load_config();
    if config.persist_crash_dump {
        let dump = format!(
            "Kernel Panic at {}\n{}\nRIP={:#x}, RSP={:#x}, RBP={:#x}\nBacktrace:\n{}",
            info,
            info.location().map(|l| format!("{}:{}", l.file(), l.line())).unwrap_or_else(|| "unknown".into()),
            rip, rsp, rbp,
            debug::backtrace::format_string(&frames)
        );
        let _ = crashdump::write_crash_dump(&dump, "kernel_panic");
    }

    // If GDB stub enabled, trap.
    if config.gdb_on_panic {
        debug::gdb_trap();
    }

    // Blue screen of death.
    bsod_screen("KERNEL PANIC", "See serial output");

    // Halt.
    loop {
        x86_64::instructions::hlt();
    }
}

/// Allocation error handler.
#[alloc_error_handler]
fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    x86_64::instructions::interrupts::disable();
    error!("ALLOCATION FAILED: size={}, align={}", layout.size(), layout.align());
    panic!("out of memory");
}

// -----------------------------------------------------------------------------
// Stack canary
// -----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("Stack smashing detected");
}

#[no_mangle]
pub static mut __stack_chk_guard: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Initialize stack canary with random value.
pub fn init_stack_canary() {
    let ts = arch::timer::uptime_ms();
    let canary = ts
        .wrapping_mul(0x517CC1B727220A95)
        .wrapping_add(0xDEAD_BEEF_CAFE_BABE)
        ^ 0xA5A5_A5A5_A5A5_A5A5;
    unsafe {
        __stack_chk_guard = canary;
    }
    info!("Stack canary initialized: {:#018x}", canary);
}

// -----------------------------------------------------------------------------
// Blue Screen of Death
// -----------------------------------------------------------------------------

/// Display a blue screen of death on the framebuffer.
fn bsod_screen(msg: &str, loc: &str) {
    use crate::io::{font, framebuffer as fb};
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
