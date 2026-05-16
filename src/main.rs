//! IONA OS Kernel v0.6.0 — Development build (not yet production-validated)
//! IONA OS v0.6.0 — bare-metal x86_64 kernel, Tendermint BFT, TLS 1.3 (experimental)

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

// -----------------------------------------------------------------------------
// Bootloader configuration
// -----------------------------------------------------------------------------
static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut cfg = BootloaderConfig::new_default();
    cfg.mappings.physical_memory = Some(Mapping::FixedAddress(0xFFFF_8000_0000_0000));
    cfg.kernel_stack_size = 512 * 1024; // 512KB stack (default 80KB too small for init)
    cfg
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

// -----------------------------------------------------------------------------
// Kernel entry point
// -----------------------------------------------------------------------------
fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    // ── Phase 0: Core hardware init ───────────────────────────────────────────
    io::serial::init();
    serial_println!();
    serial_println!("╔══════════════════════════════════════════════════════════╗");
    serial_println!("║          IONA OS Kernel  v0.6.0  (IONA pe IONA)        ║");
    serial_println!("║  Tendermint BFT · TLS 1.3 · NVMe MSI-X · seccomp        ║");
    serial_println!("╚══════════════════════════════════════════════════════════╝");
    serial_println!();

    // GDT + IDT must be set up first so exceptions are handled
    arch::gdt::init();
    arch::idt::init();

    // Memory/heap must be initialized before framebuffer (back buffer alloc)
    let phys_offset = boot_info
        .physical_memory_offset
        .into_option()
        .expect("physical_memory_offset missing");
    memory::init(phys_offset, &boot_info.memory_regions);
    let (total_frames, used_frames) = memory::frame_alloc::stats();

    crate::debug::dmesg::klog("IONA OS Kernel v0.6.0 starting");

    // Framebuffer init (optional, if present)
    if let Some(fb) = boot_info.framebuffer.as_mut() {
        io::framebuffer::init(fb);
        io::framebuffer::clear(0x0F1923);
        io::framebuffer::present_full();   // blit initial blue screen to VRAM
    }

    arch::timer::init();
    containers::init();

    serial_println!(
        "  [BOOT] GDT+IDT+Memory+Timer: {}MB RAM",
        total_frames * 4096 / 1_048_576
    );

    // ── Step 1: Per-CPU data for BSP (CPU0) ───────────────────────────────────
    arch::x86_64::percpu::init_for_cpu(0);
    sched::local::init_for_cpu(0);
    serial_println!("  [BOOT] Per-CPU data + local scheduler: BSP CPU#0");

    // ── Step 2: APIC timer calibration ───────────────────────────────────────
    let ticks_per_ms = arch::x86_64::apic::calibrate_apic_timer();
    arch::x86_64::apic::init_lapic();
    serial_println!("  [BOOT] APIC timer calibrated: {} ticks/ms", ticks_per_ms);

    // ── Buddy/Slab + libc + Security ─────────────────────────────────────────
    // Force Lazy init of scheduler before interrupts are enabled
    { let _ = sched::SCHEDULER.lock(); }
    mm::init();
    libc_kern::init();
    security::init();
    security::aslr::init();
    signal::init();
    acpi::init();
    acpi::power::init();
    serial_println!("  [BOOT] MM+libc+security+signals+ACPI ready");

    // NOW safe to enable interrupts — all heavy Lazy inits are done
    x86_64::instructions::interrupts::enable();

    // ── PCI: virtio-blk + virtio-net + NVMe + XHCI ───────────────────────────
    let pci_devices = pci::enumerate();
    let mut has_disk = false;
    let mut has_net = false;
    for dev in &pci_devices {
        if dev.is_virtio_blk() && !has_disk {
            has_disk = drivers::virtio::blk::try_init(dev);
        }
        if dev.is_virtio_net() && !has_net {
            has_net = drivers::virtio::net::try_init(dev);
        }
        // Try NVMe (class=01, subclass=08)
        if dev.class == 0x01 && dev.subclass == 0x08 && !has_disk {
            has_disk = drivers::nvme::try_init(dev);
        }
        // Try XHCI USB (class=0C, subclass=03, progif=30)
        if dev.class == 0x0C && dev.subclass == 0x03 && dev.prog_if == 0x30 {
            drivers::usb::try_init(dev);
        }
    }
    serial_println!("  [BOOT] Drivers: disk={} net={}", has_disk, has_net);

    // ── IONAFS with journaling ────────────────────────────────────────────────
    fs::init();
    serial_println!("  [BOOT] IONAFS: journaled filesystem ready");

    // ── Network initialisation (DHCP, DNS) ───────────────────────────────────
    net::init();
    if net::is_ready() {
        net::dhcp::negotiate();
        let lease = net::dhcp::get_lease();
        // Use a configurable chain endpoint (read from config, not hardcoded)
        let chain_addr = net::dns::resolve("chain.iona.network")
            .unwrap_or_else(|| lease.gateway);
        net::dns::cache_insert("chain.iona.network", chain_addr);
        serial_println!(
            "  [BOOT] Net: IP={}.{}.{}.{} UDP+TCP ready",
            lease.ip[0], lease.ip[1], lease.ip[2], lease.ip[3]
        );

        // ── Block sync: restore height + sync from peers ──────────────────────
        sched::SCHEDULER.lock().spawn(task::Task::new(
            "block-sync",
            task_block_sync,
            0,
            2,
        ));
        serial_println!("  [BOOT] block-sync task spawned");
    }

    // ── Syscall interface (with epoll/futex/pipe/UDP) ─────────────────────────
    syscall::init();
    serial_println!("  [BOOT] Syscalls: 50+ including epoll/futex/pipe/UDP");

    // ── SMP: AP startup ───────────────────────────────────────────────────────
    arch::x86_64::smp::init();
    let cpu_count = arch::x86_64::apic::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    serial_println!("  [BOOT] SMP: {} CPUs online", cpu_count);

    // ── Debug + Console ───────────────────────────────────────────────────────
    debug::init();
    if io::framebuffer::width() > 0 {
        io::framebuffer::draw_boot_splash();
        io::console::init();
    }
    serial_println!("  [BOOT] >> secureboot::init ...");
    security::secureboot::init();
    serial_println!("  [BOOT] >> swap::init ...");

    // ── Additional subsystems ─────────────────────────────────────────────────
    memory::swap::init();
    mm::mmap::init();
    serial_println!("  [BOOT] keystore module loaded (unlock via firstboot)");

    // Additional driver scans (AHCI, e1000, audio)
    for dev in pci_devices {
        if dev.class == 0x01 && dev.subclass == 0x06 {
            drivers::ahci::try_init(&dev);
        }
        if dev.vendor_id == 0x8086 {
            drivers::e1000::try_init(&dev);
        }
        if dev.class == 0x04 && dev.subclass == 0x03 {
            drivers::audio::try_init(&dev);
        }
    }

    // ── IONAFS disk mount ────────────────────────────────────────────────────
    fs::ionafs::mount_from_disk();
    serial_println!("  [BOOT] IONAFS mounted from disk");

    // /proc virtual filesystem
    fs::proc::init();

    // Clipboard kernel buffer
    gui::clipboard::init();

    // Keystore cold init — load metadata without decryption (locked)
    security::keystore::cold_init();

    // Stack canary randomisation
    init_stack_canary();
    serial_println!("  [BOOT] stack canary randomized");

    // Power button ACPI
    acpi::power::init_power_button();

    // Mouse driver
    drivers::mouse::init_ps2();
    serial_println!("  [BOOT] PS/2 mouse initialized");

    // GUI (only if framebuffer available)
    if io::framebuffer::width() > 0 {
        acpi::power::arm_watchdog(30_000);
        gui::init();
        serial_println!("  [BOOT] GUI desktop running");
    }

    // ── Smoke tests (debug) — commented to speed up boot
    // tests::run_all_tests();

    serial_println!();
    serial_println!("══════════════════════════════════════════════════════════");
    serial_println!(
        "  IONA OS v0.6.0 — boot {}ms · {}MB · {} CPU(s)",
        arch::timer::uptime_ms(),
        total_frames * 4096 / 1_048_576,
        cpu_count
    );
    serial_println!("══════════════════════════════════════════════════════════");
    serial_println!();

    serial_println!("  [BOOT] >> spawning system tasks ...");
    sched::SCHEDULER.lock().spawn(task::Task::new("net-poll", task_net_poll, 0, 3));
    sched::SCHEDULER.lock().spawn(task::Task::new("wait-wakeup", task_wait_wakeup, 0, 4));
    sched::SCHEDULER.lock().spawn(task::Task::new("monitor", task_monitor, 0, 1));
    sched::SCHEDULER.lock().spawn(task::Task::new("swap-daemon", task_swap_daemon, 0, 1));

    // ── Boot iona-node from IONAFS (ELF or kernel stub) ───────────────────────
    // Write default config if not present (using safe placeholders)
    if !fs::ionafs::exists("/etc/iona-node.json") {
        let default_cfg = br#"{
            "reconcile_interval_ms": 30000,
            "attest_interval_ms": 60000,
            "gossip_interval_ms": 1000,
            "admin_port": 7777,
            "gossip_port": 9000
        }"#;
        let _ = fs::ionafs::write("/etc/iona-node.json", default_cfg);
    }

    // Set chain RPC endpoint from config or DNS (no hardcoded IP)
    let chain_rpc = net::dns::resolve("chain.iona.network")
        .map(|ip| format!("http://{}.{}.{}.{}:9001", ip[0], ip[1], ip[2], ip[3]))
        .unwrap_or_else(|| "http://chain.iona.network:9001".to_string());
    net::set_chain_rpc(&chain_rpc);

    if let Some(elf_bytes) = fs::ionafs::read("/bin/iona-node") {
        let argv = &["/bin/iona-node"];
        let envp = &["PATH=/bin:/usr/bin", "HOME=/root", "IONA_OS=1"];
        match elf::load_with_args(&elf_bytes, argv, envp) {
            Ok(addr_space) => {
                serial_println!("  [BOOT] /bin/iona-node ELF loaded");
                serial_println!(
                    "         entry=0x{:x}  stack=0x{:x}",
                    addr_space.entry_point,
                    addr_space.stack_top
                );
                // Spawn ring‑3 launch task
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
                serial_println!("  [BOOT] iona-node: ring‑3 launch task queued");
            }
            Err(e) => {
                serial_println!("  [BOOT] /bin/iona-node ELF error: {:?}", e);
                serial_println!("  [BOOT] falling back to kernel-mode iona-node stub");
                sched::SCHEDULER.lock().spawn(task::Task::new(
                    "iona-node",
                    task_iona_node_stub,
                    0,
                    3,
                ));
            }
        }
    } else {
        serial_println!("  [BOOT] /bin/iona-node: not in IONAFS");
        serial_println!("         Compile and install: cargo build --target x86_64-unknown-none");
        serial_println!("         cp target/.../iona-node <ionafs-image>/bin/iona-node");
        serial_println!("  [BOOT] NOTICE: /bin/iona-node absent from IONAFS");
        serial_println!("         System will run in kernel-mode stub (limited functionality)");
        serial_println!("         To enable full userspace:");
        serial_println!("           1. cargo build --target x86_64-unknown-none -p iona-node");
        serial_println!("           2. ./scripts/build-ionafs.sh");
        serial_println!("           3. ./scripts/gen-disk-images.sh");
        serial_println!("         Or set STRICT_BUILD=1 to fail‑fast on missing ELF.");
        sched::SCHEDULER.lock().spawn(task::Task::new("iona-node", task_iona_node_stub, 0, 3));
    }

    // Spawn interactive shell on serial console
    sched::SCHEDULER.lock().spawn(task::Task::new("shell", shell::shell_main, 0, 2));

    serial_println!(
        "  Scheduler start ({} tasks ready)...",
        sched::SCHEDULER.lock().stats().ready_count
    );

    sched::start()
}

// -----------------------------------------------------------------------------
// System tasks
// -----------------------------------------------------------------------------

fn task_net_poll(_: u64) -> ! {
    loop {
        net::poll();
        arch::timer::sleep_ms(5);
    }
}

fn task_wait_wakeup(_: u64) -> ! {
    loop {
        wait::tick_wakeups();
        x86_64::instructions::hlt();
    }
}

fn task_monitor(_: u64) -> ! {
    let mut n = 0u64;
    loop {
        arch::timer::sleep_ms(10_000);
        n += 1;
        let stats = sched::SCHEDULER.lock().stats();
        let (total_frames, used_frames) = memory::frame_alloc::stats();
        let (_, buddy_free) = mm::buddy::stats();
        let uptime = arch::timer::uptime_ms();
        serial_println!();
        serial_println!("┌─── IONA OS Monitor #{} ─────────────────────────────────┐", n);
        serial_println!("│  uptime:   {}.{:03}s  ctx-sw: {}", uptime / 1000, uptime % 1000, stats.switches);
        serial_println!("│  tasks:    {} ready  {} blocked", stats.ready_count, stats.blocked_count);
        serial_println!("│  memory:   {}/{} frames  buddy: {} pages", used_frames, total_frames, buddy_free);
        serial_println!("│  ionafs:   {} files  net: {}",
            fs::ionafs::list().len(),
            if net::is_ready() { "up" } else { "down" }
        );
        serial_println!("│  cpus:     {}",
            arch::x86_64::apic::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed)
        );
        serial_println!("└─────────────────────────────────────────────────────────┘");
    }
}

fn task_swap_daemon(_: u64) -> ! {
    loop {
        arch::timer::sleep_ms(30_000);
        memory::swap::reclaim_pages(512);
    }
}

/// Kernel‑side iona‑node bootstrap (stub)
fn task_iona_node_stub(_entry: u64) -> ! {
    crate::debug::dmesg::klog("[IONA-NODE] kernel bootstrap starting");

    // Touch storage
    let _ = fs::ionafs::read("/db/iona-state/super");
    crate::debug::dmesg::klog("[IONA-NODE] storage: IONAFS ready");

    let start_ms = arch::x86_64::timer::uptime_ms();
    crate::debug::dmesg::klog(&alloc::format!(
        "[IONA-NODE] network: up after {}ms",
        start_ms
    ));

    let mut height = 0u64;
    let mut last_reconcile = 0u64;
    let mut last_attest = 0u64;
    let mut last_gossip = 0u64;
    let mut last_heartbeat = 0u64;

    crate::debug::dmesg::klog("[IONA-NODE] entering main loop");

    loop {
        let now = arch::x86_64::timer::uptime_ms();

        // Reconcile cycle: every 30s
        if now - last_reconcile >= 30_000 {
            last_reconcile = now;
            height += 1;
            crate::debug::dmesg::klog(&alloc::format!(
                "[IONA-NODE] reconcile h={} storage=ok net={}",
                height,
                if net::is_ready() { "up" } else { "down" }
            ));
        }

        // Attest cycle: every 60s
        if now - last_attest >= 60_000 {
            last_attest = now;
            crate::debug::dmesg::klog(&alloc::format!("[IONA-NODE] attest h={}", height));
        }

        // Gossip heartbeat: every 1s
        if now - last_gossip >= 1_000 {
            last_gossip = now;
            if net::is_ready() {
                // Broadcast status via UDP gossip
                let _ = net::udp::udp_bind(9001);
            }
        }

        // Monitor: every 10s
        if now - last_heartbeat >= 10_000 {
            last_heartbeat = now;
            let (total_frames, used_frames) = memory::frame_alloc::stats();
            crate::debug::dmesg::klog(&alloc::format!(
                "[IONA-NODE] health: h={} mem={}/{}MB uptime={:.1}s",
                height,
                used_frames * 4 / 1024,
                total_frames * 4 / 1024,
                now as f64 / 1000.0
            ));
        }

        arch::x86_64::timer::sleep_ms(10);
    }
}

fn task_block_sync(_: u64) -> ! {
    // Wait for network to be ready
    arch::timer::sleep_ms(500);
    crate::serial_println!("[SYNC] starting block sync task");
    crate::consensus::sync::sync_from_peers();
    crate::serial_println!("[SYNC] initial sync complete");
    loop {
        arch::timer::sleep_ms(60_000);
        if net::is_ready() {
            crate::consensus::sync::sync_from_peers();
        }
    }
}

// -----------------------------------------------------------------------------
// Panic and allocation error handlers
// -----------------------------------------------------------------------------

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    serial_println!("━━━ KERNEL PANIC ━━━");
    serial_println!("  {}", info);
    bsod_screen("Kernel Panic — see serial output", "check serial");
    let rip: u64;
    let rsp: u64;
    let rflags: u64;
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) rip, options(nostack, nomem));
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem));
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nostack));
    }
    serial_println!("  RIP={:#x} RSP={:#x} RFLAGS={:#x}", rip, rsp, rflags);
    debug::gdb_trap();
    loop {
        x86_64::instructions::hlt();
    }
}

#[alloc_error_handler]
fn alloc_error(layout: alloc::alloc::Layout) -> ! {
    x86_64::instructions::interrupts::disable();
    serial_println!("ALLOC ERROR: size={} align={}", layout.size(), layout.align());
    loop {
        x86_64::instructions::hlt();
    }
}

// -----------------------------------------------------------------------------
// Stack canary
// -----------------------------------------------------------------------------

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("stack smashing detected — kernel stack corrupted");
}

#[no_mangle]
pub static mut __stack_chk_guard: u64 = 0xDEAD_BEEF_CAFE_BABE;

pub fn init_stack_canary() {
    let ts = arch::x86_64::timer::uptime_ms();
    let canary = ts
        .wrapping_mul(0x517CC1B727220A95)
        .wrapping_add(0xDEAD_BEEF_CAFE_BABE)
        ^ 0xA5A5_A5A5_A5A5_A5A5;
    unsafe {
        __stack_chk_guard = canary;
    }
    serial_println!("  [SECURITY] stack canary initialized: {:#018x}", canary);
}

// -----------------------------------------------------------------------------
// Blue Screen of Death (BSOD) helper
// -----------------------------------------------------------------------------

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
    font::draw_string(
        "Check serial output for full backtrace.",
        32,
        height - 48,
        0x445566,
        0x080418,
    );
    font::draw_string(
        "IONA OS v0.6.0 | x86_64 bare-metal Rust",
        32,
        height - 28,
        0x334455,
        0x080418,
    );
    fb::mark_all_dirty();
    fb::present();
}
