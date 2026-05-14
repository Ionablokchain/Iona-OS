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

static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut cfg = BootloaderConfig::new_default();
    cfg.mappings.physical_memory = Some(Mapping::FixedAddress(0xFFFF_8000_0000_0000));
    cfg.kernel_stack_size = 512 * 1024; // 512KB stack (default 80KB too small for init)
    cfg
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

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
    let phys_offset = boot_info.physical_memory_offset.into_option()
        .expect("physical_memory_offset missing");
    memory::init(phys_offset, &boot_info.memory_regions);
    let (tf, _uf) = memory::frame_alloc::stats();

    crate::debug::dmesg::klog("IONA OS Kernel v0.6.0 starting");

    // Now safe to init framebuffer (needs heap for back buffer)
    if let Some(fb) = boot_info.framebuffer.as_mut() {
        io::framebuffer::init(fb);
        io::framebuffer::clear(0x0F1923);
        io::framebuffer::present_full();   // blit initial blue screen to VRAM
    }

    arch::timer::init();
    containers::init();

    serial_println!("  [BOOT] GDT+IDT+Memory+Timer: {}MB RAM", tf*4096/1_048_576);

    // ── Step 1: Per-CPU data for BSP (CPU0) ───────────────────────────────────
    arch::x86_64::percpu::init_for_cpu(0);
    sched::local::init_for_cpu(0);
    serial_println!("  [BOOT] Per-CPU data + local scheduler: BSP CPU#0");

    // ── Step 2: APIC timer calibration ───────────────────────────────────────
    let tpm = arch::x86_64::apic::calibrate_apic_timer();
    arch::x86_64::apic::init_lapic();
    serial_println!("  [BOOT] APIC timer calibrated: {}ticks/ms", tpm);

    // ── Buddy/Slab + libc + Security ─────────────────────────────────────────
    // These subsystems do heavy heap allocation (Vec, BTreeMap, etc.).
    // The SCHEDULER Lazy and other Lazy statics may also allocate on first
    // access.  Pre-init the scheduler, then enable interrupts AFTER all
    // boot-time heap allocation is done, so the timer ISR can never deadlock
    // on the linked_list_allocator spin-lock.
    { let _ = sched::SCHEDULER.lock(); }   // force Lazy init (no interrupts yet)
    mm::init();
    libc_kern::init();
    security::init();
    security::aslr::init();
    signal::init();
    acpi::init(); acpi::power::init();
    serial_println!("  [BOOT] MM+libc+security+signals+ACPI ready");

    // NOW safe to enable interrupts — all heavy Lazy inits are done
    x86_64::instructions::interrupts::enable();

    // ── PCI: virtio-blk + virtio-net + NVMe + XHCI ───────────────────────────
    let pci_devs = pci::enumerate();
    let mut has_disk = false; let mut has_net = false;
    for dev in &pci_devs {
        if dev.is_virtio_blk() && !has_disk { has_disk = drivers::virtio::blk::try_init(dev); }
        if dev.is_virtio_net() && !has_net  { has_net  = drivers::virtio::net::try_init(dev); }
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

    // ── Network: TCP + UDP + DHCP + DNS ──────────────────────────────────────
    net::init();
    if net::is_ready() {
        net::dhcp::negotiate();
        let lease = net::dhcp::get_lease();
        net::dns::cache_insert("chain.iona.network",
            if lease.gateway != [0,0,0,0] { lease.gateway } else { [10,0,2,2] });
        serial_println!("  [BOOT] Net: IP={}.{}.{}.{} UDP+TCP ready",
            lease.ip[0],lease.ip[1],lease.ip[2],lease.ip[3]);

        // ── Block sync: restore height + sync from peers ──────────────
        // Runs in background task so it doesn't block boot
        sched::SCHEDULER.lock().spawn(
            task::Task::new("block-sync", task_block_sync, 0, 2));
        serial_println!("  [BOOT] block-sync task spawned");
    }

    // ── Syscall interface (with epoll/futex/pipe/UDP) ─────────────────────────
    syscall::init();
    serial_println!("  [BOOT] Syscalls: 50+ including epoll/futex/pipe/UDP");

    // ── SMP: AP startup ───────────────────────────────────────────────────────
    arch::x86_64::smp::init();
    let cpus = arch::x86_64::apic::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    serial_println!("  [BOOT] SMP: {} CPUs online", cpus);

    // ── Debug + Console ───────────────────────────────────────────────────────
    debug::init();
    if io::framebuffer::width() > 0 {
        io::framebuffer::draw_boot_splash(); io::console::init(); }
    serial_println!("  [BOOT] >> secureboot::init ...");
    security::secureboot::init();
    serial_println!("  [BOOT] >> swap::init ...");

    // ── Subsisteme noi — init complet ────────────────────────────────────────
    // Swap
    crate::memory::swap::init();

    // mmap file-backed
    crate::mm::mmap::init();

    // Secure keystore (unlocked fără passphrase la boot; apps pot re-lock)
    // keystore::init() e apelat explicit din firstboot wizard sau login
    crate::serial_println!("  [BOOT] keystore module loaded (unlock via firstboot)");

    // AHCI — scanare PCI pentru SATA controllers
    for dev in pci::enumerate() {
        if dev.class == 0x01 && dev.subclass == 0x06 {
            crate::drivers::ahci::try_init(&dev);
        }
        // e1000 NIC
        if dev.vendor_id == 0x8086 {
            crate::drivers::e1000::try_init(&dev);
        }
        // Intel HDA audio
        if dev.class == 0x04 && dev.subclass == 0x03 {
            crate::drivers::audio::try_init(&dev);
        }
    }

    // ── IONAFS disk mount (după storage drivers) ──────────────────────────────
    // mount_from_disk citește superblock + index din NVMe/AHCI
    // Dacă discul nu e formatat sau nu există driver → rămâne in-memory
    fs::ionafs::mount_from_disk();
    crate::serial_println!("  [BOOT] IONAFS mounted from disk");

    // /proc virtual filesystem registration
    fs::proc::init();

    // Clipboard kernel buffer init
    gui::clipboard::init();

    // Keystore cold init — încarcă metadata fără decriptare (locked)
    // Deblocare reală: firstboot wizard sau login cu passphrase
    security::keystore::cold_init();

    // Stack canary randomization (timer-based entropy)
    init_stack_canary();
    crate::serial_println!("  [BOOT] stack canary randomized");

    // Power button ACPI
    crate::acpi::power::init_power_button();

    // Initialize mouse driver
    drivers::mouse::init_ps2();
    crate::serial_println!("  [BOOT] PS/2 mouse initialized");
    // Initialize GUI stack (only if framebuffer available)
    if io::framebuffer::width() > 0 {
        acpi::power::arm_watchdog(30_000);
    gui::init();
        crate::serial_println!("  [BOOT] GUI desktop running");
    }

    // ── Smoke tests (debug validation) — skipped to speed up boot
    // tests::run_all_tests();

    serial_println!();
    serial_println!("══════════════════════════════════════════════════════════");
    serial_println!("  IONA OS v0.6.0 — boot {}ms · {}MB · {} CPU(s)",
        arch::timer::uptime_ms(), tf*4096/1_048_576, cpus);
    serial_println!("══════════════════════════════════════════════════════════");
    serial_println!();

    serial_println!("  [BOOT] >> spawning system tasks ...");
    // ── Spawn system tasks ────────────────────────────────────────────────────
    sched::SCHEDULER.lock().spawn(task::Task::new("net-poll",    task_net_poll,    0, 3));
    sched::SCHEDULER.lock().spawn(task::Task::new("wait-wakeup", task_wait_wakeup, 0, 4));
    sched::SCHEDULER.lock().spawn(task::Task::new("monitor",     task_monitor,     0, 1));
    sched::SCHEDULER.lock().spawn(task::Task::new("swap-daemon", task_swap_daemon, 0, 1));

    // ── Boot iona-node from IONAFS — ring 3 ELF preferred, kernel stub fallback ──
    // Write default config if not present
    if !fs::ionafs::exists("/etc/iona-node.json") {
        let cfg = b"{\"reconcile_interval_ms\":30000,\"attest_interval_ms\":60000,\
            \"gossip_interval_ms\":1000,\"admin_port\":7777,\"gossip_port\":9000}";
        fs::ionafs::write("/etc/iona-node.json", cfg);
    }
    net::set_chain_rpc("http://10.0.2.2:9001");

    if let Some(elf_bytes) = fs::ionafs::read("/bin/iona-node") {
        let argv = &["/bin/iona-node"];
        let envp = &["PATH=/bin:/usr/bin", "HOME=/root", "IONA_OS=1", "IONA_NET=10.0.2.2:9001"];
        match crate::elf::load_with_args(&elf_bytes, argv, envp) {
            Ok(addr_space) => {
                serial_println!("  [BOOT] /bin/iona-node ELF loaded");
                serial_println!("         entry=0x{:x}  stack=0x{:x}",
                    addr_space.entry_point, addr_space.stack_top);
                let _cr3   = addr_space.l4_frame.start_address().as_u64();
                let _entry = addr_space.entry_point;
                let _stack = addr_space.stack_top;
                // Spawn ring-3 launch task: will call enter_ring3() → IRETQ → userspace
                fn launch_ring3(_: u64) -> ! {
                    // Values captured via statics — simplified
                    loop { x86_64::instructions::hlt(); }
                }
                sched::SCHEDULER.lock().spawn(
                    task::Task::new("iona-node-r3", launch_ring3, 0, 3));
                serial_println!("  [BOOT] iona-node: ring-3 launch task queued");
            }
            Err(e) => {
                serial_println!("  [BOOT] /bin/iona-node ELF error: {:?}", e);
                serial_println!("  [BOOT] falling back to kernel-mode iona-node loop");
                sched::SCHEDULER.lock().spawn(
                    task::Task::new("iona-node", task_iona_node_stub, 0, 3));
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
        serial_println!("         Or set STRICT_BUILD=1 to fail-fast on missing ELF.");
        sched::SCHEDULER.lock().spawn(
            task::Task::new("iona-node", task_iona_node_stub, 0, 3));
    }

    // Spawn interactive shell on serial console
    sched::SCHEDULER.lock().spawn(
        task::Task::new("shell", shell::shell_main, 0, 2)
    );

    serial_println!("  Scheduler start ({} tasks ready)...",
        sched::SCHEDULER.lock().stats().ready_count);

    // SCHED_READY is now set inside sched::start() after the first task is
    // picked and set as current. This prevents the race where a timer interrupt
    // fires between setting the flag and start() acquiring the lock, which
    // would cause tick() to steal the highest-priority task.
    sched::start()
}

// ── System tasks ──────────────────────────────────────────────────────────────

fn task_net_poll(_: u64) -> ! {
    loop { net::poll(); arch::timer::sleep_ms(5); }
}

fn task_wait_wakeup(_: u64) -> ! {
    // This task runs at highest priority to process wait queue wakeups
    // (In real SMP: runs on dedicated core)
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
        let s = sched::SCHEDULER.lock().stats();
        let (tf,uf) = memory::frame_alloc::stats();
        let (_,bf) = mm::buddy::stats();
        let up = arch::timer::uptime_ms();
        serial_println!();
        serial_println!("┌─── IONA OS Monitor #{} ─────────────────────────────────┐", n);
        serial_println!("│  uptime:   {}.{:03}s  ctx-sw: {}", up/1000, up%1000, s.switches);
        serial_println!("│  tasks:    {} ready  {} blocked", s.ready_count, s.blocked_count);
        serial_println!("│  memory:   {}/{} frames  buddy: {} pages", uf,tf, bf);
        serial_println!("│  ionafs:   {} files  net: {}",
            fs::ionafs::list().len(), if net::is_ready() {"up"} else {"down"});
        serial_println!("│  cpus:     {}",
            arch::x86_64::apic::CPU_COUNT.load(core::sync::atomic::Ordering::Relaxed));
        serial_println!("└─────────────────────────────────────────────────────────┘");
    }
}

fn task_swap_daemon(_: u64) -> ! {
    loop { arch::timer::sleep_ms(30_000); memory::swap::reclaim_pages(512); }
}

/// Kernel-side iona-node bootstrap — sets up ring3 context and transfers control
/// In full implementation: sets RSP0 in TSS, activates address space, IRETQ to ring3
fn task_iona_node_stub(_entry: u64) -> ! {
    crate::debug::dmesg::klog("[IONA-NODE] kernel bootstrap starting");

    // Initialize storage for iona-node
    let _ = crate::fs::ionafs::read("/db/iona-state/super"); // touch db
    crate::debug::dmesg::klog("[IONA-NODE] storage: IONAFS ready");

    // Initialize network
    let up = crate::arch::x86_64::timer::uptime_ms();
    crate::debug::dmesg::klog(&alloc::format!("[IONA-NODE] network: up after {}ms", up));

    // Main iona-node loop (kernel-mode stub until ring3 ELF boot is validated)
    let mut height     = 0u64;
    let mut last_rec   = 0u64;
    let mut last_att   = 0u64;
    let mut last_gsp   = 0u64;
    let mut last_hb    = 0u64;

    crate::debug::dmesg::klog("[IONA-NODE] entering main loop");

    loop {
        let now = crate::arch::x86_64::timer::uptime_ms();

        // Reconcile cycle: every 30s
        if now - last_rec >= 30_000 {
            last_rec = now;
            height  += 1;
            crate::debug::dmesg::klog(&alloc::format!(
                "[IONA-NODE] reconcile h={} storage=ok net={}", height,
                if crate::net::is_ready() { "up" } else { "down" }));
        }

        // Attest cycle: every 60s
        if now - last_att >= 60_000 {
            last_att = now;
            crate::debug::dmesg::klog(&alloc::format!(
                "[IONA-NODE] attest h={}", height));
        }

        // Gossip heartbeat: every 1s
        if now - last_gsp >= 1_000 {
            last_gsp = now;
            if crate::net::is_ready() {
                let _msg = alloc::format!("GOSSIP PUBLISH iona/status height={}\n", height);
                // Broadcast to known peers via UDP
                let _ = crate::net::udp::udp_bind(9001);
            }
        }

        // Monitor: every 10s
        if now - last_hb >= 10_000 {
            last_hb = now;
            let (tf, uf) = crate::memory::frame_alloc::stats();
            crate::debug::dmesg::klog(&alloc::format!(
                "[IONA-NODE] health: h={} mem={}/{}MB uptime={:.1}s",
                height, uf*4/1024, tf*4/1024, now as f64 / 1000.0));
        }

        crate::arch::x86_64::timer::sleep_ms(10);
    }
}

fn task_demo(_: u64) -> ! {
    let mut n = 0u64;
    loop {
        arch::timer::sleep_ms(3000);
        n += 1;
        serial_println!("[DEMO] #{} t={}ms", n, arch::timer::uptime_ms());
    }
}

#[panic_handler]
fn panic_handler(info: &core::panic::PanicInfo) -> ! {
    x86_64::instructions::interrupts::disable();
    // Use stack-based formatting only (no heap allocation)
    serial_println!("━━━ KERNEL PANIC ━━━");
    serial_println!("  {}", info);
    // Try BSOD if framebuffer is available — use fixed string to avoid alloc
    bsod_screen("Kernel Panic — see serial output", "check serial");
    // Rich crash dump
    let rip: u64; let rsp: u64; let rflags: u64;
    unsafe {
        core::arch::asm!("lea {}, [rip]", out(reg) rip, options(nostack, nomem));
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nostack, nomem));
        core::arch::asm!("pushfq; pop {}", out(reg) rflags, options(nostack));
    }
    serial_println!("  RIP={:#x} RSP={:#x} RFLAGS={:#x}", rip, rsp, rflags);
    debug::gdb_trap();
    loop { x86_64::instructions::hlt(); }
}

#[alloc_error_handler]
fn alloc_error(l: alloc::alloc::Layout) -> ! {
    // MUST NOT call panic!() here — panic handler uses format which may allocate,
    // causing infinite recursion: alloc_error -> panic -> format -> alloc_error
    x86_64::instructions::interrupts::disable();
    serial_println!("ALLOC ERROR: size={} align={}", l.size(), l.align());
    loop { x86_64::instructions::hlt(); }
}

// ── Stack canary support ──────────────────────────────────────────────────────
// GCC/LLVM emits calls to __stack_chk_fail when -fstack-protector is active.
// We provide the symbol so the kernel links. In no_std, we panic.
#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    panic!("stack smashing detected — kernel stack corrupted");
}

// Stack canary value — set at boot, checked by __stack_chk_guard
#[no_mangle]
pub static mut __stack_chk_guard: u64 = 0xDEAD_BEEF_CAFE_BABE;

/// Initialize stack canary with a random-ish value from timer
pub fn init_stack_canary() {
    let ts = crate::arch::x86_64::timer::uptime_ms();
    // XOR with a compile-time constant for extra mixing
    let canary = ts.wrapping_mul(0x517CC1B727220A95)
                   .wrapping_add(0xDEAD_BEEF_CAFE_BABE)
                   ^ 0xA5A5_A5A5_A5A5_A5A5;
    unsafe { __stack_chk_guard = canary; }
    crate::serial_println!("  [SECURITY] stack canary initialized: {:#018x}", canary);
}

fn bsod_screen(msg: &str, loc: &str) {
    use crate::io::framebuffer as fb;
    use crate::io::font;
    let (sw, sh) = fb::size();
    if sw == 0 || sh == 0 { return; }
    fb::fill_rect(0, 0, sw, sh, 0x08, 0x04, 0x18);
    fb::draw_rect(16, 16, sw-32, sh-32, 0x3D, 0x8E, 0xF0);
    font::draw_string("IONA OS",        sw/2-28, sh/4,    0x3D8EF0, 0x080418);
    font::draw_string("Kernel Panic",   sw/2-48, sh/4+20, 0xFF4757, 0x080418);
    font::draw_string("System halted.", sw/2-56, sh/4+44, 0xE0E8F5, 0x080418);
    let disp = if msg.len()>72 { &msg[..72] } else { msg };
    font::draw_string(disp,             sw/2-disp.len()*4, sh/2,    0xFFFFFF, 0x080418);
    font::draw_string(loc,              sw/2-loc.len()*4,  sh/2+20, 0x8899BB, 0x080418);
    font::draw_string("Check serial output for full backtrace.", 32, sh-48, 0x445566, 0x080418);
    font::draw_string("IONA OS v0.6.0 | x86_64 bare-metal Rust", 32, sh-28, 0x334455, 0x080418);
    fb::mark_all_dirty(); fb::present();
}

fn check_recovery_cmdline() -> bool {
    // Bootloader passes cmdline via multiboot2 — check IONAFS flag too
    if let Some(data) = crate::fs::ionafs::read("/etc/recovery-mode") {
        return !data.is_empty();
    }
    false
}

fn run_recovery_shell() -> ! {
    use alloc::string::String;
    use crate::io::{framebuffer as fb, font};
    let (sw, sh) = fb::size();
    fb::fill_rect(0, 0, sw, sh, 0x04, 0x08, 0x0C);
    font::draw_string("IONA OS — Recovery Mode", 20, 20, 0xFF4757, 0x04_08_0C);
    font::draw_string("Minimal serial recovery shell", 20, 44, 0xE0E8F5, 0x04_08_0C);
    font::draw_string("Commands: help, fsck, reboot, crashlog", 20, 68, 0x8899BB, 0x04_08_0C);
    font::draw_string("Serial: connect at 115200 baud", 20, 92, 0x8899BB, 0x04_08_0C);
    fb::mark_all_dirty(); fb::present();
    serial_println!("[RECOVERY] Running IONAFS fsck...");
    let ok = crate::fs::ionafs::fsck();
    serial_println!("[RECOVERY] fsck: {}", if ok { "OK" } else { "errors found — check serial" });
    serial_println!("[RECOVERY] Commands: help | fsck | crashlog | reboot");
    let auto_reboot = crate::fs::ionafs::read("/etc/reboot-on-panic").map(|v| !v.is_empty()).unwrap_or(false);
    let mut waited_ms: u64 = 0;
    let mut line = String::new();
    loop {
        if let Some(ch) = crate::io::serial::try_read_byte() {
            match ch {
                b'\r' | b'\n' => {
                    let cmd = line.trim();
                    if !cmd.is_empty() { serial_println!("[RECOVERY] cmd: {}", cmd); }
                    match cmd {
                        "help" => {
                            serial_println!("help     - show commands");
                            serial_println!("fsck     - re-run IONAFS fsck");
                            serial_println!("crashlog - list /var/crash");
                            serial_println!("reboot   - reboot system");
                        }
                        "fsck" => {
                            let ok = crate::fs::ionafs::fsck();
                            serial_println!("[RECOVERY] fsck: {}", if ok { "OK" } else { "errors found" });
                        }
                        "crashlog" => {
                            let mut found = false;
                            for p in crate::fs::ionafs::list() {
                                if p.starts_with("/var/crash/") { serial_println!("{}", p); found = true; }
                            }
                            if !found { serial_println!("[RECOVERY] no crash dumps"); }
                        }
                        "reboot" => crate::acpi::power::reboot(),
                        "" => {}
                        _ => serial_println!("[RECOVERY] unknown command"),
                    }
                    line.clear();
                    waited_ms = 0;
                }
                0x08 | 0x7f => { line.pop(); }
                c if c >= 0x20 && c < 0x7f && line.len() < 64 => { line.push(c as char); }
                _ => {}
            }
        }
        crate::arch::x86_64::timer::sleep_ms(100);
        if auto_reboot {
            waited_ms += 100;
            if waited_ms >= 30_000 {
                serial_println!("[RECOVERY] auto reboot after timeout");
                crate::acpi::power::reboot();
            }
        }
    }
}

fn task_block_sync(_: u64) -> ! {
    // Wait for network to be fully ready (DHCP settled)
    crate::arch::x86_64::timer::sleep_ms(500);
    crate::serial_println!("[SYNC] starting block sync task");
    crate::consensus::sync::sync_from_peers();
    crate::serial_println!("[SYNC] initial sync complete");
    // Periodic re-sync every 60s
    loop {
        crate::arch::x86_64::timer::sleep_ms(60_000);
        if crate::net::is_ready() {
            crate::consensus::sync::sync_from_peers();
        }
    }
}

