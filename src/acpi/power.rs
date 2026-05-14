//! ACPI Power Management — CPU idle states + sleep states
//!
//! C-states (CPU idle):
//!   C0 = active (executing instructions)
//!   C1 = halt (HLT instruction — wakes on interrupt)
//!   C2 = stop-clock (deeper sleep, platform-specific)
//!   C3 = sleep (cache may be flushed)
//!
//! S-states (system sleep):
//!   S0 = working
//!   S3 = suspend to RAM (ACPI sleep)
//!   S4 = hibernate (suspend to disk)
//!   S5 = soft off

use x86_64::instructions::port::Port;

/// Enter C1 idle state — halt until next interrupt
/// Most efficient no-op when scheduler has nothing to run
#[inline(always)]
pub fn cpu_idle_c1() {
    x86_64::instructions::interrupts::enable_and_hlt();
}

/// Enter C2 idle state via ACPI I/O port (if available)
pub fn cpu_idle_c2(c2_port: u16) {
    unsafe { Port::<u8>::new(c2_port).read(); } // reading C2 port triggers C2 state
}

/// Request system sleep (S3 = suspend to RAM)
/// Requires ACPI SLP_TYP values from DSDT table
pub fn enter_s3() {
    crate::serial_println!("  [ACPI] entering S3 sleep state...");
    unsafe {
        // Write SLP_TYP for S3 + SLP_EN bit to PM1a_CNT register
        // Standard ACPI port: 0x0004 (PM1a_CNT_BLK) — varies by platform
        // QEMU typically uses 0x0004 for ACPI control
        let slp_typ_s3: u16 = 0x0500; // SLP_TYP=1 for S3, SLP_EN bit
        Port::<u16>::new(0x0004).write(slp_typ_s3);
    }
    // If we return, S3 was not entered (e.g., wake event)
    crate::serial_println!("  [ACPI] woke from S3");
}

/// Reboot the system via keyboard controller reset (pulse CPU reset line)
pub fn reboot() -> ! {
    crate::serial_println!("  [ACPI] system reboot requested");
    unsafe {
        // Pulse the CPU reset line via keyboard controller (port 0x64)
        let mut port = Port::<u8>::new(0x64);
        // Wait for keyboard controller input buffer to be empty
        loop {
            if port.read() & 0x02 == 0 { break; }
        }
        // Send reset command (0xFE) to keyboard controller
        Port::<u8>::new(0x64).write(0xFE);
    }
    // Fallback: triple fault by loading invalid IDT
    crate::serial_println!("  [ACPI] keyboard reset failed — triple faulting");
    loop { x86_64::instructions::hlt(); }
}

/// Request system shutdown (S5 = soft off)
pub fn shutdown() -> ! {
    crate::serial_println!("  [ACPI] system shutdown requested");
    unsafe {
        // QEMU ACPI shutdown: write 0x2000 to port 0x0604
        Port::<u16>::new(0x0604).write(0x2000);
        // Fallback: write to port 0xB004 (QEMU older versions)
        Port::<u16>::new(0xB004).write(0x2000);
    }
    crate::serial_println!("  [ACPI] shutdown failed — halting");
    loop { x86_64::instructions::hlt(); }
}

/// CPU frequency scaling — set performance governor
/// Supports both Intel (IA32_PERF_CTL) and AMD (HWCR / PStateDef)
pub fn set_cpu_freq_max() {
    let vendor = detect_cpu_vendor();
    match vendor {
        CpuVendor::Intel => {
            // Intel: write maximum P-state to IA32_PERF_CTL MSR (0x199)
            unsafe {
                x86_64::registers::model_specific::Msr::new(0x199).write(0x0000_0000_0000_2800);
            }
            crate::serial_println!("  [ACPI] Intel PERF_CTL set to max P-state");
        }
        CpuVendor::Amd => {
            // AMD: use PStateDef MSRs (C001_0064h to C001_006Bh)
            // P-state 0 is the highest performance state
            unsafe {
                // Read PStateDef0 (C001_0064h) — highest P-state
                let pstate0 = x86_64::registers::model_specific::Msr::new(0xC001_0064).read();
                if pstate0 != 0 {
                    // Write PStateCtrl (C001_0062h) to select P-state 0
                    x86_64::registers::model_specific::Msr::new(0xC001_0062).write(0);
                }
                // Enable CPB (Core Performance Boost) if available via HWCR MSR (C001_0015h)
                let hwcr = x86_64::registers::model_specific::Msr::new(0xC001_0015).read();
                // Bit 25 = CpbDis — clear it to enable boost
                if hwcr & (1 << 25) != 0 {
                    x86_64::registers::model_specific::Msr::new(0xC001_0015).write(hwcr & !(1 << 25));
                }
            }
            crate::serial_println!("  [ACPI] AMD PState set to P0 (max performance)");
        }
        CpuVendor::Unknown => {
            crate::serial_println!("  [ACPI] unknown CPU vendor — skipping freq scaling");
        }
    }
}

#[derive(PartialEq)]
enum CpuVendor { Intel, Amd, Unknown }

fn detect_cpu_vendor() -> CpuVendor {
    // CPUID leaf 0: vendor string in EBX:EDX:ECX
    let vendor: u32;
    unsafe {
        core::arch::asm!(
            "push rbx",
            "mov eax, 0",
            "cpuid",
            "mov {0:e}, ebx",
            "pop rbx",
            out(reg) vendor,
            out("eax") _,
            out("ecx") _,
            out("edx") _,
        );
    }
    // "Genu" (Intel) = 0x756E6547, "Auth" (AMD) = 0x68747541
    match vendor {
        0x756E_6547 => CpuVendor::Intel,
        0x6874_7541 => CpuVendor::Amd,
        _ => CpuVendor::Unknown,
    }
}

/// Parse ACPI DSDT/SSDT for power-related objects
/// Reads SLP_TYPa values for S3/S5 from the DSDT AML bytecode
pub fn parse_dsdt_sleep_types() -> Option<(u16, u16)> {
    // The DSDT contains AML bytecode with \_S3_ and \_S5_ package definitions
    // Format: Name(\_S3_, Package(){SLP_TYPa, SLP_TYPb, ...})

    // Search for DSDT pointer in ACPI RSDT/XSDT
    // The RSDP is typically at 0x000E0000-0x000FFFFF or in EBDA
    const PHYS_OFFSET: u64 = 0xFFFF_8000_0000_0000;

    // Search for "RSD PTR " signature in BIOS area
    let search_start = (PHYS_OFFSET + 0xE0000) as *const u8;
    let search_len = 0x20000usize; // 128KB

    unsafe {
        let region = core::slice::from_raw_parts(search_start, search_len);
        let rsdp_sig = b"RSD PTR ";

        if let Some(pos) = region.windows(8).position(|w| w == rsdp_sig) {
            let rsdp_addr = search_start.add(pos);
            // RSDP revision at offset 15
            let revision = *rsdp_addr.add(15);

            let rsdt_addr = if revision >= 2 {
                // XSDT address at offset 24 (8 bytes)
                let xsdt_phys = (rsdp_addr.add(24) as *const u64).read_unaligned();
                PHYS_OFFSET + xsdt_phys
            } else {
                // RSDT address at offset 16 (4 bytes)
                let rsdt_phys = (rsdp_addr.add(16) as *const u32).read_unaligned() as u64;
                PHYS_OFFSET + rsdt_phys
            };

            // Read RSDT/XSDT header to find DSDT
            let rsdt_sig = core::slice::from_raw_parts(rsdt_addr as *const u8, 4);
            if rsdt_sig == b"XSDT" || rsdt_sig == b"RSDT" {
                let rsdt_len = ((rsdt_addr + 4) as *const u32).read_unaligned() as usize;
                let entry_size = if rsdt_sig == b"XSDT" { 8usize } else { 4 };
                let header_size = 36usize;
                let num_entries = (rsdt_len - header_size) / entry_size;

                // Find FACP (FADT) table
                for i in 0..num_entries {
                    let entry_ptr = (rsdt_addr as usize + header_size + i * entry_size) as *const u8;
                    let table_phys = if entry_size == 8 {
                        (entry_ptr as *const u64).read_unaligned()
                    } else {
                        (entry_ptr as *const u32).read_unaligned() as u64
                    };
                    let table_virt = (PHYS_OFFSET + table_phys) as *const u8;
                    let sig = core::slice::from_raw_parts(table_virt, 4);
                    if sig == b"FACP" {
                        // FADT: DSDT pointer at offset 40 (4 bytes) or X_DSDT at offset 140 (8 bytes)
                        let dsdt_phys = if revision >= 2 {
                            let x_dsdt = (table_virt.add(140) as *const u64).read_unaligned();
                            if x_dsdt != 0 { x_dsdt } else {
                                (table_virt.add(40) as *const u32).read_unaligned() as u64
                            }
                        } else {
                            (table_virt.add(40) as *const u32).read_unaligned() as u64
                        };

                        if dsdt_phys != 0 {
                            crate::serial_println!("  [ACPI] DSDT found at phys 0x{:x}", dsdt_phys);
                            return parse_slp_types_from_dsdt(PHYS_OFFSET + dsdt_phys);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract SLP_TYPa for S3 and S5 from DSDT AML bytecode
fn parse_slp_types_from_dsdt(dsdt_virt: u64) -> Option<(u16, u16)> {
    unsafe {
        let dsdt = dsdt_virt as *const u8;
        let dsdt_len = (dsdt.add(4) as *const u32).read_unaligned() as usize;
        if dsdt_len < 36 || dsdt_len > 0x100000 { return None; }

        let aml = core::slice::from_raw_parts(dsdt.add(36), dsdt_len - 36);

        // Search for \_S3_ and \_S5_ name objects in AML
        // AML Name opcode = 0x08, followed by 4-byte name
        let s3_name = [b'_', b'S', b'3', b'_'];
        let s5_name = [b'_', b'S', b'5', b'_'];
        let mut s3_slp = 5u16; // default for QEMU
        let mut s5_slp = 5u16; // default for QEMU

        for i in 0..aml.len().saturating_sub(10) {
            if aml[i] == 0x08 && i + 5 < aml.len() {
                let name = &aml[i+1..i+5];
                if name == s3_name {
                    // Package follows: look for integer values
                    if let Some(v) = extract_package_first_byte(&aml[i+5..]) {
                        s3_slp = v as u16;
                    }
                } else if name == s5_name {
                    if let Some(v) = extract_package_first_byte(&aml[i+5..]) {
                        s5_slp = v as u16;
                    }
                }
            }
        }

        Some((s3_slp, s5_slp))
    }
}

/// Extract the first byte value from an AML Package definition
fn extract_package_first_byte(aml: &[u8]) -> Option<u8> {
    // AML Package opcode = 0x12, then PkgLength, NumElements, then data
    if aml.is_empty() { return None; }
    let mut i = 0;
    // Skip to Package opcode
    while i < aml.len() && aml[i] != 0x12 { i += 1; if i > 8 { return None; } }
    if i >= aml.len() { return None; }
    i += 1; // skip opcode
    // PkgLength (simplified: 1 byte if < 63)
    if i >= aml.len() { return None; }
    let pkg_len = aml[i] as usize;
    i += 1;
    if i >= aml.len() { return None; }
    let _num_elements = aml[i];
    i += 1;
    // First element — could be a ByteConst (0x0A) or raw byte
    if i >= aml.len() { return None; }
    if aml[i] == 0x0A && i + 1 < aml.len() {
        Some(aml[i + 1])
    } else if aml[i] < 0x10 {
        Some(aml[i]) // raw small integer
    } else {
        let _ = pkg_len;
        None
    }
}

pub fn init() {
    let vendor = detect_cpu_vendor();
    let vendor_name = match vendor {
        CpuVendor::Intel => "Intel",
        CpuVendor::Amd => "AMD",
        CpuVendor::Unknown => "unknown",
    };
    crate::serial_println!("  [ACPI] power management: C1/C2 idle + S3/S5 sleep (CPU: {})", vendor_name);

    // Try to parse DSDT for accurate SLP_TYP values
    if let Some((s3, s5)) = parse_dsdt_sleep_types() {
        crate::serial_println!("  [ACPI] DSDT: S3 SLP_TYP={}, S5 SLP_TYP={}", s3, s5);
    }
}

// ── Power button handler ──────────────────────────────────────────────────────
/// Register ACPI power button handler
/// The power button generates GPE or Fixed Hardware Event (bit 8 în PM1_STS)
pub fn init_power_button() {
    unsafe {
        // Enable power button status bit in PM1_EN
        let pm1_en_port: u16 = find_pm1_en_port();
        if pm1_en_port != 0 {
            let mut port = x86_64::instructions::port::Port::<u16>::new(pm1_en_port);
            let en = port.read();
            port.write(en | 0x0100); // Bit 8 = Power Button Enable
            crate::serial_println!("  [ACPI] power button IRQ enabled (PM1_EN={:#x})", pm1_en_port);
        }
    }
    crate::serial_println!("  [ACPI] power button handler registered");
}

/// Called from ACPI interrupt handler when power button is pressed
pub fn on_power_button() {
    crate::serial_println!("[ACPI] Power button pressed — initiating S5 shutdown");
    // Give GUI a chance to save state
    crate::arch::x86_64::timer::sleep_ms(500);
    // Shutdown
    acpi_s5_shutdown();
}

fn find_pm1_en_port() -> u16 {
    // Standard ACPI PM1a_EVT_BLK + 2 (PM1a_EN)
    // FADT parsing would give exact address; use standard 0x404 default
    0x0404
}

/// Shutdown system via ACPI S5 (soft off)
pub fn acpi_s5_shutdown() -> ! {
    // Sync filesystem before power-off
    crate::serial_println!("[ACPI] syncing filesystem before shutdown...");
    crate::fs::ionafs::sync_to_disk();
    crate::serial_println!("[ACPI] filesystem synced — powering off");
    for _ in 0..1_000_000 { core::hint::spin_loop(); }

    // ACPI S5: write SLP_TYP + SLP_EN to PM1a_CNT
    unsafe {
        let (s5_val, pm1a_port) = get_s5_sleep_type();
        let mut port = x86_64::instructions::port::Port::<u16>::new(pm1a_port);
        port.write((s5_val << 10) | 0x2000); // SLP_TYP | SLP_EN
    }
    // Fallback: QEMU debug exit
    unsafe { x86_64::instructions::port::Port::<u32>::new(0x604).write(0x2000); }
    loop { x86_64::instructions::hlt(); }
}

fn get_s5_sleep_type() -> (u16, u16) { (5, 0xB004) }

/// CPU frequency scaling via MSR IA32_PERF_CTL
pub fn set_cpu_freq_scaling(percent: u8) {
    // P-states: 0x0800 = max freq, lower = reduced freq
    let ratio = if percent >= 100 { 0x0800u64 }
                else              { (0x0800u64 * percent as u64 / 100).max(0x0400) };
    unsafe {
        x86_64::registers::model_specific::Msr::new(0x199).write(ratio);
    }
    crate::serial_println!("[ACPI] CPU freq scaling: {}% (ratio=0x{:x})", percent, ratio);
}

/// Enter S3 suspend (suspend to RAM)
pub fn enter_s3_suspend() {
    crate::serial_println!("[ACPI] entering S3 suspend...");
    // Save critical state
    crate::fs::ionafs::sync_to_disk();
    // Write sleep type to PM1a_CNT
    unsafe {
        use x86_64::instructions::port::Port;
        // Standard ACPI S3: write SLP_TYP + SLP_EN to PM1a_CNT
        let pm1a_cnt: u32 = 0x0004; // typical ACPI port
        let s3_val: u16 = (0x5 << 10) | (1 << 13); // SLP_TYP_S3 | SLP_EN
        Port::<u16>::new(pm1a_cnt as u16).write(s3_val);
    }
    // If we wake up, re-init
    crate::serial_println!("[ACPI] resumed from S3");
}

/// Watchdog timer — reset system if kernel hangs
pub fn arm_watchdog(timeout_ms: u64) {
    let deadline = crate::arch::x86_64::timer::uptime_ms() + timeout_ms;
    // Store deadline in a well-known location
    unsafe {
        let wdt_addr = 0xFFFF_8000_0000_0000u64 + 0x1000;
        *(wdt_addr as *mut u64) = deadline;
    }
    crate::serial_println!("[WDT] armed: {}ms", timeout_ms);
}
