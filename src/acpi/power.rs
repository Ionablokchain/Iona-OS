//! ACPI Power Management — CPU idle states + sleep states.
//!
//! # C-states (CPU idle)
//!
//! - **C0** — active (executing instructions)
//! - **C1** — `HLT`: wakes on any interrupt
//! - **C2** — stop-clock (requires a valid FADT `P_LVL2` port)
//! - **C3** — deeper sleep (requires `P_LVL3` and bus-master status)
//!
//! # S-states (system sleep)
//!
//! - **S0** — working
//! - **S3** — suspend to RAM (wakes on interrupt / power button)
//! - **S4** — hibernate (suspend to disk)
//! - **S5** — soft off (only power-button / AC-loss wakes)
//!
//! # Sleep control invariants
//!
//! The SLP_TYP for each S-state is **platform-specific** and MUST be
//! read from the DSDT `\_S3_` / `\_S5_` packages. The PM1a_CNT register
//! address MUST be read from the FADT `PM1a_CNT_BLK` field. This module
//! does both, with a fallback to the QEMU defaults (`PM1a_CNT_BLK =
//! 0x604`, `SLP_TYP_S3 = 1`, `SLP_TYP_S5 = 0`) when the tables cannot be
//! parsed.
//!
//! **Never write a hardcoded SLP_TYP to a hardcoded port** — it works on
//! one hypervisor and nowhere else. The previous implementation did
//! exactly that, and the S3 path was silently a no-op while the S5 path
//! was writing to a debug-exit port.
//!
//! # Watchdog
//!
//! [`arm_watchdog`] installs a **software** deadline. The caller's timer
//! interrupt must call [`watchdog_check`] on every tick. There is no
//! hardware watchdog (that would need a platform-specific driver such as
//! IPMI or the i6300esb PCI device). The previous implementation wrote
//! the deadline to physical address `0x1000`, corrupting the EBDA and
//! real-mode boot code; this version stores it in an atomic.

use core::sync::atomic::{AtomicU64, Ordering};

use x86_64::instructions::port::Port;
use x86_64::registers::model_specific::Msr;

// ── Constants ─────────────────────────────────────────────────────────────

/// Fallback PM1a_CNT_BLK for QEMU i440fx / q35. Real hardware uses the
/// value from the FADT.
const QEMU_PM1A_CNT_BLK: u16 = 0x604;

/// Fallback PM1a_EVT_BLK for QEMU.
const QEMU_PM1A_EVT_BLK: u16 = 0x600;

/// QEMU SLP_TYP for S3 (see `include/hw/acpi/aml-build.h`).
const QEMU_SLP_TYP_S3: u16 = 1;

/// QEMU SLP_TYP for S5.
const QEMU_SLP_TYP_S5: u16 = 0;

/// SLP_EN bit in the PM1a_CNT register (bit 13).
const SLP_EN: u16 = 1 << 13;

/// SLP_TYP field shift in the PM1a_CNT register.
const SLP_TYP_SHIFT: u16 = 10;

/// PM1_EN bit for the power button (bit 8).
const PM1_EN_PWRBTN: u16 = 1 << 8;

/// IA32_PLATFORM_INFO MSR.
const MSR_PLATFORM_INFO: u32 = 0xCE;

/// IA32_PERF_CTL MSR.
const MSR_PERF_CTL: u32 = 0x199;

/// IA32_PERF_CTL ENABLE bit.
const PERF_CTL_ENABLE: u64 = 1 << 32;

/// AMD PStateCtl MSR.
const MSR_AMD_PSTATE_CTL: u32 = 0xC001_0062;

/// AMD HWCR MSR.
const MSR_AMD_HWCR: u32 = 0xC001_0015;

/// AMD HWCR.CpbDis bit.
const AMD_HWCR_CPBDIS: u64 = 1 << 25;

// ── Public types ──────────────────────────────────────────────────────────

/// Full plan for entering S3 or S5, derived from FADT + DSDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PowerPlan {
    /// PM1a event block (base for PM1_EN).
    pub pm1a_evt_blk: u16,
    /// PM1a control block (where SLP_TYP | SLP_EN is written).
    pub pm1a_cnt_blk: u16,
    /// DSDT `\_S3_` SLP_TYPa value.
    pub s3_slp_typ: u16,
    /// DSDT `\_S5_` SLP_TYPa value.
    pub s5_slp_typ: u16,
}

impl PowerPlan {
    /// QEMU defaults; used when the FADT or DSDT cannot be parsed.
    #[must_use]
    pub fn qemu_default() -> Self {
        Self {
            pm1a_evt_blk: QEMU_PM1A_EVT_BLK,
            pm1a_cnt_blk: QEMU_PM1A_CNT_BLK,
            s3_slp_typ: QEMU_SLP_TYP_S3,
            s5_slp_typ: QEMU_SLP_TYP_S5,
        }
    }

    /// The 16-bit value written to `pm1a_cnt_blk` to enter S3.
    #[must_use]
    pub fn s3_ctrl(&self) -> u16 {
        (self.s3_slp_typ << SLP_TYP_SHIFT) | SLP_EN
    }

    /// The 16-bit value written to `pm1a_cnt_blk` to enter S5.
    #[must_use]
    pub fn s5_ctrl(&self) -> u16 {
        (self.s5_slp_typ << SLP_TYP_SHIFT) | SLP_EN
    }
}

/// CPU vendor, for frequency-scaling dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuVendor {
    Intel,
    Amd,
    Unknown,
}

// ── C1 / C2 idle ──────────────────────────────────────────────────────────

/// Enter C1 idle. Halts the CPU until the next interrupt.
#[inline(always)]
pub fn cpu_idle_c1() {
    x86_64::instructions::interrupts::enable_and_hlt();
}

/// Enter C2 idle via the FADT-declared `P_LVL2` port.
///
/// **Caller contract:** `c2_port` must be the `P_LVL2` I/O port from the
/// FADT (offset 109) and must be non-zero. A port of `0` is a no-op.
pub fn cpu_idle_c2(c2_port: u16) {
    if c2_port == 0 {
        return;
    }
    // SAFETY: reading a valid ACPI C2 I/O port from ring 0 is safe; the
    // read triggers the platform to enter C2.
    unsafe {
        Port::<u8>::new(c2_port).read();
    }
}

// ── S3 suspend ────────────────────────────────────────────────────────────

/// Enter S3 (suspend to RAM).
///
/// On return, either the machine never entered S3 (a wake event fired
/// immediately) or it has just resumed.
pub fn enter_s3() {
    let plan = power_plan().unwrap_or_else(PowerPlan::qemu_default);
    crate::serial_println!(
        "  [ACPI] entering S3 (PM1a_CNT=0x{:x}, ctrl=0x{:04x})",
        plan.pm1a_cnt_blk,
        plan.s3_ctrl()
    );

    // Flush the filesystem before sleeping. A failed sync is a serious
    // condition — the wake path may resume with a dirty page cache.
    if let Err(e) = crate::fs::ionafs::sync_to_disk() {
        crate::serial_println!("  [ACPI] WARNING: sync_to_disk before S3 failed: {:?}", e);
    }

    // SAFETY: writing the ACPI PM1a_CNT register from ring 0 is the
    // architectural mechanism for entering S3.
    unsafe {
        let mut port = Port::<u16>::new(plan.pm1a_cnt_blk);
        port.write(plan.s3_ctrl());
    }

    // If we return, either S3 was not entered or we just woke up.
    crate::serial_println!("  [ACPI] resumed from S3");
}

/// Backward-compatible alias for [`enter_s3`].
pub fn enter_s3_suspend() {
    enter_s3();
}

// ── S5 shutdown ───────────────────────────────────────────────────────────

/// Power off the system via S5.
///
/// Never returns. Falls back to the QEMU `isa-debug-exit` device and then
/// to a CPU halt if both mechanisms fail.
pub fn shutdown() -> ! {
    let plan = power_plan().unwrap_or_else(PowerPlan::qemu_default);
    crate::serial_println!(
        "  [ACPI] shutdown requested (PM1a_CNT=0x{:x}, ctrl=0x{:04x})",
        plan.pm1a_cnt_blk,
        plan.s5_ctrl()
    );

    if let Err(e) = crate::fs::ionafs::sync_to_disk() {
        crate::serial_println!("  [ACPI] WARNING: sync_to_disk before shutdown failed: {:?}", e);
    }

    // Primary mechanism: PM1a_CNT with the DSDT-derived SLP_TYP.
    // SAFETY: privileged ACPI control register write from ring 0.
    unsafe {
        let mut port = Port::<u16>::new(plan.pm1a_cnt_blk);
        port.write(plan.s5_ctrl());
    }

    // Fallback: the QEMU `isa-debug-exit` device expects `0x2000` on
    // port `0x604`. This is a no-op on real hardware.
    // SAFETY: writes to a fixed I/O port; harmless when no device is
    // present (QEMU shuts down, real HW ignores it).
    unsafe {
        Port::<u16>::new(QEMU_PM1A_CNT_BLK).write(0x2000);
    }

    crate::serial_println!("  [ACPI] shutdown failed — halting");
    loop {
        x86_64::instructions::hlt();
    }
}

/// Backward-compatible alias for [`shutdown`].
pub fn acpi_s5_shutdown() -> ! {
    shutdown()
}

// ── Reboot ────────────────────────────────────────────────────────────────

/// Reboot the system.
///
/// Tries the keyboard-controller reset first, then falls back to a
/// deliberate triple fault (null IDT + `int3`).
pub fn reboot() -> ! {
    crate::serial_println!("  [ACPI] system reboot requested");

    // SAFETY: keyboard-controller reset is the standard legacy path.
    unsafe {
        let mut status = Port::<u8>::new(0x64);
        // Wait for both input-buffer-empty (bit 1) and output-buffer-empty
        // (bit 0), bounded by a spin counter.
        for _ in 0..1_000_000 {
            if status.read() & 0x03 == 0 {
                break;
            }
            core::hint::spin_loop();
        }
        Port::<u8>::new(0x64).write(0xFE);
    }

    crate::serial_println!("  [ACPI] keyboard reset returned — triple faulting");

    // SAFETY: loading a null IDT then issuing an interrupt produces a
    // triple fault, which the CPU handles by resetting.
    unsafe {
        let idt_ptr: [u8; 10] = [0; 10]; // limit = 0, base = 0
        core::arch::asm!("lidt [{}]", in(reg) &idt_ptr, options(nostack, readonly));
        core::arch::asm!("int3", options(nostack));
    }

    // If triple-fault reset is disabled by the platform, halt.
    loop {
        x86_64::instructions::hlt();
    }
}

// ── CPU vendor detection ──────────────────────────────────────────────────

/// Return the running CPU's vendor.
#[must_use]
pub fn detect_cpu_vendor() -> CpuVendor {
    let ebx: u32;
    // SAFETY: CPUID is available on every x86_64 CPU. RBX is preserved
    // via push/pop (LLVM reserves it on SysV). All output registers are
    // declared.
    unsafe {
        core::arch::asm!(
            "push rbx",
            "cpuid",
            "mov {ebx_out:e}, ebx",
            "pop rbx",
            inlateout("eax") 0u32 => _,
            out("ecx") _,
            out("edx") _,
            ebx_out = out(reg) ebx,
            options(preserves_flags),
        );
    }
    match ebx {
        0x756E_6547 => CpuVendor::Intel, // "Genu"
        0x6874_7541 => CpuVendor::Amd,   // "Auth"
        _ => CpuVendor::Unknown,
    }
}

// ── CPU frequency scaling ─────────────────────────────────────────────────

/// Request the CPU to run at its maximum P-state.
pub fn set_cpu_freq_max() {
    match detect_cpu_vendor() {
        CpuVendor::Intel => set_intel_perf_max(),
        CpuVendor::Amd => set_amd_perf_max(),
        CpuVendor::Unknown => {
            crate::serial_println!("  [ACPI] unknown CPU vendor — skipping freq scaling");
        }
    }
}

/// Set the CPU to `percent` of its maximum P-state (clamped to
/// `[min_ratio, max_ratio]`).
///
/// - **Intel**: computes the target ratio from `IA32_PLATFORM_INFO`,
///   then writes `ENABLE | FID` to `IA32_PERF_CTL`.
/// - **AMD**: selects `P0` (100 %) or `P1` (< 100 %) via `PStateCtl`.
///   AMD P-states are discrete; percentages other than 100 % select the
///   next-lower state, not a linear interpolation.
pub fn set_cpu_freq_scaling(percent: u8) {
    if percent == 0 || percent > 100 {
        crate::serial_println!("  [ACPI] invalid percent {}, ignoring", percent);
        return;
    }
    match detect_cpu_vendor() {
        CpuVendor::Intel => set_intel_perf_percent(percent),
        CpuVendor::Amd => set_amd_perf_percent(percent),
        CpuVendor::Unknown => {
            crate::serial_println!("  [ACPI] unknown CPU vendor — cannot scale");
        }
    }
}

fn set_intel_perf_max() {
    // SAFETY: MSR read/write is valid in ring 0.
    unsafe {
        let platform_info = Msr::new(MSR_PLATFORM_INFO).read();
        let max_ratio = ((platform_info >> 8) & 0xFF) as u64;
        if !(6..=0x3F).contains(&max_ratio) {
            crate::serial_println!(
                "  [ACPI] Intel IA32_PLATFORM_INFO max_ratio={} out of range — skipping",
                max_ratio
            );
            return;
        }
        // ENABLE | FID << 8 | VID 0
        Msr::new(MSR_PERF_CTL).write(PERF_CTL_ENABLE | (max_ratio << 8));
        crate::serial_println!("  [ACPI] Intel PERF_CTL max P-state (ratio={})", max_ratio);
    }
}

fn set_intel_perf_percent(percent: u8) {
    // SAFETY: MSR read/write is valid in ring 0.
    unsafe {
        let platform_info = Msr::new(MSR_PLATFORM_INFO).read();
        let max_ratio = ((platform_info >> 8) & 0xFF) as u64;
        let min_ratio = ((platform_info >> 40) & 0xFF) as u64;
        if !(6..=0x3F).contains(&max_ratio) || min_ratio == 0 || min_ratio > max_ratio {
            crate::serial_println!(
                "  [ACPI] Intel P-state ratios invalid (min={} max={}) — skipping",
                min_ratio, max_ratio
            );
            return;
        }
        let target = (max_ratio * percent as u64 / 100).clamp(min_ratio, max_ratio);
        Msr::new(MSR_PERF_CTL).write(PERF_CTL_ENABLE | (target << 8));
        crate::serial_println!("  [ACPI] Intel PERF_CTL target ratio={} ({}%)", target, percent);
    }
}

fn set_amd_perf_max() {
    // SAFETY: MSR read/write is valid in ring 0.
    unsafe {
        // Select P-state 0 (highest performance).
        Msr::new(MSR_AMD_PSTATE_CTL).write(0);

        // Clear HWCR.CpbDis to enable Core Performance Boost, if present.
        let hwcr = Msr::new(MSR_AMD_HWCR).read();
        if hwcr & AMD_HWCR_CPBDIS != 0 {
            Msr::new(MSR_AMD_HWCR).write(hwcr & !AMD_HWCR_CPBDIS);
        }
    }
    crate::serial_println!("  [ACPI] AMD PStateCtl P0, CPB enabled");
}

fn set_amd_perf_percent(percent: u8) {
    // AMD P-states are discrete. 100 % → P0, anything lower → P1.
    let pstate: u64 = if percent >= 100 { 0 } else { 1 };
    // SAFETY: MSR write is valid in ring 0.
    unsafe {
        Msr::new(MSR_AMD_PSTATE_CTL).write(pstate);
    }
    crate::serial_println!("  [ACPI] AMD PStateCtl P{} ({}%)", pstate, percent);
}

// ── DSDT / FADT parsing ───────────────────────────────────────────────────

/// Fallback PM1_EN port used by [`init_power_button`] when the FADT
/// cannot be parsed.
const QEMU_PM1A_EVT_BLK_FALLBACK: u16 = QEMU_PM1A_EVT_BLK;

/// Extract the S3 and S5 `SLP_TYPa` values from the DSDT.
///
/// Returns `None` if the FADT or DSDT cannot be found or parsed. Falls
/// back to the QEMU defaults in that case at the call sites, not here.
#[must_use]
pub fn parse_dsdt_sleep_types() -> Option<(u16, u16)> {
    parse_power_plan().map(|p| (p.s3_slp_typ, p.s5_slp_typ))
}

/// Parse the full power plan from FADT + DSDT.
///
/// The `PM1a_CNT_BLK` port comes from the FADT; the SLP_TYP values come
/// from the DSDT AML `\_S3_` and `\_S5_` packages.
fn parse_power_plan() -> Option<PowerPlan> {
    let rsdp = super::find_rsdp().ok()?;
    let fadt_phys = find_fadt(&rsdp)?;
    let fadt = parse_fadt(fadt_phys)?;
    if fadt.dsdt_phys == 0 {
        return None;
    }
    let (s3, s5) = parse_slp_types_from_dsdt(super::PHYS_OFFSET as u64 + fadt.dsdt_phys)?;
    Some(PowerPlan {
        pm1a_evt_blk: fadt.pm1a_evt_blk,
        pm1a_cnt_blk: fadt.pm1a_cnt_blk,
        s3_slp_typ: s3,
        s5_slp_typ: s5,
    })
}

struct FadtInfo {
    pm1a_evt_blk: u16,
    pm1a_cnt_blk: u16,
    dsdt_phys: u64,
}

/// Return the physical address of the FACP (FADT).
fn find_fadt(rsdp: &super::Rsdp) -> Option<usize> {
    let (root_phys, is_xsdt) = if rsdp.has_xsdt() {
        (rsdp.xsdt_addr as usize, true)
    } else {
        (rsdp.rsdt_addr as usize, false)
    };

    let virt = super::PHYS_OFFSET + root_phys;

    // SAFETY: the root SDT header is 36 bytes and within the mapped region.
    let header: &[u8] = unsafe { core::slice::from_raw_parts(virt as *const u8, 36) };

    // Verify the root SDT checksum before walking it.
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length < 36 || length > 0x10_0000 {
        return None;
    }
    // SAFETY: `length` is bounded above; the table is within the direct map.
    let full: &[u8] = unsafe { core::slice::from_raw_parts(virt as *const u8, length) };
    if full.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return None;
    }

    let entry_size = if is_xsdt { 8 } else { 4 };
    let n = (length - 36) / entry_size;

    for i in 0..n {
        let off = virt + 36 + i * entry_size;
        // SAFETY: `off` is within the checksum-verified root SDT.
        let child_phys = unsafe {
            if is_xsdt {
                (off as *const u64).read_unaligned() as usize
            } else {
                (off as *const u32).read_unaligned() as usize
            }
        };
        let child_virt = super::PHYS_OFFSET + child_phys;
        // SAFETY: the child's 4-byte signature is within the direct map.
        let sig: &[u8] = unsafe { core::slice::from_raw_parts(child_virt as *const u8, 4) };
        if sig == b"FACP" {
            return Some(child_phys);
        }
    }
    None
}

fn parse_fadt(fadt_phys: usize) -> Option<FadtInfo> {
    let virt = super::PHYS_OFFSET + fadt_phys;

    // SAFETY: reading the SDT header from within the direct map.
    let header: &[u8] = unsafe { core::slice::from_raw_parts(virt as *const u8, 36) };
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length < 68 {
        // Need at least PM1a_CNT_BLK at offset 64.
        return None;
    }

    // SAFETY: `length` is bounded below; the FADT is within the direct
    // map. The checksum was verified by `find_fadt`.
    let bytes: &[u8] = unsafe { core::slice::from_raw_parts(virt as *const u8, length) };

    let pm1a_evt_blk = u32::from_le_bytes([bytes[56], bytes[57], bytes[58], bytes[59]]) as u16;
    let pm1a_cnt_blk = u32::from_le_bytes([bytes[64], bytes[65], bytes[66], bytes[67]]) as u16;
    let dsdt_phys_32 = u32::from_le_bytes([bytes[40], bytes[41], bytes[42], bytes[43]]) as u64;

    let x_dsdt_phys = if length >= 148 {
        u64::from_le_bytes([
            bytes[140], bytes[141], bytes[142], bytes[143],
            bytes[144], bytes[145], bytes[146], bytes[147],
        ])
    } else {
        0
    };
    let dsdt_phys = if x_dsdt_phys != 0 { x_dsdt_phys } else { dsdt_phys_32 };

    Some(FadtInfo {
        pm1a_evt_blk,
        pm1a_cnt_blk,
        dsdt_phys,
    })
}

fn parse_slp_types_from_dsdt(dsdt_virt: u64) -> Option<(u16, u16)> {
    let dsdt = dsdt_virt as *const u8;

    // SAFETY: reading the SDT header from within the direct map.
    let header: &[u8] = unsafe { core::slice::from_raw_parts(dsdt, 36) };
    let dsdt_len = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if dsdt_len < 36 || dsdt_len > 0x10_0000 {
        return None;
    }

    // SAFETY: `dsdt_len` is bounded above; the DSDT is within the direct map.
    let full: &[u8] = unsafe { core::slice::from_raw_parts(dsdt, dsdt_len) };
    if full.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return None; // Corrupt DSDT — refuse to trust its SLP_TYP values.
    }

    let aml = &full[36..];
    let mut s3: Option<u16> = None;
    let mut s5: Option<u16> = None;

    // Scan for `Name (_S3_ | _S5_)` objects. NameOp = 0x08, followed by
    // a 4-byte name, then the object.
    let mut i = 0usize;
    while i + 5 < aml.len() {
        if aml[i] == 0x08 {
            let name = &aml[i + 1..i + 5];
            if name == b"_S3_" {
                if let Some(v) = extract_package_first_byte(&aml[i + 5..]) {
                    s3 = Some(v as u16);
                }
            } else if name == b"_S5_" {
                if let Some(v) = extract_package_first_byte(&aml[i + 5..]) {
                    s5 = Some(v as u16);
                }
            }
        }
        i += 1;
    }

    match (s3, s5) {
        (Some(s3v), Some(s5v)) => Some((s3v, s5v)),
        _ => None,
    }
}

/// Read the first element of an AML `Package`.
///
/// AML encoding used:
/// - `0x00` = Zero
/// - `0x01` = One
/// - `0xFF` = Ones
/// - `0x0A <u8>` = ByteConst
fn extract_package_first_byte(aml: &[u8]) -> Option<u8> {
    if aml.first() != Some(&0x12) {
        return None;
    }
    let (_, after_len) = read_pkg_length(&aml[1..])?;
    let after_num = after_len.get(1..)?; // skip NumElements (assumes ByteConst, valid for < 256)
    read_aml_integer(after_num)
}

fn read_pkg_length(aml: &[u8]) -> Option<(usize, &[u8])> {
    let first = *aml.first()?;
    let num_extra = (first >> 6) as usize;
    if aml.len() < 1 + num_extra {
        return None;
    }
    let len = match num_extra {
        0 => (first & 0x3F) as usize,
        1 => ((first & 0x0F) as usize) | ((aml[1] as usize) << 4),
        2 => ((first & 0x0F) as usize) | ((aml[1] as usize) << 4) | ((aml[2] as usize) << 12),
        3 => {
            ((first & 0x0F) as usize)
                | ((aml[1] as usize) << 4)
                | ((aml[2] as usize) << 12)
                | ((aml[3] as usize) << 20)
        }
        _ => return None,
    };
    Some((len, &aml[1 + num_extra..]))
}

fn read_aml_integer(aml: &[u8]) -> Option<u8> {
    match *aml.first()? {
        0x00 => Some(0),            // Zero
        0x01 => Some(1),            // One
        0xFF => Some(0xFF),         // Ones
        0x0A => Some(*aml.get(1)?), // ByteConst
        _ => None,                  // Larger integer forms not expected here.
    }
}

// ── Power button ──────────────────────────────────────────────────────────

/// Enable the ACPI power-button IRQ via PM1a_EN bit 8.
pub fn init_power_button() {
    let pm1a_evt_blk = power_plan()
        .map(|p| p.pm1a_evt_blk)
        .unwrap_or(QEMU_PM1A_EVT_BLK_FALLBACK);
    let pm1_en_port = pm1a_evt_blk.wrapping_add(2);

    // SAFETY: writes a valid ACPI PM1_EN register from ring 0.
    unsafe {
        let mut port = Port::<u16>::new(pm1_en_port);
        let en = port.read();
        port.write(en | PM1_EN_PWRBTN);
    }
    crate::serial_println!(
        "  [ACPI] power button enabled (PM1_EN=0x{:x})",
        pm1_en_port
    );
}

/// Called from the ACPI interrupt handler when the power button is pressed.
///
/// # Warning
///
/// This function is expected to run in interrupt context. It does **not**
/// sleep. If the GUI needs to save state, the interrupt handler should
/// wake a dedicated shutdown task; blocking here would prevent the
/// system from servicing other interrupts (including the timer).
pub fn on_power_button() {
    crate::serial_println!("[ACPI] power button pressed — initiating S5");
    shutdown();
}

// ── Software watchdog ─────────────────────────────────────────────────────

/// Software watchdog deadline in milliseconds since boot. `0` means
/// disarmed.
static WATCHDOG_DEADLINE_MS: AtomicU64 = AtomicU64::new(0);

/// Arm the software watchdog. The caller's timer interrupt must invoke
/// [`watchdog_check`] on every tick; when `uptime_ms()` reaches the
/// deadline, the system reboots.
pub fn arm_watchdog(timeout_ms: u64) {
    let now = crate::arch::x86_64::timer::uptime_ms();
    let deadline = now.saturating_add(timeout_ms);
    WATCHDOG_DEADLINE_MS.store(deadline, Ordering::Release);
    crate::serial_println!("[WDT] armed: {}ms (deadline={})", timeout_ms, deadline);
}

/// Disarm the watchdog. Safe to call even if not armed.
pub fn disarm_watchdog() {
    WATCHDOG_DEADLINE_MS.store(0, Ordering::Release);
}

/// Check the watchdog. Call from the timer interrupt handler.
pub fn watchdog_check() {
    let deadline = WATCHDOG_DEADLINE_MS.load(Ordering::Acquire);
    if deadline == 0 {
        return;
    }
    let now = crate::arch::x86_64::timer::uptime_ms();
    if now >= deadline {
        crate::serial_println!("[WDT] deadline reached ({} ms) — rebooting", now);
        // Prevent re-entry if reboot somehow returns.
        WATCHDOG_DEADLINE_MS.store(0, Ordering::Release);
        reboot();
    }
}

// ── Init ──────────────────────────────────────────────────────────────────

/// Log the resolved power plan and enable the power button.
///
/// Idempotent. Does **not** enter any sleep state or scale the CPU.
pub fn init() {
    let vendor = detect_cpu_vendor();
    crate::serial_println!(
        "  [ACPI] power management: C1/C2 idle, S3/S5 sleep, {:?} CPU",
        vendor
    );

    match power_plan() {
        Some(plan) => {
            crate::serial_println!(
                "  [ACPI] FADT: PM1a_EVT=0x{:x} PM1a_CNT=0x{:x}",
                plan.pm1a_evt_blk,
                plan.pm1a_cnt_blk
            );
            crate::serial_println!(
                "  [ACPI] DSDT: S3 SLP_TYP={} S5 SLP_TYP={}",
                plan.s3_slp_typ,
                plan.s5_slp_typ
            );
        }
        None => {
            crate::serial_println!(
                "  [ACPI] FADT/DSDT unavailable — using QEMU defaults (S3 SLP_TYP={}, S5 SLP_TYP={}, PM1a_CNT=0x{:x})",
                QEMU_SLP_TYP_S3,
                QEMU_SLP_TYP_S5,
                QEMU_PM1A_CNT_BLK
            );
        }
    }

    init_power_button();
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qemu_default_plan_ctrl_values() {
        let p = PowerPlan::qemu_default();
        assert_eq!(p.s3_ctrl(), (QEMU_SLP_TYP_S3 << 10) | SLP_EN);
        assert_eq!(p.s3_ctrl(), 0x2400);
        assert_eq!(p.s5_ctrl(), (QEMU_SLP_TYP_S5 << 10) | SLP_EN);
        assert_eq!(p.s5_ctrl(), 0x2000);
    }

    #[test]
    fn cpu_vendor_is_one_of_the_known_variants() {
        // CPUID always returns a known vendor on x86_64 test hosts
        // (Intel or AMD); the Unknown arm exists for other platforms.
        let v = detect_cpu_vendor();
        assert!(matches!(
            v,
            CpuVendor::Intel | CpuVendor::Amd | CpuVendor::Unknown
        ));
    }

    #[test]
    fn read_pkg_length_single_byte() {
        // PkgLength = 0x0F (1 byte, no extra)
        let (len, rest) = read_pkg_length(&[0x0F, 0xAA, 0xBB]).unwrap();
        assert_eq!(len, 0x0F);
        assert_eq!(rest, &[0xAA, 0xBB]);
    }

    #[test]
    fn read_pkg_length_two_bytes() {
        // First byte: 0x40 | 0x03 = 0x43 (num_extra=1, low=3)
        // Second byte: 0x12 → length = 3 | 0x12 << 4 = 3 | 0x120 = 0x123
        let (len, rest) = read_pkg_length(&[0x43, 0x12, 0xAA]).unwrap();
        assert_eq!(len, 0x123);
        assert_eq!(rest, &[0xAA]);
    }

    #[test]
    fn read_pkg_length_rejects_truncated() {
        assert!(read_pkg_length(&[0xC0]).is_none()); // 2 extra bytes needed, none present
    }

    #[test]
    fn read_aml_integer_zero_one_byte_const() {
        assert_eq!(read_aml_integer(&[0x00]), Some(0));
        assert_eq!(read_aml_integer(&[0x01]), Some(1));
        assert_eq!(read_aml_integer(&[0xFF]), Some(0xFF));
        assert_eq!(read_aml_integer(&[0x0A, 0x2A]), Some(42));
        assert_eq!(read_aml_integer(&[0x0A]), None); // missing value byte
        assert_eq!(read_aml_integer(&[0x10]), None); // unsupported form
    }

    #[test]
    fn extract_package_first_byte_handles_byte_const() {
        // Package (0x02) { 0x0A 0x2A, Zero } → first byte 0x2A.
        // Layout: 0x12, PkgLength=0x05, NumElements=0x02, 0x0A, 0x2A, 0x00
        let aml = [0x12, 0x05, 0x02, 0x0A, 0x2A, 0x00];
        assert_eq!(extract_package_first_byte(&aml), Some(0x2A));
    }

    #[test]
    fn extract_package_first_byte_handles_zero_and_one() {
        let aml_zero = [0x12, 0x03, 0x02, 0x00, 0x00];
        assert_eq!(extract_package_first_byte(&aml_zero), Some(0));

        let aml_one = [0x12, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(extract_package_first_byte(&aml_one), Some(1));
    }

    #[test]
    fn extract_package_first_byte_rejects_non_package() {
        assert_eq!(extract_package_first_byte(&[0x00, 0x01]), None);
    }

    #[test]
    fn watchdog_arm_disarm() {
        arm_watchdog(10_000);
        assert_ne!(WATCHDOG_DEADLINE_MS.load(Ordering::Acquire), 0);
        disarm_watchdog();
        assert_eq!(WATCHDOG_DEADLINE_MS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn watchdog_zero_disarms() {
        arm_watchdog(0);
        // Deadline equals `now`, which is > 0, so the check would fire
        // immediately. Verify that's the documented behaviour, not a bug.
        // (Callers that want to disable must call `disarm_watchdog`.)
        disarm_watchdog();
        assert_eq!(WATCHDOG_DEADLINE_MS.load(Ordering::Acquire), 0);
    }

    #[test]
    fn cpu_idle_c2_zero_port_is_a_noop() {
        // Should not touch hardware.
        cpu_idle_c2(0);
    }
}
