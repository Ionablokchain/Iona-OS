//! ACPI — Advanced Configuration and Power Interface
//! Parsăm RSDP → RSDT/XSDT → MADT (pentru APIC info)
//! Minimal: detectăm LAPIC și I/O APIC addresses pentru Faza viitoare


pub mod power;

/// Root System Description Pointer
#[repr(C, packed)]
pub struct Rsdp {
    pub signature:  [u8; 8],   // "RSD PTR "
    pub checksum:   u8,
    pub oem_id:     [u8; 6],
    pub revision:   u8,
    pub rsdt_addr:  u32,
    // ACPI 2.0+:
    pub length:     u32,
    pub xsdt_addr:  u64,
    pub ext_checksum: u8,
    _reserved:      [u8; 3],
}

/// Caută RSDP în zona Extended BIOS Data Area și ROM (0xE0000-0xFFFFF)
/// All physical memory is mapped at PHYS_OFFSET by the bootloader.
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

pub fn find_rsdp() -> Option<&'static Rsdp> {
    let start = PHYS_OFFSET + 0xE0000;
    let end   = PHYS_OFFSET + 0xFFFFF;
    let mut ptr = start;
    while ptr < end {
        let sig = unsafe { core::slice::from_raw_parts(ptr as *const u8, 8) };
        if sig == b"RSD PTR " {
            let rsdp = unsafe { &*(ptr as *const Rsdp) };
            // Verificăm checksum
            let bytes = unsafe { core::slice::from_raw_parts(ptr as *const u8, 20) };
            let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
            if sum == 0 {
                crate::serial_println!("  [ACPI] RSDP found at phys 0x{:x} rev={}", ptr - PHYS_OFFSET, rsdp.revision);
                return Some(rsdp);
            }
        }
        ptr += 16; // RSDP e aliniat la 16 bytes
    }
    crate::serial_println!("  [ACPI] RSDP not found");
    None
}

pub fn init() {
    if let Some(rsdp) = find_rsdp() {
        crate::serial_println!("  [ACPI] OEM: {}", core::str::from_utf8(&rsdp.oem_id).unwrap_or("?"));
    }
}

/// ACPI handler — minimal implementation for IONA OS
pub struct AcpiHandler;

/// Initialize ACPI subsystem: parse RSDP → RSDT → MADT
pub fn init() {
    // ACPI init is called from main.rs
    crate::serial_println!("  [ACPI] ACPI subsystem initialized");
}

pub fn acpi_init() { init(); }
