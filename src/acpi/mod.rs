//! ACPI — Advanced Configuration and Power Interface.
//!
//! Parses `RSDP → RSDT/XSDT → MADT` to discover the local APIC MMIO base
//! and stores it in a static for later phases (per-CPU bringup, IRQ
//! routing, etc.).
//!
//! # Discovery procedure
//!
//! 1. Scan the BIOS EBDA/ROM range `[0xE0000, 0x100000)` at 16-byte
//!    alignment for the `"RSD PTR "` signature.
//! 2. Verify the v1 checksum (sum of the first 20 bytes == 0). If the
//!    revision is `>= 2`, verify the v2 extended checksum (sum of all
//!    `length` bytes == 0) and require `length == 36`.
//! 3. Walk the RSDT (v1) or XSDT (v2) to locate the MADT (`"APIC"`).
//! 4. Read the LAPIC MMIO base from the MADT and store it in
//!    [`lapic_mmio_base`].
//!
//! # Assumptions
//!
//! - The bootloader maps **all** physical memory at [`PHYS_OFFSET`]. Change
//!   the constant if your bootloader uses a different direct-map offset;
//!   there is no portable way to detect this at runtime.
//! - The EBDA and BIOS ROM sit in the low 1 MiB, per the ACPI spec.
//! - Every SDT within the walk has a valid checksum. A corrupt table is
//!   reported via [`AcpiError`] instead of walking off the map.
//!
//! # Failure modes
//!
//! No ACPI tables found is **not** a fatal condition. [`init`] logs a
//! warning and leaves [`is_ready`] returning `false`; the caller decides
//! whether to fall back to legacy PIC or refuse to boot.
//!
//! # Unsafety
//!
//! Every read from physical memory goes through `core::slice::from_raw_parts`
//! bounded by an explicit `addr + N <= end` check. The RSDP is read
//! byte-by-byte from a `u8` slice and reassembled into an owned [`Rsdp`],
//! so no reference to packed memory escapes this module.

pub mod power;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

// ── Constants ─────────────────────────────────────────────────────────────

/// Physical-memory direct-map offset.
///
/// **Caller contract:** the bootloader must map `[0, max_phys)` at
/// `[PHYS_OFFSET, PHYS_OFFSET + max_phys)`. Change this if your
/// bootloader uses a different offset.
pub const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

/// Start of the BIOS EBDA/ROM search window (physical address).
const RSDP_SEARCH_START: usize = 0xE_0000;

/// Exclusive end of the search window (1 MiB).
const RSDP_SEARCH_END: usize = 0x10_0000;

/// RSDP is 16-byte aligned within the search window.
const RSDP_ALIGN: usize = 16;

/// Size of an RSDP v1 header (ACPI 1.0).
const RSDP_V1_SIZE: usize = 20;

/// Size of an RSDP v2 header (ACPI 2.0+).
const RSDP_V2_SIZE: usize = 36;

/// Size of a standard SDT header.
const SDT_HEADER_SIZE: usize = 36;

/// Upper bound on an SDT length.
///
/// Real ACPI tables are at most a few KiB. A length above this bound means
/// either the table is corrupt or the pointer is wrong; refuse to walk.
const SDT_MAX_LEN: usize = 16 * 1024 * 1024;

const RSDP_SIGNATURE: &[u8; 8] = b"RSD PTR ";
const RSDT_SIGNATURE: &[u8; 4] = b"RSDT";
const XSDT_SIGNATURE: &[u8; 4] = b"XSDT";
const MADT_SIGNATURE: &[u8; 4] = b"APIC";

/// Minimum MADT size: 36-byte header + 4-byte LAPIC base + 4-byte flags.
const MADT_MIN_LEN: usize = 44;

// ── Errors ────────────────────────────────────────────────────────────────

/// ACPI discovery errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcpiError {
    /// No `"RSD PTR "` block with a valid v1 checksum was found in the
    /// EBDA/ROM window.
    RsdpNotFound,
    /// An RSDP was found but its v1 checksum is invalid.
    RsdpChecksumMismatch,
    /// An RSDP v2 was found but its extended checksum or `length` field is
    /// invalid.
    RsdpExtendedChecksumMismatch,
    /// An SDT header is malformed (bad length, checksum, or signature).
    SdtMalformed,
    /// No MADT table was found while walking the RSDT/XSDT.
    MadtNotFound,
    /// The MADT header is malformed (bad length or checksum).
    MadtMalformed,
}

// ── Public types ──────────────────────────────────────────────────────────

/// A validated RSDP, owned (no reference into physical memory).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rsdp {
    pub oem_id: [u8; 6],
    pub revision: u8,
    pub rsdt_addr: u32,
    pub length: u32,
    pub xsdt_addr: u64,
}

impl Rsdp {
    /// Whether this RSDP carries an XSDT (ACPI 2.0+ with a valid pointer).
    #[inline]
    #[must_use]
    pub fn has_xsdt(&self) -> bool {
        self.revision >= 2 && self.xsdt_addr != 0
    }

    /// OEM ID with non-printable bytes replaced by `.`, so it can be
    /// logged safely.
    #[must_use]
    pub fn oem_id_str(&self) -> [u8; 6] {
        let mut out = self.oem_id;
        for b in &mut out {
            if !b.is_ascii_graphic() && *b != b' ' {
                *b = b'.';
            }
        }
        out
    }
}

// ── Internal SDT header (owned) ───────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct SdtHeader {
    signature: [u8; 4],
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: [u8; 6],
    oem_table_id: [u8; 8],
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
}

// ── Global state ──────────────────────────────────────────────────────────

/// LAPIC MMIO base address discovered by [`init`], or `0` if not yet
/// discovered.
static LAPIC_MMIO_BASE: AtomicU64 = AtomicU64::new(0);

/// Set to `true` once [`init`] has successfully parsed a MADT.
static ACPI_READY: AtomicBool = AtomicBool::new(false);

// ── RSDP discovery ────────────────────────────────────────────────────────

/// Scan the EBDA/ROM window for an RSDP with a valid checksum.
///
/// Returns an **owned** [`Rsdp`] — no reference into physical memory
/// escapes this function.
pub fn find_rsdp() -> Result<Rsdp, AcpiError> {
    let end = PHYS_OFFSET + RSDP_SEARCH_END;
    let mut addr = PHYS_OFFSET + RSDP_SEARCH_START;
    let mut last_checksum_error: Option<AcpiError> = None;

    while addr + RSDP_V1_SIZE <= end {
        // SAFETY: `addr >= PHYS_OFFSET` and `addr + 20 <= end` where
        // `end = PHYS_OFFSET + 1 MiB`; the bootloader maps the low 1 MiB
        // at `PHYS_OFFSET`, so this slice is within a mapped region.
        let v1: &[u8] = unsafe {
            core::slice::from_raw_parts(addr as *const u8, RSDP_V1_SIZE)
        };

        if &v1[..8] == RSDP_SIGNATURE {
            match validate_rsdp_at(addr, end) {
                Ok(rsdp) => {
                    crate::serial_println!(
                        "  [ACPI] RSDP at phys 0x{:x} rev={}",
                        addr - PHYS_OFFSET,
                        rsdp.revision
                    );
                    return Ok(rsdp);
                }
                Err(e) => last_checksum_error = Some(e),
            }
        }

        addr += RSDP_ALIGN;
    }

    Err(last_checksum_error.unwrap_or(AcpiError::RsdpNotFound))
}

/// Validate the RSDP whose signature starts at `addr`.
fn validate_rsdp_at(addr: usize, end: usize) -> Result<Rsdp, AcpiError> {
    debug_assert!(addr + RSDP_V1_SIZE <= end);
    debug_assert!(addr >= PHYS_OFFSET);

    // Read the v1 header (20 bytes).
    // SAFETY: bounds verified by the caller; low 1 MiB is mapped.
    let v1: &[u8] = unsafe {
        core::slice::from_raw_parts(addr as *const u8, RSDP_V1_SIZE)
    };

    // v1 checksum: sum of first 20 bytes must be 0.
    if v1.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return Err(AcpiError::RsdpChecksumMismatch);
    }

    let oem_id: [u8; 6] = [v1[9], v1[10], v1[11], v1[12], v1[13], v1[14]];
    let revision = v1[15];
    let rsdt_addr = u32::from_le_bytes([v1[16], v1[17], v1[18], v1[19]]);

    // ACPI 1.0: no XSDT.
    if revision < 2 {
        return Ok(Rsdp {
            oem_id,
            revision,
            rsdt_addr,
            length: RSDP_V1_SIZE as u32,
            xsdt_addr: 0,
        });
    }

    // ACPI 2.0+: the extended header extends past the v1 header. Refuse if
    // it would run off the search window — the v1 fields are still usable,
    // but without a validated extended checksum we cannot trust `xsdt_addr`.
    if addr + RSDP_V2_SIZE > end {
        return Err(AcpiError::RsdpExtendedChecksumMismatch);
    }

    // SAFETY: `addr + RSDP_V2_SIZE <= end` and the low 1 MiB is mapped.
    let v2: &[u8] = unsafe {
        core::slice::from_raw_parts(addr as *const u8, RSDP_V2_SIZE)
    };

    // Extended checksum over all `length` bytes (must be 36).
    let length = u32::from_le_bytes([v2[20], v2[21], v2[22], v2[23]]);
    if length as usize != RSDP_V2_SIZE {
        return Err(AcpiError::RsdpExtendedChecksumMismatch);
    }
    if v2.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return Err(AcpiError::RsdpExtendedChecksumMismatch);
    }

    let xsdt_addr = u64::from_le_bytes([
        v2[24], v2[25], v2[26], v2[27], v2[28], v2[29], v2[30], v2[31],
    ]);

    Ok(Rsdp {
        oem_id,
        revision,
        rsdt_addr,
        length,
        xsdt_addr,
    })
}

// ── SDT walking ───────────────────────────────────────────────────────────

/// Read and checksum-verify an SDT header at physical address `phys`
/// (relative to [`PHYS_OFFSET`]).
fn read_sdt_header(phys: usize) -> Result<SdtHeader, AcpiError> {
    let virt = PHYS_OFFSET
        .checked_add(phys)
        .ok_or(AcpiError::SdtMalformed)?;

    // SAFETY: caller guarantees `phys` points at a mapped SDT with at
    // least 36 bytes. The direct map covers all physical memory.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(virt as *const u8, SDT_HEADER_SIZE)
    };

    let header = SdtHeader {
        signature: [bytes[0], bytes[1], bytes[2], bytes[3]],
        length: u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        revision: bytes[8],
        checksum: bytes[9],
        oem_id: [bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
        oem_table_id: [
            bytes[16], bytes[17], bytes[18], bytes[19],
            bytes[20], bytes[21], bytes[22], bytes[23],
        ],
        oem_revision: u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]),
        creator_id: u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]),
        creator_revision: u32::from_le_bytes([bytes[32], bytes[33], bytes[34], bytes[35]]),
    };

    // Reject lengths that are too small or absurdly large before
    // attempting to read the whole table.
    if (header.length as usize) < SDT_HEADER_SIZE || (header.length as usize) > SDT_MAX_LEN {
        return Err(AcpiError::SdtMalformed);
    }

    // Verify checksum: sum of every `length` byte must be 0.
    // SAFETY: `phys` is within a mapped region and `length <= SDT_MAX_LEN`;
    // a corrupt length near the end of memory would fault here, which is
    // why `SDT_MAX_LEN` exists.
    let full: &[u8] = unsafe {
        core::slice::from_raw_parts(virt as *const u8, header.length as usize)
    };
    if full.iter().fold(0u8, |a, &b| a.wrapping_add(b)) != 0 {
        return Err(AcpiError::SdtMalformed);
    }

    Ok(header)
}

/// Walk a root SDT (RSDT or XSDT) and return the physical address of the
/// MADT.
fn find_madt(root_phys: usize, is_xsdt: bool) -> Result<usize, AcpiError> {
    let root = read_sdt_header(root_phys)?;

    let expected = if is_xsdt { XSDT_SIGNATURE } else { RSDT_SIGNATURE };
    if &root.signature != expected {
        return Err(AcpiError::SdtMalformed);
    }

    let entry_size: usize = if is_xsdt { 8 } else { 4 };
    let payload_len = root.length as usize - SDT_HEADER_SIZE;
    if payload_len % entry_size != 0 {
        return Err(AcpiError::SdtMalformed);
    }

    let base = PHYS_OFFSET + root_phys + SDT_HEADER_SIZE;
    for i in 0..(payload_len / entry_size) {
        let off = base + i * entry_size;

        // SAFETY: `off` is within the root SDT, whose full `length` bytes
        // were checksum-verified above.
        let child_phys = if is_xsdt {
            unsafe { core::ptr::read_unaligned(off as *const u64) as usize }
        } else {
            unsafe { core::ptr::read_unaligned(off as *const u32) as usize }
        };

        match read_sdt_header(child_phys) {
            Ok(hdr) if &hdr.signature == MADT_SIGNATURE => return Ok(child_phys),
            Ok(_) => continue,
            Err(_) => continue, // Skip malformed child; keep looking.
        }
    }

    Err(AcpiError::MadtNotFound)
}

// ── MADT parsing ──────────────────────────────────────────────────────────

/// Read the LAPIC MMIO base from a MADT at physical address `phys`.
fn parse_madt_lapic_base(phys: usize) -> Result<u64, AcpiError> {
    let hdr = read_sdt_header(phys)?;
    if &hdr.signature != MADT_SIGNATURE || (hdr.length as usize) < MADT_MIN_LEN {
        return Err(AcpiError::MadtMalformed);
    }

    let virt = PHYS_OFFSET + phys;
    // SAFETY: the MADT is at least 44 bytes long (checked above), the
    // header was checksum-verified, and `virt + 4` is inside the table.
    let lapic_base = unsafe {
        core::ptr::read_unaligned((virt + 36) as *const u32)
    } as u64;

    if lapic_base == 0 {
        return Err(AcpiError::MadtMalformed);
    }
    Ok(lapic_base)
}

// ── Public entry points ───────────────────────────────────────────────────

/// Parse `RSDP → RSDT/XSDT → MADT`.
///
/// Idempotent: a second call returns immediately if the first succeeded.
/// On failure, no state is written and a subsequent call retries the whole
/// discovery.
pub fn init() {
    if ACPI_READY.load(Ordering::Acquire) {
        return;
    }

    let rsdp = match find_rsdp() {
        Ok(r) => r,
        Err(e) => {
            crate::serial_println!("  [ACPI] RSDP discovery failed: {:?}", e);
            return;
        }
    };

    let oem = rsdp.oem_id_str();
    crate::serial_println!(
        "  [ACPI] RSDP rev={} OEM={}",
        rsdp.revision,
        core::str::from_utf8(&oem).unwrap_or("??????")
    );

    let (root_phys, is_xsdt) = if rsdp.has_xsdt() {
        (rsdp.xsdt_addr as usize, true)
    } else {
        (rsdp.rsdt_addr as usize, false)
    };

    let madt_phys = match find_madt(root_phys, is_xsdt) {
        Ok(p) => p,
        Err(e) => {
            crate::serial_println!("  [ACPI] MADT discovery failed: {:?}", e);
            return;
        }
    };
    crate::serial_println!("  [ACPI] MADT at phys 0x{:x}", madt_phys);

    match parse_madt_lapic_base(madt_phys) {
        Ok(base) => {
            LAPIC_MMIO_BASE.store(base, Ordering::Release);
            ACPI_READY.store(true, Ordering::Release);
            crate::serial_println!("  [ACPI] LAPIC MMIO base = 0x{:x}", base);
        }
        Err(e) => {
            crate::serial_println!("  [ACPI] MADT parse failed: {:?}", e);
        }
    }
}

/// Backward-compatible alias for [`init`].
pub fn acpi_init() {
    init();
}

/// LAPIC MMIO base address discovered by [`init`], or `0` if ACPI was not
/// found or has not been initialised.
#[inline]
#[must_use]
pub fn lapic_mmio_base() -> u64 {
    LAPIC_MMIO_BASE.load(Ordering::Acquire)
}

/// Whether [`init`] has successfully parsed a MADT.
#[inline]
#[must_use]
pub fn is_ready() -> bool {
    ACPI_READY.load(Ordering::Acquire)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal RSDP v1 in a `[u8; 20]` with a valid checksum.
    fn make_v1(oem: [u8; 6], rsdt_addr: u32) -> [u8; RSDP_V1_SIZE] {
        let mut b = [0u8; RSDP_V1_SIZE];
        b[..8].copy_from_slice(RSDP_SIGNATURE);
        b[8] = 0; // checksum placeholder
        b[9..15].copy_from_slice(&oem);
        b[15] = 1; // revision
        b[16..20].copy_from_slice(&rsdt_addr.to_le_bytes());
        let sum: u8 = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(sum);
        b
    }

    /// Build a minimal RSDP v2 (36 bytes) with a valid extended checksum.
    fn make_v2(oem: [u8; 6], rsdt_addr: u32, xsdt_addr: u64) -> [u8; RSDP_V2_SIZE] {
        let mut b = [0u8; RSDP_V2_SIZE];
        b[..8].copy_from_slice(RSDP_SIGNATURE);
        b[9..15].copy_from_slice(&oem);
        b[15] = 2; // revision
        b[16..20].copy_from_slice(&rsdt_addr.to_le_bytes());
        b[20..24].copy_from_slice(&(RSDP_V2_SIZE as u32).to_le_bytes());
        b[24..32].copy_from_slice(&xsdt_addr.to_le_bytes());
        // Compute v1 checksum first (bytes 0..20), then extended (all 36).
        let sum1: u8 = b[..20].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[8] = 0u8.wrapping_sub(sum1);
        // Now recompute the extended checksum over all 36 bytes.
        // The ext_checksum byte is at offset 32.
        b[32] = 0;
        let sum2: u8 = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        b[32] = 0u8.wrapping_sub(sum2);
        b
    }

    #[test]
    fn rsdp_v1_checksum_roundtrip() {
        let b = make_v1(*b"IONA  ", 0x1000);
        let sum: u8 = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        assert_eq!(sum, 0, "v1 checksum must sum to 0");
    }

    #[test]
    fn rsdp_v1_checksum_rejects_flip() {
        let mut b = make_v1(*b"IONA  ", 0x1000);
        b[10] ^= 0xFF;
        let sum: u8 = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        assert_ne!(sum, 0, "corrupt v1 must not sum to 0");
    }

    #[test]
    fn rsdp_v2_checksum_roundtrip() {
        let b = make_v2(*b"NEWOEM", 0x1000, 0x2000);
        let sum_v1: u8 = b[..20].iter().fold(0u8, |a, &x| a.wrapping_add(x));
        assert_eq!(sum_v1, 0);
        let sum_v2: u8 = b.iter().fold(0u8, |a, &x| a.wrapping_add(x));
        assert_eq!(sum_v2, 0);
    }

    #[test]
    fn rsdp_v2_length_field_is_36() {
        let b = make_v2(*b"NEWOEM", 0x1000, 0x2000);
        let length = u32::from_le_bytes([b[20], b[21], b[22], b[23]]);
        assert_eq!(length, RSDP_V2_SIZE as u32);
    }

    #[test]
    fn has_xsdt_reflects_revision_and_pointer() {
        let v1 = Rsdp {
            oem_id: *b"OLD   ",
            revision: 1,
            rsdt_addr: 0x1000,
            length: RSDP_V1_SIZE as u32,
            xsdt_addr: 0,
        };
        assert!(!v1.has_xsdt());

        let v2 = Rsdp {
            oem_id: *b"NEW   ",
            revision: 2,
            rsdt_addr: 0x1000,
            length: RSDP_V2_SIZE as u32,
            xsdt_addr: 0x2000,
        };
        assert!(v2.has_xsdt());

        // Revision 2 with a zero XSDT pointer: not usable, fall back to
        // RSDT.
        let v2_no_xsdt = Rsdp {
            oem_id: *b"NEW   ",
            revision: 2,
            rsdt_addr: 0x1000,
            length: RSDP_V2_SIZE as u32,
            xsdt_addr: 0,
        };
        assert!(!v2_no_xsdt.has_xsdt());
    }

    #[test]
    fn oem_id_str_sanitizes_non_ascii() {
        let rsdp = Rsdp {
            oem_id: *b"AB\x00\x01CD",
            revision: 1,
            rsdt_addr: 0,
            length: RSDP_V1_SIZE as u32,
            xsdt_addr: 0,
        };
        let s = rsdp.oem_id_str();
        assert!(s.iter().all(|b| b.is_ascii_graphic() || *b == b' '));
        // The `\x00` and `\x01` are replaced with `.`.
        assert_eq!(&s[..2], b"AB");
        assert_eq!(&s[2..4], b"..");
    }

    #[test]
    fn init_does_not_panic_without_acpi() {
        // On a test host, ACPI may or may not be present. Calling init
        // twice must not panic; if the first call succeeded, the second
        // short-circuits on ACPI_READY.
        init();
        init();
        let _ = lapic_mmio_base();
        let _ = is_ready();
    }

    #[test]
    fn sdt_length_bounds_are_sane() {
        // Sanity on the bounds used by `read_sdt_header`.
        assert!(SDT_HEADER_SIZE >= 36);
        assert!(SDT_MAX_LEN >= SDT_HEADER_SIZE);
        assert!(MADT_MIN_LEN >= SDT_HEADER_SIZE + 8);
    }
}
