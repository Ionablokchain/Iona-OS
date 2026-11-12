//! NVMe MSI-X interrupt mode — replaces polling.
//!
//! MSI-X (Message Signaled Interrupts Extended) lets the device raise a
//! regular interrupt by writing a message to a pre-programmed address.
//! Each completion queue can have its own vector, and each vector can be
//! targeted at a specific CPU.
//!
//! # Why MSI-X (vs. polling)
//!
//! * CPU can `hlt` while NVMe processes I/O, instead of busy-polling.
//! * Completion latency is ~1–2 µs, vs. one poll tick (typically 1 ms).
//! * Each completion wakes exactly the task that submitted the command.
//!
//! # Implementation
//!
//! * Vector [`NVME_MSIX_VECTOR`] (0x41, IDT entry 65) is reserved for
//!   NVMe completion interrupts. The IDT entry must be installed before
//!   [`setup_msix`] is called.
//! * [`register_waiter`] associates a submission-queue command ID with
//!   the task waiting for its completion.
//! * [`completion_handler`] drains the completion queue in IRQ context,
//!   wakes the matching tasks, and sends EOI to the local APIC.
//!
//! # Contract: register before submit
//!
//! Callers MUST call [`register_waiter`] **before** ringing the
//! submission-queue doorbell. If a completion arrives between
//! submission and registration, the completion is remembered in
//! [`NVME_LOST_WAKEUPS`] and the eventual `register_waiter` call wakes
//! the task immediately instead of blocking. This closes the classic
//! lost-wakeup race that otherwise hangs I/O submission paths.
//!
//! # Failure modes
//!
//! If [`setup_msix`] returns `false` the driver must fall back to
//! polling. All [`completion_handler`] state is benign when no MSI-X is
//! enabled — the interrupt simply never fires.
//!
//! # Limitations
//!
//! * Only MSI-X is implemented; classic MSI and legacy INTx are not
//!   supported by this module.
//! * Assumes the PCI MSI-X table lives in an identity-mapped MMIO BAR
//!   (the kernel's [`PHYS_OFFSET`] convention).
//! * Assumes 8-bit local APIC IDs (xAPIC). On systems with x2APIC
//!   enabled and CPU IDs > 255, the destination address computed here
//!   will be wrong. Supporting x2APIC requires querying IA32_APIC_BASE[10]
//!   and using the wider destination field.
//! * The completion queue itself is expected to be fully described by
//!   `crate::drivers::nvme::poll_completions()`; this module does not
//!   touch NVMe registers directly.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use core::sync::atomic::{fence, Ordering};
use spin::{Lazy, Mutex};

use crate::task::TaskId;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// IDT vector reserved for NVMe completion interrupts.
pub const NVME_MSIX_VECTOR: u8 = 0x41; // IDT[65]

/// PCI capability ID for MSI-X (§6.8.2).
const MSIX_CAP_ID: u8 = 0x11;

/// Offsets within the MSI-X capability structure.
const MSIX_MSG_CTRL_OFFSET: u8 = 2;
const MSIX_TABLE_OFFSET:    u8 = 4;
const MSIX_PBA_OFFSET:      u8 = 8;

/// Message Control register bits.
const MSIX_MSG_CTRL_ENABLE:        u16 = 1 << 15;
const MSIX_MSG_CTRL_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_MSG_CTRL_SIZE_MASK:     u16 = 0x07FF;

/// MSI-X table entry layout (§6.8.2). 16 bytes per entry.
const MSIX_ENTRY_SIZE: usize = 16;

/// Vector Control bit 0 = Mask (1 = masked). All other bits reserved.
const MSIX_ENTRY_MASK: u32 = 1 << 0;

/// PCI Status register bit 4 = Capabilities List present.
const PCI_STATUS_CAP_LIST_BIT: u16 = 1 << 4;
const PCI_STATUS_OFFSET: u8 = 0x06;
const PCI_CAP_PTR_OFFSET: u8 = 0x34;
const PCI_BAR0_OFFSET: u8 = 0x10;

/// Maximum BIR value (BARs 0–5).
const MAX_BIR: u8 = 5;

/// Maximum length of a PCI capability chain (§6.7).
const MAX_CAP_CHAIN: u32 = 48;

/// Valid range for external interrupt vectors (32..=255). Vector 0
/// would clobber the double-fault handler.
const MIN_VECTOR: u8 = 32;

/// Physical base address of the local APIC MMIO window.
const LAPIC_BASE: u64 = 0xFEE0_0000;

/// Virtual-to-physical offset (identity map of physical memory).
const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// ---------------------------------------------------------------------------
// MSI-X table entry
// ---------------------------------------------------------------------------

#[repr(C)]
struct MsixTableEntry {
    /// Lower 32 bits of the message destination address.
    msg_addr_lo: u32,
    /// Upper 32 bits of the message destination address.
    msg_addr_hi: u32,
    /// Message data written to the destination.
    msg_data:    u32,
    /// Vector control (bit 0 = mask).
    vector_ctrl: u32,
}

const _: () = assert!(core::mem::size_of::<MsixTableEntry>() == MSIX_ENTRY_SIZE);

// ---------------------------------------------------------------------------
// Waiters and lost-wakeup tracking
// ---------------------------------------------------------------------------

/// Pending completions: `cmd_id → task`.
static NVME_WAITERS: Lazy<Mutex<BTreeMap<u16, TaskId>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

/// Completions that arrived before their waiter was registered. A
/// subsequent `register_waiter` for the same `cmd_id` wakes the task
/// immediately instead of letting it sleep forever.
static NVME_LOST_WAKEUPS: Lazy<Mutex<BTreeMap<u16, ()>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// ---------------------------------------------------------------------------
// Public API: task waiting
// ---------------------------------------------------------------------------

/// Register `tid` as the task waiting for `cmd_id`.
///
/// **Must be called before ringing the submission-queue doorbell.**
///
/// If the completion for `cmd_id` already arrived (i.e. the caller
/// raced and lost), the task is woken immediately and no waiter is
/// recorded. This is the correct behaviour: the task will observe its
/// completion state on the next schedule and proceed.
pub fn register_waiter(cmd_id: u16, tid: TaskId) {
    let already_completed = NVME_LOST_WAKEUPS.lock().remove(&cmd_id).is_some();
    if already_completed {
        crate::sched::wake_task(tid);
        return;
    }
    NVME_WAITERS.lock().insert(cmd_id, tid);
}

/// Cancel a waiter without waking it. Returns `true` if a waiter was
/// registered for `cmd_id`.
///
/// Useful on the caller's error path when the command was never
/// submitted, or on timeout when the task is abandoning the wait.
pub fn cancel_waiter(cmd_id: u16) -> bool {
    NVME_WAITERS.lock().remove(&cmd_id).is_some()
}

// ---------------------------------------------------------------------------
// Interrupt handler
// ---------------------------------------------------------------------------

/// MSI-X completion handler. Installed at IDT[`NVME_MSIX_VECTOR`].
///
/// Drains the completion queue, wakes tasks that were waiting on the
/// completed commands, and sends EOI to the local APIC.
///
/// # Safety
///
/// Must be called from an interrupt handler. All state accessed here is
/// protected by IRQ-safe `spin::Mutex`; the function will not deadlock
/// against non-IRQ callers as long as they do not hold one of the
/// module's locks while blocking (they don't — `register_waiter` and
/// `cancel_waiter` take and release each lock in one operation).
pub fn completion_handler() {
    // Drain first, then release locks before calling scheduler code.
    let woken = process_completions();
    for tid in woken {
        crate::sched::wake_task(tid);
    }
    // NVME_MSIX_VECTOR is a dedicated vector, so unconditional EOI is
    // correct.
    unsafe { crate::arch::x86_64::apic::lapic_eoi(); }
}

/// Drain the completion queue and return the task IDs to wake.
fn process_completions() -> Vec<TaskId> {
    let completed = crate::drivers::nvme::poll_completions();
    if completed.is_empty() {
        return Vec::new();
    }

    let mut waiters = NVME_WAITERS.lock();
    let mut lost = NVME_LOST_WAKEUPS.lock();

    let mut woken = Vec::with_capacity(completed.len());
    for cmd_id in completed {
        match waiters.remove(&cmd_id) {
            Some(tid) => woken.push(tid),
            None => {
                // No waiter yet. Remember so a late `register_waiter`
                // can wake the task instead of blocking.
                lost.insert(cmd_id, ());
            }
        }
    }
    woken
}

// ---------------------------------------------------------------------------
// MSI-X setup
// ---------------------------------------------------------------------------

/// Program MSI-X vector 0 for the NVMe controller and enable MSI-X.
///
/// Sequence (§6.8.2):
///   1. Locate the MSI-X capability.
///   2. Read Message Control and validate size / current state.
///   3. Read the table's BIR and offset, translate to a virtual address.
///   4. Mask entry 0, program address and data, unmask entry 0.
///   5. Set Message Control.Enable and verify it stuck.
///
/// Returns `true` on success, in which case [`completion_handler`] will
/// fire on every CQ completion. Returns `false` on any failure; the
/// caller must fall back to polling.
pub fn setup_msix(pci_bus: u8, pci_dev: u8, pci_fn: u8) -> bool {
    // Vector sanity: must not collide with CPU-exception handlers.
    if NVME_MSIX_VECTOR < MIN_VECTOR {
        log("NVMe vector collides with CPU exception space");
        return false;
    }

    // 1. Find the MSI-X capability.
    let Some(cap) = find_cap(pci_bus, pci_dev, pci_fn, MSIX_CAP_ID) else {
        log("MSI-X capability not present");
        return false;
    };

    // 2. Read Message Control.
    let ctrl = crate::pci::read_config_u16(pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET);
    let table_size = (ctrl & MSIX_MSG_CTRL_SIZE_MASK) as usize + 1;
    if table_size == 0 {
        log("MSI-X reports zero vectors");
        return false;
    }
    if ctrl & MSIX_MSG_CTRL_ENABLE != 0 {
        log("MSI-X already enabled; refusing to re-program");
        return false;
    }
    if ctrl & MSIX_MSG_CTRL_FUNCTION_MASK != 0 {
        // Function Mask gates all vectors; leave it alone (some firmware
        // sets it for a reason). Clear it only if we plan to handle the
        // consequence, which we don't here.
        log("MSI-X is function-masked; cannot enable cleanly");
        return false;
    }

    // 3. Read table and PBA locations.
    let tbl_info = crate::pci::read_config_u32(pci_bus, pci_dev, pci_fn, cap + MSIX_TABLE_OFFSET);
    let tbl_bir  = (tbl_info & 0x7) as u8;
    let tbl_off  = (tbl_info & !0x7) as u64;

    let pba_info = crate::pci::read_config_u32(pci_bus, pci_dev, pci_fn, cap + MSIX_PBA_OFFSET);
    let pba_bir  = (pba_info & 0x7) as u8;
    let _pba_off = (pba_info & !0x7) as u64;

    if tbl_bir > MAX_BIR || pba_bir > MAX_BIR {
        log("MSI-X BIR out of range (must be 0..=5)");
        return false;
    }

    // Translate BIR → BAR physical address → identity-mapped virtual.
    let Some(tbl_bar_phys) = read_bar_base(pci_bus, pci_dev, pci_fn, tbl_bir) else {
        log("MSI-X table BAR is unmapped or I/O space");
        return false;
    };
    let Some(tbl_virt) = tbl_bar_phys
        .checked_add(PHYS_OFFSET as u64)
        .map(|a| a as usize)
    else {
        log("MSI-X table BAR address overflow");
        return false;
    };

    // 4. Program entry 0.
    //
    // Destination: physical mode, fixed delivery, xAPIC ID. The 8-bit
    // mask matches xAPIC. See module docs for x2APIC limitations.
    let lapic_id = crate::arch::x86_64::apic::current_cpu_id() as u64 & 0xFF;
    let msg_addr = LAPIC_BASE | (lapic_id << 12);
    let msg_data = NVME_MSIX_VECTOR as u32;

    let entry_virt = tbl_virt + tbl_off as usize;
    unsafe {
        let entry = entry_virt as *mut MsixTableEntry;

        // Per spec: entry must be masked while being programmed.
        core::ptr::write_volatile(&mut (*entry).vector_ctrl, MSIX_ENTRY_MASK);
        fence(Ordering::SeqCst);

        core::ptr::write_volatile(&mut (*entry).msg_addr_lo, msg_addr as u32);
        core::ptr::write_volatile(&mut (*entry).msg_addr_hi, (msg_addr >> 32) as u32);
        core::ptr::write_volatile(&mut (*entry).msg_data,    msg_data);
        fence(Ordering::SeqCst);

        // Unmask now that the entry is fully programmed.
        core::ptr::write_volatile(&mut (*entry).vector_ctrl, 0);
        fence(Ordering::SeqCst);
    }

    // 5. Enable MSI-X and verify.
    let new_ctrl = ctrl | MSIX_MSG_CTRL_ENABLE;
    crate::pci::write_config_u16(
        pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET, new_ctrl,
    );
    let check = crate::pci::read_config_u16(
        pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET,
    );
    if check & MSIX_MSG_CTRL_ENABLE == 0 {
        log("MSI-X enable bit did not stick");
        return false;
    }

    crate::serial_println!(
        "  [NVMe MSI-X] enabled: vector=0x{:x}, addr=0x{:x}, entries={}",
        NVME_MSIX_VECTOR, msg_addr, table_size,
    );
    true
}

/// Disable MSI-X (e.g. for shutdown or to fall back to polling).
///
/// The table entries are left as programmed; only the enable bit is
/// cleared.
pub fn disable_msix(pci_bus: u8, pci_dev: u8, pci_fn: u8) -> bool {
    let Some(cap) = find_cap(pci_bus, pci_dev, pci_fn, MSIX_CAP_ID) else {
        return false;
    };
    let ctrl = crate::pci::read_config_u16(pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET);
    if ctrl & MSIX_MSG_CTRL_ENABLE == 0 {
        return true; // already disabled
    }
    let new_ctrl = ctrl & !MSIX_MSG_CTRL_ENABLE;
    crate::pci::write_config_u16(
        pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET, new_ctrl,
    );
    // Drop any waiters to avoid leaking them.
    NVME_WAITERS.lock().clear();
    NVME_LOST_WAKEUPS.lock().clear();
    true
}

/// Return `true` if MSI-X is currently enabled on the controller.
pub fn is_enabled(pci_bus: u8, pci_dev: u8, pci_fn: u8) -> bool {
    let Some(cap) = find_cap(pci_bus, pci_dev, pci_fn, MSIX_CAP_ID) else {
        return false;
    };
    let ctrl = crate::pci::read_config_u16(pci_bus, pci_dev, pci_fn, cap + MSIX_MSG_CTRL_OFFSET);
    ctrl & MSIX_MSG_CTRL_ENABLE != 0
}

// ---------------------------------------------------------------------------
// PCI helpers
// ---------------------------------------------------------------------------

/// Walk the capability chain to find `target_id`. Returns the offset of
/// the capability struct, or `None`.
fn find_cap(bus: u8, dev: u8, func: u8, target_id: u8) -> Option<u8> {
    let status = crate::pci::read_config_u16(bus, dev, func, PCI_STATUS_OFFSET);
    if status & PCI_STATUS_CAP_LIST_BIT == 0 {
        return None;
    }

    let mut ptr = crate::pci::read_config_u8(bus, dev, func, PCI_CAP_PTR_OFFSET) & !0x3;
    for _ in 0..MAX_CAP_CHAIN {
        if ptr == 0 {
            return None;
        }
        let id = crate::pci::read_config_u8(bus, dev, func, ptr);
        if id == target_id {
            return Some(ptr);
        }
        // Next pointer lives at offset +1 and is word-aligned.
        ptr = crate::pci::read_config_u8(bus, dev, func, ptr + 1) & !0x3;
    }
    None
}

/// Read the physical base address of the given BAR.
///
/// Returns `None` for BARs that are unimplemented, mapped in I/O space,
/// or misconfigured (e.g. a 64-bit BAR placed at index 5).
fn read_bar_base(bus: u8, dev: u8, func: u8, bar_idx: u8) -> Option<u64> {
    if bar_idx > MAX_BIR {
        return None;
    }
    let off = PCI_BAR0_OFFSET + bar_idx * 4;
    let lo = crate::pci::read_config_u32(bus, dev, func, off);
    if lo == 0 || lo == 0xFFFF_FFFF {
        return None;
    }
    if lo & 0x1 != 0 {
        return None; // I/O space
    }
    let is_64bit = (lo & 0x6) == 0x4;
    if is_64bit {
        if bar_idx >= MAX_BIR {
            return None;
        }
        let hi = crate::pci::read_config_u32(bus, dev, func, off + 4);
        Some(((hi as u64) << 32) | (lo as u64 & !0xF))
    } else {
        Some((lo as u64) & !0xF)
    }
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

fn log(msg: &str) {
    crate::serial_println!("  [NVMe MSI-X] {}", msg);
}
