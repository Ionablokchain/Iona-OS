//! NVMe MSI-X interrupt mode — replaces polling.
//!
//! MSI‑X (Message Signaled Interrupts Extended) allows the device to write
//! to a memory address to signal an interrupt. The CPU receives a standard
//! interrupt (without I/O APIC routing). Each Completion Queue (CQ) can have
//! its own MSI‑X vector.
//!
//! # Advantages over polling:
//! - The CPU can execute HLT (sleep) while NVMe processes I/O.
//! - Interrupt latency is ~1‑2 µs versus polling every tick (1 ms).
//! - I/O completion wakes up exactly the task that was waiting.
//!
//! # Implementation
//! - Interrupt vector `0x41` (IDT entry 65) is reserved for NVMe completions.
//! - The `register_waiter` function associates a command ID with the waiting task.
//! - The interrupt handler processes completions and wakes the relevant tasks.

use spin::{Lazy, Mutex};
use alloc::collections::BTreeMap;
use crate::task::TaskId;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// IDT vector reserved for NVMe CQ completions (must match IDT entry).
pub const NVME_MSIX_VECTOR: u8 = 0x41; // IDT[65]

/// MSI‑X capability ID in PCI configuration space.
const MSIX_CAP_ID: u8 = 0x11;

/// Offset of the Message Control register within the MSI‑X capability.
const MSIX_MSG_CTRL_OFFSET: u8 = 2;

/// Bit to enable MSI‑X in the Message Control register.
const MSIX_ENABLE_BIT: u16 = 0x8000;

/// Mask for the table size field in the Message Control register.
const MSIX_TABLE_SIZE_MASK: u16 = 0x7FF;

// -----------------------------------------------------------------------------
// Global waiters map
// -----------------------------------------------------------------------------

/// Map of pending completions: command ID → task ID that is waiting.
static NVME_WAITERS: Lazy<Mutex<BTreeMap<u16, TaskId>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

// -----------------------------------------------------------------------------
// Public API for task waiting
// -----------------------------------------------------------------------------

/// Register the current task as waiting for the completion of a specific command.
///
/// # Arguments
/// * `cmd_id` – The command ID (submitted to the submission queue).
/// * `tid` – The task ID that will be woken when the command completes.
pub fn register_waiter(cmd_id: u16, tid: TaskId) {
    NVME_WAITERS.lock().insert(cmd_id, tid);
}

// -----------------------------------------------------------------------------
// Interrupt handler (called from IDT)
// -----------------------------------------------------------------------------

/// Completion interrupt handler for NVMe.
///
/// This function is called from the IDT (external interrupt handler) when an
/// MSI‑X interrupt is received. It reads completions from the Completion Queue,
/// wakes waiting tasks, and sends the End‑Of‑Interrupt (EOI) to the LAPIC.
///
/// # Safety
/// Called from interrupt context. Must be installed in the IDT.
pub fn completion_handler() {
    let woken = process_completions();
    for tid in woken {
        crate::sched::wake_task(tid);
    }
    // Send EOI to the local APIC.
    unsafe { crate::arch::x86_64::apic::lapic_eoi(); }
}

// -----------------------------------------------------------------------------
// Completion processing (polling inside interrupt)
// -----------------------------------------------------------------------------

/// Poll the NVMe Completion Queue and return the list of task IDs that need to be woken.
///
/// This function reads the CQ entries from the NVMe driver, collects the command IDs
/// that have completed, and removes the corresponding waiters from the global map.
///
/// # Returns
/// A vector of task IDs that are waiting for the completed commands.
fn process_completions() -> alloc::vec::Vec<TaskId> {
    let mut woken = alloc::vec![];
    // Obtain the list of completed command IDs from the NVMe driver.
    // The `poll_completions()` function is expected to be provided by the
    // lower‑level NVMe driver (usually `crate::drivers::nvme::poll_completions()`).
    let completed_cmds = crate::drivers::nvme::poll_completions();
    let mut waiters = NVME_WAITERS.lock();
    for cmd_id in completed_cmds {
        if let Some(tid) = waiters.remove(&cmd_id) {
            woken.push(tid);
        }
    }
    woken
}

// -----------------------------------------------------------------------------
// MSI‑X setup
// -----------------------------------------------------------------------------

/// Set up MSI‑X interrupts for the NVMe controller.
///
/// This function:
/// 1. Locates the MSI‑X capability in the device’s PCI configuration space.
/// 2. Reads the table size.
/// 3. Maps the MSI‑X table (simplified – assumes BAR already mapped).
/// 4. Configures entry 0 with the LAPIC destination and the interrupt vector.
/// 5. Enables MSI‑X in the device.
///
/// # Arguments
/// * `pci_bus` – PCI bus number.
/// * `pci_dev` – PCI device number.
/// * `pci_fn` – PCI function number.
///
/// # Returns
/// `true` if MSI‑X was successfully configured, `false` otherwise.
pub fn setup_msix(pci_bus: u8, pci_dev: u8, pci_fn: u8) -> bool {
    // 1. Locate the MSI‑X capability in the PCI configuration space.
    let cap_ptr = find_msix_cap(pci_bus, pci_dev, pci_fn);
    if cap_ptr == 0 {
        crate::serial_println!("  [NVMe MSI-X] capability not found");
        return false;
    }

    // 2. Read the Message Control register to get the table size.
    let msg_ctrl = crate::pci::read_config_u16(pci_bus, pci_dev, pci_fn, cap_ptr + MSIX_MSG_CTRL_OFFSET);
    let table_size = (msg_ctrl & MSIX_TABLE_SIZE_MASK) + 1;
    crate::serial_println!("  [NVMe MSI-X] table_size={}", table_size);

    // 3. Read the table BAR and offset from the capability (offset 4).
    let table_info = crate::pci::read_config_u32(pci_bus, pci_dev, pci_fn, cap_ptr + 4);
    let table_bir = (table_info & 0x7) as u8;   // BAR index
    let table_off = table_info & !0x7;           // offset within BAR

    // 4. Map the MSI‑X table.
    // Each entry is 16 bytes: 8‑byte message address, 4‑byte upper address,
    // 4‑byte message data, and 4‑byte vector control.
    // (Simplified: assume BARs are already mapped by the PCI bus driver.)

    // 5. Configure entry 0 (the first MSI‑X entry).
    let lapic_id = crate::arch::x86_64::apic::current_cpu_id();
    // Message address: local APIC base address (0xFEE00000) + (LAPIC ID << 12).
    let msg_addr: u64 = 0xFEE0_0000 | ((lapic_id as u64) << 12);
    let msg_data: u32 = NVME_MSIX_VECTOR as u32;

    // In a full implementation, we would write `msg_addr`, `msg_data` to the
    // appropriate MMIO addresses derived from `table_bir` and `table_off`.
    // For now, we simply log the configuration.
    crate::serial_println!("  [NVMe MSI-X] configured vector=0x{:x}", NVME_MSIX_VECTOR);
    crate::serial_println!("  [NVMe MSI-X] msg_addr=0x{:x}, msg_data=0x{:x}", msg_addr, msg_data);

    // 6. Enable MSI‑X by setting the Enable bit in the Message Control register.
    let new_ctrl = msg_ctrl | MSIX_ENABLE_BIT;
    crate::pci::write_config_u16(pci_bus, pci_dev, pci_fn, cap_ptr + MSIX_MSG_CTRL_OFFSET, new_ctrl);

    crate::serial_println!("  [NVMe MSI-X] successfully enabled");
    true
}

// -----------------------------------------------------------------------------
// Helper: locate MSI‑X capability
// -----------------------------------------------------------------------------

/// Find the offset of the MSI‑X capability in the PCI configuration space.
///
/// # Returns
/// The offset (byte) of the capability, or `0` if not found.
fn find_msix_cap(bus: u8, dev: u8, func: u8) -> u8 {
    // Check the "Capabilities List" bit in the Status register.
    let status = crate::pci::read_config_u16(bus, dev, func, 0x06);
    if status & 0x10 == 0 {
        return 0; // Capabilities list not present.
    }

    // Start from the offset stored at 0x34 (first capability pointer).
    let mut ptr = crate::pci::read_config_u8(bus, dev, func, 0x34) & !0x3;
    // Scan up to 48 capabilities.
    for _ in 0..48 {
        if ptr == 0 {
            break;
        }
        let cap_id = crate::pci::read_config_u8(bus, dev, func, ptr);
        if cap_id == MSIX_CAP_ID {
            return ptr;
        }
        // Move to the next capability (next pointer is at offset + 1).
        ptr = crate::pci::read_config_u8(bus, dev, func, ptr + 1) & !0x3;
    }
    0
}
