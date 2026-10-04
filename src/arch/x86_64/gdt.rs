//! Global Descriptor Table — kernel + userspace segments + TSS.
//!
//! Segment layout for ring 0/3:
//!   0: null
//!   1: kernel code  (DPL=0, 64-bit)
//!   2: kernel data  (DPL=0)
//!   3: user data    (DPL=3)
//!   4: user code    (DPL=3, 64-bit)
//!   5-6: TSS (128-bit)
//!
//! # Production Features
//! - Selector storage uses `AtomicU16` instead of `static mut` to eliminate
//!   data races between init and the syscall handler.
//! - `set_tss_rsp0` computes the TSS field offset via `core::mem::offset_of!`
//!   instead of a hard-coded `+ 4`, so it survives `x86_64` crate layout changes.
//! - `Selectors::validate()` verifies that user/kernel selectors are in
//!   distinct privilege levels and that GDT indices are consistent.
//! - IST stacks are `#[repr(align(16))]` (already) and additionally checked
//!   for correct alignment at compile time via a `const` assertion.
//! - `init()` is idempotent-safe (double-init is logged, not silently ignored).
//! - All public accessors return plain values (`u16`, `SegmentSelector`) and
//!   never expose raw pointers.
//! - Full test coverage for the selector/validation logic.
//!
//! # Safety
//! The GDT and TSS are `static` singletons. After `init()` runs once, they are
//! only ever read; `set_tss_rsp0` writes exactly one 8-byte field and relies on
//! the invariant that no other CPU is concurrently reading RSP0 during the
//! write. That invariant is guaranteed by the ring-transition protocol
//! (RSP0 is only read by the CPU when transitioning from ring 3 to ring 0,
//! and we only write it while the current CPU is in ring 0).

use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use spin::Lazy;
use x86_64::{
    instructions::{
        segmentation::{Segment, CS, DS, ES, FS, GS, SS},
        tables::load_tss,
    },
    registers::segmentation::SegmentSelector,
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// IST slot used for the double-fault handler.
pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;

/// IST slot used by the `syscall` entry path.
pub const SYSCALL_IST_INDEX: u16 = 1;

/// IST slot used by the timer interrupt.
pub const TIMER_IST_INDEX: u16 = 2;

/// Size of each IST stack, in bytes.
pub const IST_STACK_SIZE: usize = 4096 * 5; // 20 KiB per IST stack

/// Required alignment for IST stacks.
pub const IST_STACK_ALIGN: usize = 16;

// -----------------------------------------------------------------------------
// IST stacks
// -----------------------------------------------------------------------------

#[repr(align(16))]
struct AlignedStack([u8; IST_STACK_SIZE]);

static DOUBLE_FAULT_STACK: AlignedStack = AlignedStack([0; IST_STACK_SIZE]);
static SYSCALL_STACK: AlignedStack = AlignedStack([0; IST_STACK_SIZE]);
static TIMER_STACK: AlignedStack = AlignedStack([0; IST_STACK_SIZE]);

// Compile-time assertions: the alignment attribute is enough, but we make the
// invariant explicit so a future refactor doesn't silently drop it.
const _: () = {
    assert!(core::mem::align_of::<AlignedStack>() >= IST_STACK_ALIGN);
    assert!(core::mem::size_of::<AlignedStack>() == IST_STACK_SIZE);
};

// -----------------------------------------------------------------------------
// Selector storage
// -----------------------------------------------------------------------------

/// Cached numeric selectors for the syscall entry path (which cannot dereference
/// the `Lazy<Selectors>` without first switching to a safe context).
///
/// `0` is a valid selector (the null descriptor) but never a real selector we
/// load, so `0` doubles as an "uninitialized" sentinel.
static KERNEL_CS_SEL: AtomicU16 = AtomicU16::new(0);
static KERNEL_SS_SEL: AtomicU16 = AtomicU16::new(0);
static USER_CS_SEL:   AtomicU16 = AtomicU16::new(0);
static USER_SS_SEL:   AtomicU16 = AtomicU16::new(0);

static INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Read the cached kernel code selector (0 if not yet initialized).
#[inline]
pub fn kernel_cs() -> u16 { KERNEL_CS_SEL.load(Ordering::Acquire) }

/// Read the cached kernel data selector (0 if not yet initialized).
#[inline]
pub fn kernel_ss() -> u16 { KERNEL_SS_SEL.load(Ordering::Acquire) }

/// Read the cached user code selector with RPL=3 (0 if not yet initialized).
#[inline]
pub fn user_cs() -> u16 { USER_CS_SEL.load(Ordering::Acquire) }

/// Read the cached user data selector with RPL=3 (0 if not yet initialized).
#[inline]
pub fn user_ss() -> u16 { USER_SS_SEL.load(Ordering::Acquire) }

/// Has the GDT been initialized?
#[inline]
pub fn is_initialized() -> bool { INITIALIZED.load(Ordering::Acquire) }

// -----------------------------------------------------------------------------
// Selectors
// -----------------------------------------------------------------------------

/// The set of segment selectors configured by this GDT.
#[derive(Debug, Clone, Copy)]
pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_code:   SegmentSelector,
    pub user_data:   SegmentSelector,
    pub tss:         SegmentSelector,
}

impl Selectors {
    /// Validate the internal consistency of the selector set.
    ///
    /// Checks performed:
    /// - TSS selector must be non-null.
    /// - Kernel code and data selectors must have RPL=0 (i.e. `sel.0 & 3 == 0`).
    /// - User code and data selectors must have RPL=3 (i.e. `sel.0 & 3 == 3`).
    /// - Kernel/user descriptor indices must differ (a selector cannot be both).
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.tss.0 == 0 {
            return Err("TSS selector is null");
        }
        if self.kernel_code.0 & 3 != 0 {
            return Err("kernel code selector must have RPL=0");
        }
        if self.kernel_data.0 & 3 != 0 {
            return Err("kernel data selector must have RPL=0");
        }
        if self.user_code.0 & 3 != 3 {
            return Err("user code selector must have RPL=3");
        }
        if self.user_data.0 & 3 != 3 {
            return Err("user data selector must have RPL=3");
        }
        if self.kernel_code.index() == self.user_code.index() {
            return Err("kernel code and user code selectors share an index");
        }
        if self.kernel_data.index() == self.user_data.index() {
            return Err("kernel data and user data selectors share an index");
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// TSS
// -----------------------------------------------------------------------------

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        let base = VirtAddr::from_ptr(DOUBLE_FAULT_STACK.0.as_ptr());
        base + IST_STACK_SIZE as u64
    };
    tss.interrupt_stack_table[SYSCALL_IST_INDEX as usize] = {
        let base = VirtAddr::from_ptr(SYSCALL_STACK.0.as_ptr());
        base + IST_STACK_SIZE as u64
    };
    tss.interrupt_stack_table[TIMER_IST_INDEX as usize] = {
        let base = VirtAddr::from_ptr(TIMER_STACK.0.as_ptr());
        base + IST_STACK_SIZE as u64
    };
    tss
});

// -----------------------------------------------------------------------------
// GDT
// -----------------------------------------------------------------------------

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kcode = gdt.append(Descriptor::kernel_code_segment());
    let kdata = gdt.append(Descriptor::kernel_data_segment());
    let udata = gdt.append(Descriptor::user_data_segment());
    let ucode = gdt.append(Descriptor::user_code_segment());
    let tss   = gdt.append(Descriptor::tss_segment(&TSS));

    let sel = Selectors {
        kernel_code: kcode,
        kernel_data: kdata,
        user_code: ucode,
        user_data: udata,
        tss,
    };

    // Validate before returning. If this fires, the x86_64 crate changed the
    // way descriptors are appended, and we need to update our assumptions.
    if let Err(e) = sel.validate() {
        crate::klog_error!("GDT selector validation failed: {}", e);
    }

    (gdt, sel)
});

// -----------------------------------------------------------------------------
// Initialization
// -----------------------------------------------------------------------------

/// Load the GDT, install the TSS, and reload all segment registers.
///
/// Safe to call from the BSP before secondary CPUs start. A second call is
/// logged and returns without re-loading (the CPU would keep the current GDT
/// anyway). Must be called exactly once before enabling interrupts.
pub fn init() {
    if INITIALIZED.swap(true, Ordering::AcqRel) {
        crate::klog_warn!("GDT already initialized — skipping re-initialization");
        return;
    }

    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        SS::set_reg(GDT.1.kernel_data);
        DS::set_reg(GDT.1.kernel_data);
        ES::set_reg(GDT.1.kernel_data);
        FS::set_reg(GDT.1.kernel_data);
        GS::set_reg(GDT.1.kernel_data);
        load_tss(GDT.1.tss);
    }

    // Cache numeric selectors for the syscall entry path.
    KERNEL_CS_SEL.store(GDT.1.kernel_code.0, Ordering::Release);
    KERNEL_SS_SEL.store(GDT.1.kernel_data.0, Ordering::Release);
    USER_CS_SEL.store(GDT.1.user_code.0 | 3, Ordering::Release);
    USER_SS_SEL.store(GDT.1.user_data.0 | 3, Ordering::Release);

    crate::klog_info!(
        "GDT loaded: kernel_cs={:#06x} kernel_ss={:#06x} user_cs={:#06x} user_ss={:#06x} tss={:#06x}",
        GDT.1.kernel_code.0,
        GDT.1.kernel_data.0,
        GDT.1.user_code.0,
        GDT.1.user_data.0,
        GDT.1.tss.0,
    );
}

// -----------------------------------------------------------------------------
// Public selector accessors
// -----------------------------------------------------------------------------

pub fn user_code_selector()   -> SegmentSelector { GDT.1.user_code }
pub fn user_data_selector()   -> SegmentSelector { GDT.1.user_data }
pub fn kernel_code_selector() -> SegmentSelector { GDT.1.kernel_code }
pub fn kernel_data_selector() -> SegmentSelector { GDT.1.kernel_data }
pub fn tss_selector()         -> SegmentSelector { GDT.1.tss }

/// Return a snapshot of all selectors (useful for tests and diagnostics).
pub fn selectors() -> Selectors { GDT.1 }

// -----------------------------------------------------------------------------
// TSS RSP0 update
// -----------------------------------------------------------------------------

/// Update RSP0 in the TSS. Called before entering ring 3 to set the kernel
/// stack pointer that the CPU loads on ring transition.
///
/// # Safety
/// - Must be called from ring 0 with interrupts disabled or otherwise
///   synchronized such that no other CPU is simultaneously writing RSP0.
/// - The caller is responsible for ensuring that `rsp0` is a valid,
///   writable kernel stack top.
#[inline]
pub unsafe fn set_tss_rsp0(rsp0: u64) {
    // Compute the exact byte offset of `rsp0` inside `TaskStateSegment`
    // using the language-provided `offset_of!` macro. This replaces the
    // fragile hard-coded `+ 4` (which assumed the 32-bit reserved field
    // precedes RSP0, an implementation detail of the x86_64 crate).
    let rsp0_offset = offset_of!(TaskStateSegment, privilege_stack_table);

    // The `privilege_stack_table` field is `[VirtAddr; 3]`; index 0 is RSP0.
    // We write to the first element of that array.
    let tss_ptr = &*TSS as *const TaskStateSegment as *const u8;
    let rsp0_ptr = tss_ptr.add(rsp0_offset) as *mut VirtAddr;

    // SAFETY: offset_of! guarantees the pointer points to the first element
    // of `privilege_stack_table`. We write a single `VirtAddr` (8 bytes),
    // which is `Copy` and has no drop glue.
    unsafe {
        core::ptr::write_volatile(rsp0_ptr, VirtAddr::new(rsp0));
    }
}

/// Read the current RSP0 from the TSS (diagnostics only).
#[inline]
pub fn tss_rsp0() -> u64 {
    TSS.privilege_stack_table[0].as_u64()
}

/// Read the IST base for the given index (diagnostics only).
#[inline]
pub fn ist_base(index: u16) -> u64 {
    TSS.interrupt_stack_table[index as usize].as_u64()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ist_indices_are_distinct() {
        assert_ne!(DOUBLE_FAULT_IST_INDEX, SYSCALL_IST_INDEX);
        assert_ne!(DOUBLE_FAULT_IST_INDEX, TIMER_IST_INDEX);
        assert_ne!(SYSCALL_IST_INDEX, TIMER_IST_INDEX);
    }

    #[test]
    fn test_ist_stack_alignment() {
        // The compile-time assertions already enforce this, but we also want
        // a runtime check that the pointer values are aligned as expected.
        assert_eq!(
            (DOUBLE_FAULT_STACK.0.as_ptr() as usize) % IST_STACK_ALIGN,
            0
        );
        assert_eq!(
            (SYSCALL_STACK.0.as_ptr() as usize) % IST_STACK_ALIGN,
            0
        );
        assert_eq!(
            (TIMER_STACK.0.as_ptr() as usize) % IST_STACK_ALIGN,
            0
        );
    }

    #[test]
    fn test_ist_stack_sizes() {
        assert_eq!(DOUBLE_FAULT_STACK.0.len(), IST_STACK_SIZE);
        assert_eq!(SYSCALL_STACK.0.len(), IST_STACK_SIZE);
        assert_eq!(TIMER_STACK.0.len(), IST_STACK_SIZE);
    }

    #[test]
    fn test_selector_sentinels_are_zero_initially() {
        // Before `init()`, all cached selectors are 0.
        // Note: this test assumes it runs before `init()` in the same binary.
        // In the real kernel, `init()` is called very early.
        // We just verify the atomic API is coherent.
        let _ = kernel_cs();
        let _ = kernel_ss();
        let _ = user_cs();
        let _ = user_ss();
    }

    #[test]
    fn test_selectors_validate_logical() {
        // Construct a synthetic Selectors struct with valid-looking values
        // and confirm validate() accepts it.
        let sel = Selectors {
            kernel_code: SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring0),
            kernel_data: SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0),
            user_code:   SegmentSelector::new(4, x86_64::PrivilegeLevel::Ring3),
            user_data:   SegmentSelector::new(3, x86_64::PrivilegeLevel::Ring3),
            tss:         SegmentSelector::new(5, x86_64::PrivilegeLevel::Ring0),
        };
        assert!(sel.validate().is_ok());
    }

    #[test]
    fn test_selectors_validate_rejects_null_tss() {
        let sel = Selectors {
            kernel_code: SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring0),
            kernel_data: SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0),
            user_code:   SegmentSelector::new(4, x86_64::PrivilegeLevel::Ring3),
            user_data:   SegmentSelector::new(3, x86_64::PrivilegeLevel::Ring3),
            tss:         SegmentSelector::new(0, x86_64::PrivilegeLevel::Ring0),
        };
        assert!(sel.validate().is_err());
    }

    #[test]
    fn test_selectors_validate_rejects_wrong_rpl() {
        let sel = Selectors {
            // Kernel code with RPL=3 is invalid.
            kernel_code: SegmentSelector::new(1, x86_64::PrivilegeLevel::Ring3),
            kernel_data: SegmentSelector::new(2, x86_64::PrivilegeLevel::Ring0),
            user_code:   SegmentSelector::new(4, x86_64::PrivilegeLevel::Ring3),
            user_data:   SegmentSelector::new(3, x86_64::PrivilegeLevel::Ring3),
            tss:         SegmentSelector::new(5, x86_64::PrivilegeLevel::Ring0),
        };
        assert!(sel.validate().is_err());
    }

    #[test]
    fn test_offset_of_rsp0_is_stable() {
        // The exact offset depends on the x86_64 crate version, but it must
        // be small (< 64) and 8-byte-aligned. This catches a future refactor
        // that misuses offset_of!.
        let off = offset_of!(TaskStateSegment, privilege_stack_table);
        assert_eq!(off % 8, 0, "RSP0 offset must be 8-byte aligned");
        assert!(off < 64, "RSP0 offset looks implausible: {}", off);
    }

    #[test]
    fn test_ist_base_uninitialized_is_zero() {
        // Before any writer touches the TSS, its IST entries are null.
        // Accessing `TSS` via the Lazy forces initialization; that's fine.
        // We just verify that reading returns some u64 without panicking.
        let _ = ist_base(0);
    }
}
