//! Global Descriptor Table — kernel + userspace segments + TSS
//!
//! Segmente necesare pentru ring 0/3:
//!   0: null
//!   1: kernel code  (DPL=0, 64-bit)
//!   2: kernel data  (DPL=0)
//!   3: user code    (DPL=3, 64-bit)  ← Faza 2
//!   4: user data    (DPL=3)          ← Faza 2
//!   5-6: TSS (128-bit)

use spin::Lazy;
use x86_64::{
    instructions::{segmentation::{CS, DS, ES, FS, GS, SS, Segment}, tables::load_tss},
    registers::segmentation::SegmentSelector,
    structures::{
        gdt::{Descriptor, GlobalDescriptorTable},
        tss::TaskStateSegment,
    },
    VirtAddr,
};

pub const DOUBLE_FAULT_IST_INDEX: u16 = 0;
pub const SYSCALL_IST_INDEX:      u16 = 1;
pub const TIMER_IST_INDEX:        u16 = 2;

const STACK_SIZE: usize = 4096 * 5; // 20KB per IST stack

#[repr(align(16))]
struct AlignedStack([u8; STACK_SIZE]);

static DOUBLE_FAULT_STACK: AlignedStack = AlignedStack([0; STACK_SIZE]);
static SYSCALL_STACK:      AlignedStack = AlignedStack([0; STACK_SIZE]);
static TIMER_STACK:        AlignedStack = AlignedStack([0; STACK_SIZE]);

pub struct Selectors {
    pub kernel_code: SegmentSelector,
    pub kernel_data: SegmentSelector,
    pub user_code:   SegmentSelector,   // Faza 2
    pub user_data:   SegmentSelector,   // Faza 2
    pub tss:         SegmentSelector,
}

/// Selector-uri pentru acces din syscall handler
pub static mut KERNEL_CS: u16 = 0;
pub static mut KERNEL_SS: u16 = 0;
pub static mut USER_CS:   u16 = 0;
pub static mut USER_SS:   u16 = 0;

static TSS: Lazy<TaskStateSegment> = Lazy::new(|| {
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[DOUBLE_FAULT_IST_INDEX as usize] = {
        let s = VirtAddr::from_ptr(DOUBLE_FAULT_STACK.0.as_ptr());
        s + STACK_SIZE as u64
    };
    tss.interrupt_stack_table[SYSCALL_IST_INDEX as usize] = {
        let s = VirtAddr::from_ptr(SYSCALL_STACK.0.as_ptr());
        s + STACK_SIZE as u64
    };
    tss.interrupt_stack_table[TIMER_IST_INDEX as usize] = {
        let s = VirtAddr::from_ptr(TIMER_STACK.0.as_ptr());
        s + STACK_SIZE as u64
    };
    tss
});

static GDT: Lazy<(GlobalDescriptorTable, Selectors)> = Lazy::new(|| {
    let mut gdt = GlobalDescriptorTable::new();
    let kcode = gdt.append(Descriptor::kernel_code_segment());
    let kdata = gdt.append(Descriptor::kernel_data_segment());
    let udata = gdt.append(Descriptor::user_data_segment());  // DPL=3
    let ucode = gdt.append(Descriptor::user_code_segment());  // DPL=3
    let tss   = gdt.append(Descriptor::tss_segment(&TSS));
    (gdt, Selectors {
        kernel_code: kcode,
        kernel_data: kdata,
        user_code:   ucode,
        user_data:   udata,
        tss,
    })
});

pub fn init() {
    GDT.0.load();
    unsafe {
        CS::set_reg(GDT.1.kernel_code);
        SS::set_reg(GDT.1.kernel_data);
        DS::set_reg(GDT.1.kernel_data);
        ES::set_reg(GDT.1.kernel_data);
        FS::set_reg(GDT.1.kernel_data);
        GS::set_reg(GDT.1.kernel_data);
        load_tss(GDT.1.tss);

        // Salvăm valorile numerice pentru syscall handler
        KERNEL_CS = GDT.1.kernel_code.0;
        KERNEL_SS = GDT.1.kernel_data.0;
        USER_CS   = GDT.1.user_code.0 | 3;  // RPL=3 pentru userspace
        USER_SS   = GDT.1.user_data.0 | 3;
    }
}

pub fn user_code_selector() -> SegmentSelector { GDT.1.user_code }
pub fn user_data_selector() -> SegmentSelector { GDT.1.user_data }
pub fn kernel_code_selector() -> SegmentSelector { GDT.1.kernel_code }

/// Update RSP0 in TSS — called before entering ring 3
/// RSP0 is the kernel stack pointer that the CPU loads on ring transition
pub fn set_tss_rsp0(rsp0: u64) {
    // TSS is in the GDT; we need to update RSP0 field at offset 4
    // The TSS struct has: u32 reserved, u64 rsp0, u64 rsp1, u64 rsp2 ...
    // Access via the static TSS using raw pointer arithmetic
    unsafe {
        let tss_ptr = &*TSS as *const TaskStateSegment as *const u8 as *mut u8;
        // RSP0 is at offset 4 in TSS (after 32-bit reserved field)
        let rsp0_ptr = tss_ptr.add(4) as *mut u64;
        rsp0_ptr.write_volatile(rsp0);
    }
}
