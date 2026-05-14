//! Kernel backtrace — frame pointer chain walk
//!
//! Funcționează dacă kernelul e compilat cu frame pointers (default în debug).
//! Release: necesită -C force-frame-pointers=yes sau unwinding via .eh_frame.
//!
//! Walk:
//!   1. Citește RBP curent
//!   2. La fiecare frame: RBP+8 = return address, *RBP = previous RBP
//!   3. Verifică că adresa e în range-ul kernel (0xFFFF...)
//!   4. Max 64 frames
//!
//! Symbol resolution: fără symtable embedded, afișăm adresele brute.
//! Cu gdb: `add-symbol-file target/.../iona-os-kernel` și `info symbol 0xADDR`

use alloc::{vec::Vec, format, string::String};

pub const MAX_FRAMES: usize = 64;
const KERNEL_BASE:    u64   = 0xFFFF_8000_0000_0000;

#[derive(Clone, Debug)]
pub struct Frame {
    pub rip:   u64,
    pub rbp:   u64,
    pub depth: usize,
}

impl Frame {
    pub fn format(&self) -> String {
        format!("  #{:2} 0x{:016x} (rbp=0x{:016x})", self.depth, self.rip, self.rbp)
    }
}

/// Walk the frame pointer chain starting from `rbp`.
/// Call with `current_rbp()` to capture the live stack.
pub fn walk_frames(start_rbp: u64) -> Vec<Frame> {
    let mut frames = Vec::new();
    let mut rbp = start_rbp;

    for depth in 0..MAX_FRAMES {
        // Validate RBP: must be kernel address and 8-byte aligned
        if rbp < KERNEL_BASE || rbp & 7 != 0 { break; }

        unsafe {
            // RIP is at [RBP + 8]
            let rip_ptr = (rbp + 8) as *const u64;
            let rbp_ptr =  rbp      as *const u64;

            // Bounds check before deref
            if rip_ptr as u64 >= u64::MAX - 8 { break; }

            let rip = core::ptr::read_volatile(rip_ptr);
            let prev_rbp = core::ptr::read_volatile(rbp_ptr);

            // Stop on obviously bogus RIP
            if rip == 0 || rip < KERNEL_BASE { break; }

            frames.push(Frame { rip, rbp, depth });

            // Detect cycle or non-progressing stack
            if prev_rbp <= rbp { break; }
            rbp = prev_rbp;
        }
    }
    frames
}

/// Capture current frame pointer (RBP) inline
#[inline(always)]
pub fn current_rbp() -> u64 {
    let rbp: u64;
    unsafe { core::arch::asm!("mov {}, rbp", out(reg) rbp, options(nostack, nomem)); }
    rbp
}

/// Capture complete backtrace from current execution point
pub fn capture() -> Vec<Frame> {
    let rbp = current_rbp();
    walk_frames(rbp)
}

/// Print backtrace to serial output
pub fn print(frames: &[Frame]) {
    crate::serial_println!("--- backtrace ({} frames) ---", frames.len());
    for f in frames {
        crate::serial_println!("{}", f.format());
    }
    crate::serial_println!("--- end backtrace ---");
}

/// Print backtrace from current point (convenience)
pub fn print_current() {
    let frames = capture();
    print(&frames);
}

/// Format backtrace as a single string (for crash dumps)
pub fn format_string(frames: &[Frame]) -> alloc::string::String {
    let mut s = alloc::string::String::new();
    for f in frames {
        s.push_str(&f.format());
        s.push('\n');
    }
    s
}
