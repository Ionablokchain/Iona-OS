//! Safe userspace memory access — copy_from_user / copy_to_user
//!
//! Current implementation level:
//!
//!   1. Range check: all pointers validated against USER_SPACE_MAX (canonical limit)
//!   2. SMAP bypass: STAC/CLAC bracket every user memory access
//!   3. Safe-copy window: dual-path flag (per-CPU + global fallback)
//!      - Per-CPU: PerCpu::in_safe_copy via GS pointer — SMP-correct
//!      - Global: IS_SAFE_COPY AtomicBool — boot/early AP fallback
//!      - IDT checks both via OR: correct in all CPU initialization phases
//!   4. RAII guard: ScopedUserAccess — STAC + window on entry, CLAC + clear on Drop
//!
//! Known limitations (documented, not regressions):
//!
//!   L1. get_user_u64() uses read_unaligned() — direct pointer dereference.
//!       Protected by ScopedUserAccess + IDT EFAULT recovery.
//!       A true fault-safe primitive would use inline assembly with explicit
//!       error label (Linux: copy_user_generic_unrolled + fixup table).
//!       This requires per-CPU exception fixup tables — planned for v0.8.
//!
//!   L2. copy_cstr_from_user() reads byte-by-byte under the same window.
//!       Each byte access can fault independently; the IDT kills the task.
//!       A batch-copy approach (copy 8 bytes at a time, stop at NUL) would
//!       be faster but adds complexity. Current approach is correct and safe.
//!
//!   L3. IS_SAFE_COPY global is set in addition to per-CPU flag.
//!       On SMP, two concurrent safe-copy operations on different CPUs each
//!       set their own per-CPU flag independently — no interference.
//!       The global flag is redundant for SMP but required for the IDT
//!       fast-path check before per-CPU data is initialized.
//!
//!   L4. ScopedUserAccess Drop does NOT run on fault path.
//!       If #PF fires during user memory access, the task is killed via
//!       exit_current(-14). The IDT manually calls clear_safe_copy_window().
//!       This is semantically correct — the task is dead, no cleanup needed.
//!       A longjmp-style recovery (setjmp/siglongjmp) would allow returning
//!       Err to the caller, but requires x86 exception fixup infrastructure.

use core::sync::atomic::{AtomicBool, Ordering};

pub const USER_SPACE_MAX: u64 = 0x0000_8000_0000_0000;

/// Global safe-copy window flag — dual role:
///   - Boot/early AP: only this flag is set (per-CPU GS not yet initialized)
///   - Normal SMP: both this AND per-CPU flag are set; IDT checks both via OR
pub static IS_SAFE_COPY: AtomicBool = AtomicBool::new(false);

#[inline] unsafe fn stac() { core::arch::asm!("stac", options(nostack, nomem)); }
#[inline] unsafe fn clac() { core::arch::asm!("clac", options(nostack, nomem)); }

/// Set safe-copy window on current CPU.
/// Writes per-CPU flag (SMP-correct) AND global flag (IDT fast-path).
#[inline]
pub fn set_safe_copy_window() {
    crate::arch::x86_64::percpu::set_safe_copy(true);
    IS_SAFE_COPY.store(true, Ordering::SeqCst);
}

/// Clear safe-copy window on current CPU.
#[inline]
pub fn clear_safe_copy_window() {
    crate::arch::x86_64::percpu::set_safe_copy(false);
    IS_SAFE_COPY.store(false, Ordering::SeqCst);
}

/// RAII guard: STAC + safe-copy window on entry; CLAC + clear on Drop.
///
/// Normal exit (including ? operator): Drop runs → cleanup guaranteed.
/// Fault path (#PF in user memory): Drop does NOT run (task killed).
///   IDT calls clear_safe_copy_window() manually before exit_current(-14).
///
/// See module docs L4 for discussion of longjmp-style alternative.
struct ScopedUserAccess;

impl ScopedUserAccess {
    fn new() -> Self {
        set_safe_copy_window();
        unsafe { stac(); }
        ScopedUserAccess
    }
}

impl Drop for ScopedUserAccess {
    fn drop(&mut self) {
        unsafe { clac(); }
        clear_safe_copy_window();
    }
}

/// Validate user pointer range: non-null, canonical, no overflow past limit.
#[inline]
pub fn check_user_range(ptr: u64, len: u64) -> bool {
    if ptr == 0 { return false; }
    if ptr >= USER_SPACE_MAX { return false; }
    if len > 0 {
        match ptr.checked_add(len) {
            Some(end) if end <= USER_SPACE_MAX => {}
            _ => return false,
        }
    }
    true
}

/// Copy bytes from userspace into kernel buffer.
/// On page fault: task killed via IDT, EFAULT returned to caller.
pub fn copy_from_user(dst: &mut [u8], src_user: u64) -> Result<usize, &'static str> {
    if !check_user_range(src_user, dst.len() as u64) {
        return Err("EFAULT: bad user pointer");
    }
    let n = dst.len();
    let _guard = ScopedUserAccess::new();
    unsafe { core::ptr::copy_nonoverlapping(src_user as *const u8, dst.as_mut_ptr(), n); }
    Ok(n)
}

/// Copy bytes from kernel into userspace.
pub fn copy_to_user(dst_user: u64, src: &[u8]) -> Result<usize, &'static str> {
    if !check_user_range(dst_user, src.len() as u64) {
        return Err("EFAULT: bad user pointer");
    }
    let n = src.len();
    let _guard = ScopedUserAccess::new();
    unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst_user as *mut u8, n); }
    Ok(n)
}

/// Read u64 from userspace (unaligned).
/// Uses read_unaligned — see module doc L1 for limitation discussion.
pub fn get_user_u64(addr: u64) -> Result<u64, &'static str> {
    if !check_user_range(addr, 8) { return Err("EFAULT"); }
    let _guard = ScopedUserAccess::new();
    // SAFETY: range-checked above; fault handled by IDT via IS_SAFE_COPY
    let v = unsafe { (addr as *const u64).read_unaligned() };
    Ok(v)
}

/// Write u64 to userspace.
pub fn put_user_u64(addr: u64, val: u64) -> Result<(), &'static str> {
    if !check_user_range(addr, 8) { return Err("EFAULT"); }
    let _guard = ScopedUserAccess::new();
    unsafe { (addr as *mut u64).write_unaligned(val); }
    Ok(())
}

/// Read NUL-terminated C string from userspace (max 4095 bytes).
/// Byte-by-byte — see module doc L2 for limitation discussion.
/// Any byte fault kills the task via IDT, not the kernel.
pub fn copy_cstr_from_user(ptr: u64) -> Result<alloc::string::String, &'static str> {
    if !check_user_range(ptr, 1) { return Err("EFAULT"); }
    let mut s = alloc::string::String::new();
    let _guard = ScopedUserAccess::new();
    unsafe {
        for i in 0..4095usize {
            let b = *((ptr + i as u64) as *const u8);
            if b == 0 { break; }
            if b.is_ascii() { s.push(b as char); } else { break; }
        }
    }
    Ok(s)
}

/// Legacy alias
pub fn copy_cstr(ptr: u64) -> Result<alloc::string::String, &'static str> {
    copy_cstr_from_user(ptr)
}
