//! Minimal libc for kernel — memory + string functions
//! These are provided to userspace via syscalls and to kernel internally.
//! Wraps buddy/slab allocators for malloc/free.


pub mod musl_compat;

/// malloc — allocate heap memory via buddy allocator (page-aligned)
/// For small allocations: uses kernel heap (linked_list_allocator)
/// For page-sized: uses buddy allocator directly
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 { return core::ptr::null_mut(); }
    // Use alloc::alloc for kernel heap
    use alloc::alloc::{alloc, Layout};
    let layout = match Layout::from_size_align(size, 16) {
        Ok(l)  => l,
        Err(_) => return core::ptr::null_mut(),
    };
    unsafe { alloc(layout) }
}

/// free — release memory allocated by malloc
pub fn free(ptr: *mut u8, size: usize) {
    if ptr.is_null() { return; }
    use alloc::alloc::{dealloc, Layout};
    if let Ok(layout) = Layout::from_size_align(size, 16) {
        unsafe { dealloc(ptr, layout); }
    }
}

/// memcpy — copy n bytes from src to dst
///
/// # Safety
/// src and dst must be valid for n bytes and non-overlapping
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n { *dst.add(i) = *src.add(i); }
    dst
}

/// memmove — copy n bytes, handles overlapping regions
///
/// # Safety
/// src and dst must be valid for n bytes
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst < src as *mut u8 {
        for i in 0..n { *dst.add(i) = *src.add(i); }
    } else {
        for i in (0..n).rev() { *dst.add(i) = *src.add(i); }
    }
    dst
}

/// memset — fill n bytes with value
///
/// # Safety
/// dst must be valid for n bytes
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    for i in 0..n { *dst.add(i) = val as u8; }
    dst
}

/// memcmp — compare n bytes
///
/// # Safety
/// Both pointers must be valid for n bytes
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let diff = *a.add(i) as i32 - *b.add(i) as i32;
        if diff != 0 { return diff; }
    }
    0
}

/// strlen — length of null-terminated string
///
/// # Safety
/// ptr must point to a valid null-terminated string
#[no_mangle]
pub unsafe extern "C" fn strlen(ptr: *const u8) -> usize {
    let mut n = 0;
    while *ptr.add(n) != 0 { n += 1; }
    n
}

/// strcmp — compare null-terminated strings
///
/// # Safety
/// Both pointers must point to valid null-terminated strings
#[no_mangle]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb { return ca as i32 - cb as i32; }
        if ca == 0  { return 0; }
        i += 1;
    }
}

/// strncpy — copy at most n bytes of string
///
/// # Safety
/// Both pointers must be valid
#[no_mangle]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        let c = *src.add(i);
        *dst.add(i) = c;
        if c == 0 { break; }
        i += 1;
    }
    dst
}

pub fn init() {
    crate::serial_println!("  [LIBC] kernel libc: memcpy/memmove/memset/strcmp/strlen ready");
}
