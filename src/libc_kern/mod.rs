//! Minimal libc for kernel — memory and string functions.
//!
//! Provides core routines used by the kernel and exposed to userspace via syscalls.
//! Memory allocation uses the global kernel allocator (buddy/slab based).
//!
//! # Safety
//! All functions with pointer arguments are unsafe; callers must uphold pointer validity
//! and aliasing rules.

pub mod musl_compat;

// -----------------------------------------------------------------------------
// Allocation
// -----------------------------------------------------------------------------

/// Allocates `size` bytes of heap memory using the global kernel allocator.
///
/// Returns a pointer to the allocated block, or `null_mut` if `size == 0` or
/// allocation fails.
pub fn malloc(size: usize) -> *mut u8 {
    if size == 0 {
        return core::ptr::null_mut();
    }
    let layout = match alloc::alloc::Layout::from_size_align(size, 16) {
        Ok(l) => l,
        Err(_) => return core::ptr::null_mut(),
    };
    unsafe { alloc::alloc::alloc(layout) }
}

/// Frees memory previously allocated by `malloc`.
///
/// The caller **must** provide the exact `size` that was used during allocation.
/// Passing a different size will corrupt the allocator.
///
/// # Safety
/// `ptr` must have been obtained from `malloc` with the same `size`.
pub unsafe fn free_sized(ptr: *mut u8, size: usize) {
    if ptr.is_null() || size == 0 {
        return;
    }
    if let Ok(layout) = alloc::alloc::Layout::from_size_align(size, 16) {
        alloc::alloc::dealloc(ptr, layout);
    }
}

/// Convenience wrapper for freeing a heap-allocated string buffer.
///
/// # Safety
/// `ptr` must have been allocated by `malloc` with size equal to `len + 1` (null terminator).
pub unsafe fn free_str(ptr: *mut u8, len_with_nul: usize) {
    free_sized(ptr, len_with_nul);
}

// -----------------------------------------------------------------------------
// Memory functions (byte by byte, compliant with C standard)
// -----------------------------------------------------------------------------

/// Copies `n` bytes from `src` to `dst`. The regions must **not** overlap.
///
/// # Safety
/// Both pointers must be valid for `n` bytes and must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // Optimisation: word-sized copies could be added here for performance.
    for i in 0..n {
        *dst.add(i) = *src.add(i);
    }
    dst
}

/// Copies `n` bytes from `src` to `dst`, handling overlapping regions correctly.
///
/// # Safety
/// Both pointers must be valid for `n` bytes (may overlap).
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // Compare raw addresses to decide copy direction.
    // This is technically implementation-defined in Rust but works on flat address spaces.
    if dst as usize <= src as usize {
        for i in 0..n {
            *dst.add(i) = *src.add(i);
        }
    } else {
        for i in (0..n).rev() {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

/// Fills `n` bytes starting at `dst` with the value `val` (truncated to u8).
///
/// # Safety
/// `dst` must be valid for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memset(dst: *mut u8, val: i32, n: usize) -> *mut u8 {
    let byte = val as u8;
    for i in 0..n {
        *dst.add(i) = byte;
    }
    dst
}

/// Compares `n` bytes at `a` and `b`.
///
/// Returns:
/// - `< 0` if the first differing byte in `a` is less than the corresponding byte in `b`.
/// - `0` if all `n` bytes are equal.
/// - `> 0` otherwise.
///
/// # Safety
/// Both pointers must be valid for `n` bytes.
#[no_mangle]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
    }
    0
}

// -----------------------------------------------------------------------------
// String functions
// -----------------------------------------------------------------------------

/// Returns the length of the null-terminated string `ptr`, excluding the null byte.
///
/// # Safety
/// `ptr` must point to a valid null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strlen(ptr: *const u8) -> usize {
    let mut n = 0;
    while *ptr.add(n) != 0 {
        n += 1;
    }
    n
}

/// Compares two null-terminated strings lexicographically.
///
/// Returns:
/// - `< 0` if `a` < `b`
/// - `0` if `a` == `b`
/// - `> 0` if `a` > `b`
///
/// # Safety
/// Both pointers must point to valid null-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0;
    loop {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
        if ca == 0 {
            return 0;
        }
        i += 1;
    }
}

/// Copies at most `n` characters from `src` to `dst`.
///
/// If `strlen(src) < n`, the remaining bytes in `dst` are padded with zeros.
///
/// # Safety
/// `dst` must be writable for `n` bytes, `src` must be readable for at least the
/// length of the null-terminated source string (plus 1 for the null byte).
#[no_mangle]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        let c = *src.add(i);
        *dst.add(i) = c;
        if c == 0 {
            // Pad the rest with zero
            i += 1;
            while i < n {
                *dst.add(i) = 0;
                i += 1;
            }
            break;
        }
        i += 1;
    }
    dst
}

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

pub fn init() {
    // The global allocator is expected to be set up earlier (by the kernel boot).
    crate::serial_println!("  [LIBC] kernel libc: memcpy/memmove/memset/memcmp/strlen/strcmp/strncpy ready");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -------------------------------------------------------------------------
    // memcpy & memmove
    // -------------------------------------------------------------------------
    #[test]
    fn test_memcpy_basic() {
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        unsafe { memcpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        assert_eq!(dst, src);
    }

    #[test]
    fn test_memcpy_zero_bytes() {
        let src = [1u8];
        let mut dst = [2u8];
        unsafe { memcpy(dst.as_mut_ptr(), src.as_ptr(), 0) };
        assert_eq!(dst[0], 2); // unchanged
    }

    #[test]
    fn test_memmove_overlap_forward() {
        let mut buf = [1u8, 2, 3, 4, 0];
        // copy [0..3] to [1..4]
        unsafe { memmove(buf.as_mut_ptr().add(1), buf.as_ptr(), 4) };
        assert_eq!(buf, [1, 1, 2, 3, 4]);
    }

    #[test]
    fn test_memmove_overlap_backward() {
        let mut buf = [1u8, 2, 3, 4, 0];
        // copy [1..4] to [0..3]
        unsafe { memmove(buf.as_mut_ptr(), buf.as_ptr().add(1), 4) };
        assert_eq!(buf, [2, 3, 4, 0, 0]);
    }

    // -------------------------------------------------------------------------
    // memset
    // -------------------------------------------------------------------------
    #[test]
    fn test_memset_fill() {
        let mut buf = [0u8; 5];
        unsafe { memset(buf.as_mut_ptr(), 0xAB, 5) };
        assert_eq!(buf, [0xAB; 5]);
    }

    #[test]
    fn test_memset_zero() {
        let mut buf = [0xFFu8; 3];
        unsafe { memset(buf.as_mut_ptr(), 0, 3) };
        assert_eq!(buf, [0; 3]);
    }

    // -------------------------------------------------------------------------
    // memcmp
    // -------------------------------------------------------------------------
    #[test]
    fn test_memcmp_equal() {
        let a = [1, 2, 3];
        let b = [1, 2, 3];
        let res = unsafe { memcmp(a.as_ptr(), b.as_ptr(), 3) };
        assert_eq!(res, 0);
    }

    #[test]
    fn test_memcmp_diff() {
        let a = [1, 2, 3];
        let b = [1, 4, 3];
        let res = unsafe { memcmp(a.as_ptr(), b.as_ptr(), 3) };
        assert!(res < 0);
    }

    // -------------------------------------------------------------------------
    // strlen
    // -------------------------------------------------------------------------
    #[test]
    fn test_strlen() {
        let s = "hello\0extra";
        let len = unsafe { strlen(s.as_ptr()) };
        assert_eq!(len, 5);
    }

    #[test]
    fn test_strlen_empty() {
        let s = "\0";
        assert_eq!(unsafe { strlen(s.as_ptr()) }, 0);
    }

    // -------------------------------------------------------------------------
    // strcmp
    // -------------------------------------------------------------------------
    #[test]
    fn test_strcmp_equal() {
        let a = "abc\0";
        let b = "abc\0";
        assert_eq!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) }, 0);
    }

    #[test]
    fn test_strcmp_a_less() {
        let a = "abc\0";
        let b = "abd\0";
        assert!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) } < 0);
    }

    #[test]
    fn test_strcmp_a_greater() {
        let a = "abz\0";
        let b = "aba\0";
        assert!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) } > 0);
    }

    // -------------------------------------------------------------------------
    // strncpy
    // -------------------------------------------------------------------------
    #[test]
    fn test_strncpy_full() {
        let src = "abcde\0";
        let mut dst = [0u8; 5];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        assert_eq!(&dst, b"abcde");
    }

    #[test]
    fn test_strncpy_pad_zeros() {
        let src = "ab\0";
        let mut dst = [0xFFu8; 5];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        // copies 'a','b','\0', then pads two zeros
        assert_eq!(&dst, b"ab\0\0\0");
    }

    #[test]
    fn test_strncpy_no_null_terminator_in_source() {
        // src longer than n, no early null
        let src = [0x41u8, 0x42, 0x43, 0x44, 0x45]; // not null-terminated
        let mut dst = [0u8; 3];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 3) };
        // should copy exactly 3 bytes, no padding (n reached before null)
        assert_eq!(dst, [0x41, 0x42, 0x43]);
    }
}
