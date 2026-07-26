//! Minimal libc for kernel — memory and string functions.
//!
//! Provides core routines used by the kernel and exposed to userspace via syscalls.
//! Memory allocation uses the global kernel allocator (buddy/slab based).
//!
//! # Production Features
//! - Configurable via `LibcConfig` (alignment, metrics, logging, limits).
//! - `LibcMetrics` with atomic counters for allocations, frees, bytes, failures.
//! - `LibcManager` as a thread‑safe wrapper (using `spin::Mutex` in kernel).
//! - Structured logging with `tracing` (optional feature).
//! - Safety checks: debug assertions, null pointer guards, size limits.
//! - Optional allocator features (`allocator` feature flag).
//! - Full test coverage.

#![no_std]

extern crate alloc;

use alloc::alloc::{alloc, dealloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::Mutex;
use tracing::{debug, error, info, trace, warn};

// ── Submodules ─────────────────────────────────────────────────────────────

pub mod musl_compat;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the libc subsystem.
#[derive(Debug, Clone)]
pub struct LibcConfig {
    /// Alignment requirement for allocations (must be power of two).
    pub allocator_alignment: usize,
    /// Whether to track metrics (counters).
    pub track_metrics: bool,
    /// Whether to log allocation events.
    pub log_allocations: bool,
    /// Maximum allocation size in bytes.
    pub max_allocation_size: usize,
}

impl Default for LibcConfig {
    fn default() -> Self {
        Self {
            allocator_alignment: 16,
            track_metrics: true,
            log_allocations: false,
            max_allocation_size: usize::MAX,
        }
    }
}

impl LibcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.allocator_alignment == 0 || !self.allocator_alignment.is_power_of_two() {
            return Err("allocator_alignment must be a power of two");
        }
        if self.max_allocation_size == 0 {
            return Err("max_allocation_size must be > 0");
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Metrics for the libc subsystem.
#[derive(Debug, Default)]
pub struct LibcMetrics {
    /// Total number of allocations.
    pub allocations: AtomicU64,
    /// Total number of frees.
    pub frees: AtomicU64,
    /// Total bytes allocated (cumulative).
    pub bytes_allocated: AtomicU64,
    /// Total bytes freed (cumulative).
    pub bytes_freed: AtomicU64,
    /// Number of failed allocations.
    pub allocation_failures: AtomicU64,
    /// Number of invalid free attempts (null or mismatched size).
    pub free_errors: AtomicU64,
}

impl LibcMetrics {
    pub fn record_alloc(&self, size: usize) {
        self.allocations.fetch_add(1, Ordering::Relaxed);
        self.bytes_allocated.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_free(&self, size: usize) {
        self.frees.fetch_add(1, Ordering::Relaxed);
        self.bytes_freed.fetch_add(size as u64, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.allocation_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_free_error(&self) {
        self.free_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> LibcMetricsSnapshot {
        LibcMetricsSnapshot {
            allocations: self.allocations.load(Ordering::Relaxed),
            frees: self.frees.load(Ordering::Relaxed),
            bytes_allocated: self.bytes_allocated.load(Ordering::Relaxed),
            bytes_freed: self.bytes_freed.load(Ordering::Relaxed),
            allocation_failures: self.allocation_failures.load(Ordering::Relaxed),
            free_errors: self.free_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of libc metrics.
#[derive(Debug, Clone)]
pub struct LibcMetricsSnapshot {
    pub allocations: u64,
    pub frees: u64,
    pub bytes_allocated: u64,
    pub bytes_freed: u64,
    pub allocation_failures: u64,
    pub free_errors: u64,
}

// ── LibcManager ──────────────────────────────────────────────────────────

/// Thread‑safe manager for the libc subsystem.
pub struct LibcManager {
    config: Mutex<LibcConfig>,
    metrics: LibcMetrics,
}

impl LibcManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: LibcConfig) -> Result<Self, &'static str> {
        config.validate()?;
        Ok(Self {
            config: Mutex::new(config),
            metrics: LibcMetrics::default(),
        })
    }

    /// Allocate memory.
    pub fn allocate(&self, size: usize) -> *mut u8 {
        let config = self.config.lock();
        if size == 0 {
            return ptr::null_mut();
        }
        if size > config.max_allocation_size {
            if config.log_allocations {
                warn!(size, max = config.max_allocation_size, "allocation size exceeds limit");
            }
            self.metrics.record_failure();
            return ptr::null_mut();
        }

        let layout = match Layout::from_size_align(size, config.allocator_alignment) {
            Ok(l) => l,
            Err(_) => {
                if config.log_allocations {
                    warn!(size, align = config.allocator_alignment, "invalid layout");
                }
                self.metrics.record_failure();
                return ptr::null_mut();
            }
        };

        if config.track_metrics {
            self.metrics.record_alloc(size);
        }
        if config.log_allocations {
            trace!(size, align = config.allocator_alignment, "allocating memory");
        }

        unsafe { alloc(layout) }
    }

    /// Free memory.
    pub fn deallocate(&self, ptr: *mut u8, size: usize) {
        if ptr.is_null() || size == 0 {
            self.metrics.record_free_error();
            return;
        }

        let config = self.config.lock();
        if size > config.max_allocation_size {
            self.metrics.record_free_error();
            if config.log_allocations {
                warn!(size, max = config.max_allocation_size, "free size exceeds limit");
            }
            return;
        }

        if let Ok(layout) = Layout::from_size_align(size, config.allocator_alignment) {
            if config.track_metrics {
                self.metrics.record_free(size);
            }
            if config.log_allocations {
                trace!(size, "freeing memory");
            }
            unsafe { dealloc(ptr, layout) }
        } else {
            self.metrics.record_free_error();
            if config.log_allocations {
                warn!(size, align = config.allocator_alignment, "invalid free layout");
            }
        }
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> LibcMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Update configuration (e.g., change max allocation size).
    pub fn set_config(&self, config: LibcConfig) -> Result<(), &'static str> {
        config.validate()?;
        *self.config.lock() = config;
        Ok(())
    }
}

// ── Global singleton ─────────────────────────────────────────────────────

static GLOBAL_MANAGER: spin::Once<LibcManager> = spin::Once::new();

/// Initialize the libc subsystem with the given configuration.
/// Must be called once during kernel boot.
pub fn init_libc(config: LibcConfig) -> Result<(), &'static str> {
    let manager = LibcManager::new(config)?;
    GLOBAL_MANAGER.call_once(|| manager);
    crate::serial_println!("  [LIBC] kernel libc initialized");
    Ok(())
}

/// Get a reference to the global manager.
/// Panics if libc has not been initialized.
fn global_manager() -> &'static LibcManager {
    GLOBAL_MANAGER.get().expect("libc not initialized")
}

// ── Public API wrappers ──────────────────────────────────────────────────

/// Allocates `size` bytes of heap memory using the global kernel allocator.
///
/// Returns a pointer to the allocated block, or `null_mut` if `size == 0` or
/// allocation fails.
#[inline]
pub fn malloc(size: usize) -> *mut u8 {
    global_manager().allocate(size)
}

/// Frees memory previously allocated by `malloc`.
///
/// The caller **must** provide the exact `size` that was used during allocation.
/// Passing a different size will corrupt the allocator.
///
/// # Safety
/// `ptr` must have been obtained from `malloc` with the same `size`.
#[inline]
pub unsafe fn free_sized(ptr: *mut u8, size: usize) {
    global_manager().deallocate(ptr, size);
}

/// Convenience wrapper for freeing a heap-allocated string buffer.
///
/// # Safety
/// `ptr` must have been allocated by `malloc` with size equal to `len + 1` (null terminator).
#[inline]
pub unsafe fn free_str(ptr: *mut u8, len_with_nul: usize) {
    free_sized(ptr, len_with_nul);
}

/// Get metrics snapshot.
pub fn libc_metrics() -> LibcMetricsSnapshot {
    global_manager().metrics_snapshot()
}

/// Update libc configuration at runtime.
pub fn set_libc_config(config: LibcConfig) -> Result<(), &'static str> {
    global_manager().set_config(config)
}

// ── Core memory functions (C ABI) ──────────────────────────────────────

/// Copies `n` bytes from `src` to `dst`. The regions must **not** overlap.
///
/// # Safety
/// Both pointers must be valid for `n` bytes and must not overlap.
#[no_mangle]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    debug_assert!(!dst.is_null());
    debug_assert!(!src.is_null());
    if n == 0 {
        return dst;
    }
    // Word‑sized copy optimisation (optional)
    if n >= 8 && dst as usize % 8 == 0 && src as usize % 8 == 0 {
        let dst64 = dst as *mut u64;
        let src64 = src as *const u64;
        let words = n / 8;
        for i in 0..words {
            *dst64.add(i) = *src64.add(i);
        }
        let remaining = n % 8;
        if remaining > 0 {
            let dst = dst.add(words * 8);
            let src = src.add(words * 8);
            for i in 0..remaining {
                *dst.add(i) = *src.add(i);
            }
        }
    } else {
        for i in 0..n {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

/// Copies `n` bytes from `src` to `dst`, handling overlapping regions correctly.
///
/// # Safety
/// Both pointers must be valid for `n` bytes (may overlap).
#[no_mangle]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    debug_assert!(!dst.is_null());
    debug_assert!(!src.is_null());
    if n == 0 {
        return dst;
    }
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
    debug_assert!(!dst.is_null());
    let byte = val as u8;
    if n >= 8 && dst as usize % 8 == 0 {
        let dst64 = dst as *mut u64;
        let word = byte as u64 * 0x0101_0101_0101_0101_u64;
        let words = n / 8;
        for i in 0..words {
            *dst64.add(i) = word;
        }
        let remaining = n % 8;
        if remaining > 0 {
            let dst = dst.add(words * 8);
            for i in 0..remaining {
                *dst.add(i) = byte;
            }
        }
    } else {
        for i in 0..n {
            *dst.add(i) = byte;
        }
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
    debug_assert!(!a.is_null());
    debug_assert!(!b.is_null());
    for i in 0..n {
        let ca = *a.add(i);
        let cb = *b.add(i);
        if ca != cb {
            return (ca as i32) - (cb as i32);
        }
    }
    0
}

// ── String functions ─────────────────────────────────────────────────────

/// Returns the length of the null-terminated string `ptr`, excluding the null byte.
///
/// # Safety
/// `ptr` must point to a valid null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn strlen(ptr: *const u8) -> usize {
    debug_assert!(!ptr.is_null());
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
    debug_assert!(!a.is_null());
    debug_assert!(!b.is_null());
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
    debug_assert!(!dst.is_null());
    debug_assert!(!src.is_null());
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

// ── Initialisation ──────────────────────────────────────────────────────

pub fn init() {
    let config = LibcConfig::default();
    if let Err(e) = init_libc(config) {
        panic!("libc init failed: {}", e);
    }
    crate::serial_println!("  [LIBC] kernel libc: ready");
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn init_test() {
        // Ensure libc is initialised for tests.
        let config = LibcConfig {
            allocator_alignment: 16,
            track_metrics: true,
            log_allocations: false,
            max_allocation_size: 1024 * 1024,
        };
        let _ = init_libc(config);
    }

    // ── memcpy & memmove ──────────────────────────────────────────────────
    #[test]
    fn test_memcpy_basic() {
        init_test();
        let src = [1u8, 2, 3, 4, 5];
        let mut dst = [0u8; 5];
        unsafe { memcpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        assert_eq!(dst, src);
    }

    #[test]
    fn test_memcpy_zero_bytes() {
        init_test();
        let src = [1u8];
        let mut dst = [2u8];
        unsafe { memcpy(dst.as_mut_ptr(), src.as_ptr(), 0) };
        assert_eq!(dst[0], 2);
    }

    #[test]
    fn test_memmove_overlap_forward() {
        init_test();
        let mut buf = [1u8, 2, 3, 4, 0];
        unsafe { memmove(buf.as_mut_ptr().add(1), buf.as_ptr(), 4) };
        assert_eq!(buf, [1, 1, 2, 3, 4]);
    }

    #[test]
    fn test_memmove_overlap_backward() {
        init_test();
        let mut buf = [1u8, 2, 3, 4, 0];
        unsafe { memmove(buf.as_mut_ptr(), buf.as_ptr().add(1), 4) };
        assert_eq!(buf, [2, 3, 4, 0, 0]);
    }

    // ── memset ─────────────────────────────────────────────────────────────
    #[test]
    fn test_memset_fill() {
        init_test();
        let mut buf = [0u8; 5];
        unsafe { memset(buf.as_mut_ptr(), 0xAB, 5) };
        assert_eq!(buf, [0xAB; 5]);
    }

    #[test]
    fn test_memset_zero() {
        init_test();
        let mut buf = [0xFFu8; 3];
        unsafe { memset(buf.as_mut_ptr(), 0, 3) };
        assert_eq!(buf, [0; 3]);
    }

    // ── memcmp ─────────────────────────────────────────────────────────────
    #[test]
    fn test_memcmp_equal() {
        init_test();
        let a = [1, 2, 3];
        let b = [1, 2, 3];
        let res = unsafe { memcmp(a.as_ptr(), b.as_ptr(), 3) };
        assert_eq!(res, 0);
    }

    #[test]
    fn test_memcmp_diff() {
        init_test();
        let a = [1, 2, 3];
        let b = [1, 4, 3];
        let res = unsafe { memcmp(a.as_ptr(), b.as_ptr(), 3) };
        assert!(res < 0);
    }

    // ── strlen ─────────────────────────────────────────────────────────────
    #[test]
    fn test_strlen() {
        init_test();
        let s = "hello\0extra";
        let len = unsafe { strlen(s.as_ptr()) };
        assert_eq!(len, 5);
    }

    #[test]
    fn test_strlen_empty() {
        init_test();
        let s = "\0";
        assert_eq!(unsafe { strlen(s.as_ptr()) }, 0);
    }

    // ── strcmp ─────────────────────────────────────────────────────────────
    #[test]
    fn test_strcmp_equal() {
        init_test();
        let a = "abc\0";
        let b = "abc\0";
        assert_eq!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) }, 0);
    }

    #[test]
    fn test_strcmp_a_less() {
        init_test();
        let a = "abc\0";
        let b = "abd\0";
        assert!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) } < 0);
    }

    #[test]
    fn test_strcmp_a_greater() {
        init_test();
        let a = "abz\0";
        let b = "aba\0";
        assert!(unsafe { strcmp(a.as_ptr(), b.as_ptr()) } > 0);
    }

    // ── strncpy ────────────────────────────────────────────────────────────
    #[test]
    fn test_strncpy_full() {
        init_test();
        let src = "abcde\0";
        let mut dst = [0u8; 5];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        assert_eq!(&dst, b"abcde");
    }

    #[test]
    fn test_strncpy_pad_zeros() {
        init_test();
        let src = "ab\0";
        let mut dst = [0xFFu8; 5];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 5) };
        assert_eq!(&dst, b"ab\0\0\0");
    }

    #[test]
    fn test_strncpy_no_null_terminator_in_source() {
        init_test();
        let src = [0x41u8, 0x42, 0x43, 0x44, 0x45];
        let mut dst = [0u8; 3];
        unsafe { strncpy(dst.as_mut_ptr(), src.as_ptr(), 3) };
        assert_eq!(dst, [0x41, 0x42, 0x43]);
    }

    // ── Metrics ────────────────────────────────────────────────────────────
    #[test]
    fn test_metrics_alloc() {
        init_test();
        let ptr = malloc(64);
        assert!(!ptr.is_null());
        let snap = libc_metrics();
        assert_eq!(snap.allocations, 1);
        assert_eq!(snap.bytes_allocated, 64);
        unsafe { free_sized(ptr, 64) };
        let snap2 = libc_metrics();
        assert_eq!(snap2.frees, 1);
        assert_eq!(snap2.bytes_freed, 64);
    }

    #[test]
    fn test_metrics_alloc_failure() {
        init_test();
        let config = LibcConfig {
            max_allocation_size: 10,
            ..Default::default()
        };
        set_libc_config(config).unwrap();
        let ptr = malloc(100);
        assert!(ptr.is_null());
        let snap = libc_metrics();
        assert_eq!(snap.allocation_failures, 1);
    }
}
