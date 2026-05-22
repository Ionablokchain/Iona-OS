//! Interrupt utilities — enable, disable, and critical sections.
//!
//! This module provides a safe interface to the CPU's interrupt flag (IF)
//! on x86_64. It wraps the raw `sti` and `cli` instructions with Rust
//! functions that respect the calling conventions and allow interrupt‑free
//! critical sections.
//!
//! # Safety
//!
//! Disabling interrupts is inherently unsafe if not done carefully.
//! The recommended way to run a critical section is `without_interrupts`,
//! which guarantees that interrupts are restored to their previous state.
//! Directly using `disable()` / `enable()` can lead to unbalanced pairs
//! and hard‑to‑debug bugs.

use x86_64::instructions::interrupts;

// -----------------------------------------------------------------------------
// Basic operations
// -----------------------------------------------------------------------------

/// Disable interrupts on the current CPU (`cli` instruction).
///
/// After this function returns, no maskable interrupts will be delivered.
/// Use `enable()` to re‑enable them.
///
/// # Safety
///
/// This function is unsafe because the caller must ensure that interrupts
/// are re‑enabled at some point, and that no critical code relies on them
/// being disabled for too long (which could cause system stalls, missed
/// timer ticks, or deadlocks).
///
/// Prefer `without_interrupts` for most use cases.
#[inline(always)]
pub unsafe fn disable() {
    interrupts::disable();
}

/// Enable interrupts on the current CPU (`sti` instruction).
///
/// # Safety
///
/// This function is safe to call from any context, but it is marked `unsafe`
/// to discourage unbalanced enable/disable pairs. Use `without_interrupts`
/// instead.
#[inline(always)]
pub unsafe fn enable() {
    interrupts::enable();
}

/// Check whether interrupts are currently enabled on the current CPU.
///
/// This reads the interrupt flag (IF) via the `pushf` / `popf` instructions.
/// The result is `true` if maskable interrupts are allowed.
///
/// # Example
/// ```
/// use iona_os::interrupts;
/// let enabled = interrupts::are_enabled();
/// println!("Interrupts are {}", if enabled { "enabled" } else { "disabled" });
/// ```
#[inline(always)]
pub fn are_enabled() -> bool {
    interrupts::are_enabled()
}

// -----------------------------------------------------------------------------
// Critical sections
// -----------------------------------------------------------------------------

/// Execute a closure with interrupts disabled, restoring the previous
/// interrupt state after the closure returns.
///
/// This is the safe and recommended way to run code that must not be
/// interrupted. It works even if interrupts were already disabled before
/// the call – the original state is always restored.
///
/// # Returns
///
/// The value returned by the closure `f`.
///
/// # Example
/// ```
/// use iona_os::interrupts;
/// let x = interrupts::without_interrupts(|| {
///     // This code runs with interrupts disabled.
///     42
/// });
/// assert_eq!(x, 42);
/// // Interrupts are re‑enabled (if they were enabled before) here.
/// ```
///
/// # Performance
///
/// Disabling interrupts is very cheap (a few cycles) but should still be
/// used only for short critical sections (a few microseconds).
pub fn without_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    interrupts::without_interrupts(f)
}

/// Execute a closure **with interrupts enabled**, restoring the previous
/// interrupt state afterwards. This is useful when you are in a context
/// where interrupts are currently disabled (e.g., an interrupt handler)
/// but you need to temporarily enable them, for example to allow a
/// higher‑priority interrupt to fire.
///
/// # Safety
///
/// This function is safe to call, but enabling interrupts inside a context
/// that expects them to be disabled (like a low‑level driver critical
/// section) can lead to re‑entrancy and data races. Use only when you
/// fully understand the consequences.
///
/// # Example
/// ```
/// use iona_os::interrupts;
/// // Assume interrupts are disabled here.
/// let result = interrupts::with_interrupts(|| {
///     // Interrupts are temporarily enabled inside this closure.
///     do_something_that_may_block();
/// });
/// // Back to disabled state.
/// ```
pub fn with_interrupts<F, R>(f: F) -> R
where
    F: FnOnce() -> R,
{
    let was_enabled = are_enabled();
    if !was_enabled {
        unsafe { enable(); }
    }
    let result = f();
    if !was_enabled {
        unsafe { disable(); }
    }
    result
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_interrupts_restores_state() {
        let initially_enabled = are_enabled();
        let inside = without_interrupts(|| {
            // Interrupts should be disabled inside
            assert!(!are_enabled());
            true
        });
        assert!(inside);
        assert_eq!(are_enabled(), initially_enabled);
    }

    #[test]
    fn with_interrupts_temporarily_enables() {
        // Start with interrupts disabled
        let _ = without_interrupts(|| {
            assert!(!are_enabled());
            let result = with_interrupts(|| {
                // Inside the closure they should be enabled
                assert!(are_enabled());
                42
            });
            assert_eq!(result, 42);
            // After returning, they should be disabled again
            assert!(!are_enabled());
        });
        // Original state restored
    }
}
