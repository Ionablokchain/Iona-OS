//! Interrupt utilities
pub fn disable() { x86_64::instructions::interrupts::disable(); }
pub fn enable()  { x86_64::instructions::interrupts::enable();  }
pub fn without_interrupts<F, R>(f: F) -> R
    where F: FnOnce() -> R
{
    x86_64::instructions::interrupts::without_interrupts(f)
}
