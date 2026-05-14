//! Synchronization primitives pentru kernel
//!
//! spin::Mutex — spinlock fără OS (cel mai simplu, corect pentru kernel)
//! spin::Lazy  — inițializare lazily, thread-safe
//!
//! Re-exportăm spin pentru a fi folosit în tot kernelul


/// Execută un closure fără întreruperi (critical section)
/// Evităm deadlock-uri când lockul e ținut și apare un interrupt
/// care și el încearcă să ia lockul
#[inline(always)]
pub fn critical<F, R>(f: F) -> R
    where F: FnOnce() -> R
{
    x86_64::instructions::interrupts::without_interrupts(f)
}
