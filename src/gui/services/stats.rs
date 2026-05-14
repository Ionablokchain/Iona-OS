pub fn cpu_pct() -> u8 {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    (30 + (ms / 120) % 40) as u8
}
pub fn ram_pct() -> u8 {
    let (tf, uf) = crate::memory::frame_alloc::stats();
    if tf == 0 { 0 } else { (uf * 100 / tf) as u8 }
}
pub fn disk_pct() -> u8 { 55 }
pub fn tx_mb() -> f32 {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    ((ms / 50) % 40) as f32 / 10.0
}
pub fn rx_mb() -> f32 {
    let ms = crate::arch::x86_64::timer::uptime_ms();
    ((ms / 70) % 25) as f32 / 10.0
}
