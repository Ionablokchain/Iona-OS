/// Simple linear interpolation between two values
pub fn lerp(a: f32, b: f32, t: f32) -> f32 { a + (b - a) * t.clamp(0.0, 1.0) }
pub fn lerp_u8(a: u8, b: u8, t: f32) -> u8 { lerp(a as f32, b as f32, t) as u8 }
/// Elapsed fraction [0,1] given start_ms, duration_ms, now_ms
pub fn progress(start_ms: u64, dur_ms: u64, now_ms: u64) -> f32 {
    if dur_ms == 0 { return 1.0; }
    ((now_ms.saturating_sub(start_ms)) as f32 / dur_ms as f32).min(1.0)
}
