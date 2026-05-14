//! Easing functions — M-02 fix: .powi() replaced with manual multiply
//! .powi() is an intrinsic and works on x86_64-unknown-none with SSE2,
//! but manual multiply is safer for future ARM/RISC-V ports without FPU.

pub fn ease_out_cubic(t: f32) -> f32 {
    let u = 1.0 - t.clamp(0.0, 1.0);
    1.0 - u * u * u
}
pub fn ease_in_out(t: f32) -> f32 {
    let t = t.clamp(0.0, 1.0);
    if t < 0.5 {
        2.0 * t * t
    } else {
        let u = -2.0 * t + 2.0;
        1.0 - u * u / 2.0
    }
}
pub fn ease_in_quad(t: f32) -> f32 { let t = t.clamp(0.0,1.0); t * t }
pub fn ease_out_quad(t: f32) -> f32 { let t = t.clamp(0.0,1.0); 1.0 - (1.0-t)*(1.0-t) }
pub fn linear(t: f32) -> f32 { t.clamp(0.0, 1.0) }
