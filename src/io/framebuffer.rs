//! Framebuffer — double buffer + dirty rect invalidation.
//!
//! Design:
//!   BACK_BUF: Vec<u32>           – all drawing goes here (ARGB 32bpp)
//!   DIRTY_LIST: Vec<DirtyRect>   – zones marked as modified (max 32)
//!   present()                    – copies ONLY dirty regions to VRAM
//!   present_full()               – full blit (at boot or if dirty > 32)
//!
//! Benefit of dirty rects:
//!   Static desktop    → 0 bytes copied to VRAM per frame
//!   Cursor drag       → ~14×22px per frame (not 1920×1080)
//!   Window move       → only the frame rectangle (not whole screen)
//!
//! Merge strategy: if two rects overlap or are adjacent, merge into a bounding box.
//!   If the list exceeds 32, fallback to full blit.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                       Framebuffer Manager                              │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (FbCfg)     │ (FbError)    │ (FbMetrics)   │ (DirtyRect, BackBuf)     │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Hardware  │    Dirty     │    Drawing    │        Presenter         │
//! │ (VRAM, Hw)  │ (list, merge)│ (primitives)  │ (blit, full/partial)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Manager   │    Legacy    │               │                          │
//! │ (FbMgr)     │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::drivers::framebuffer::{FramebufferManager, FramebufferConfig};
//!
//! let config = FramebufferConfig::default();
//! let manager = FramebufferManager::new(config);
//! manager.init(fb);
//! manager.fill_rect(10, 10, 100, 100, 0xFF, 0x00, 0x00);
//! manager.present();
//! ```

#![allow(dead_code)]

use bootloader_api::info::{FrameBuffer, PixelFormat};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the framebuffer subsystem.
    pub const DEFAULT_MAX_DIRTY_RECTS: usize = 32;
    pub const DEFAULT_CURSOR_W: usize = 14;
    pub const DEFAULT_CURSOR_H: usize = 22;
}

pub mod config {
    //! Configuration for the framebuffer.
    use serde::{Deserialize, Serialize};
    use super::constants::DEFAULT_MAX_DIRTY_RECTS;

    /// Configuration for the framebuffer.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FramebufferConfig {
        pub max_dirty_rects: usize,
        pub double_buffer_enabled: bool,
        pub collect_metrics: bool,
        pub log_operations: bool,
        pub default_bg_rgb: u32,
    }

    impl Default for FramebufferConfig {
        fn default() -> Self {
            Self {
                max_dirty_rects: DEFAULT_MAX_DIRTY_RECTS,
                double_buffer_enabled: true,
                collect_metrics: true,
                log_operations: false,
                default_bg_rgb: 0x0A0E1A,
            }
        }
    }

    impl FramebufferConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_dirty_rects == 0 {
                return Err("max_dirty_rects must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the framebuffer.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum FramebufferError {
        #[error("framebuffer not initialised")]
        NotInitialised,

        #[error("invalid dimensions: width={w}, height={h}")]
        InvalidDimensions { w: usize, h: usize },

        #[error("invalid pixel format: {0:?}")]
        UnsupportedPixelFormat(PixelFormat),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("I/O error: {0}")]
        Io(String),
    }

    pub type FramebufferResult<T> = Result<T, FramebufferError>;
}

pub mod types {
    //! Core types for the framebuffer.
    use super::constants::{DEFAULT_CURSOR_W, DEFAULT_CURSOR_H};
    use bootloader_api::info::PixelFormat;
    use alloc::vec::Vec;

    /// A dirty rectangle.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct DirtyRect {
        pub x: usize,
        pub y: usize,
        pub w: usize,
        pub h: usize,
    }

    impl DirtyRect {
        pub fn right(&self) -> usize { self.x + self.w }
        pub fn bottom(&self) -> usize { self.y + self.h }

        /// True if rectangles overlap or touch (horizontally or vertically adjacent).
        pub fn overlaps_or_adjacent(&self, o: &DirtyRect) -> bool {
            self.x <= o.right() && o.x <= self.right() &&
            self.y <= o.bottom() && o.y <= self.bottom()
        }

        /// Merge into bounding box.
        pub fn merge(&self, o: &DirtyRect) -> DirtyRect {
            let x1 = self.x.min(o.x);
            let y1 = self.y.min(o.y);
            let x2 = self.right().max(o.right());
            let y2 = self.bottom().max(o.bottom());
            DirtyRect { x: x1, y: y1, w: x2 - x1, h: y2 - y1 }
        }
    }

    /// Hardware framebuffer metadata.
    pub struct HardwareFb {
        pub base: *mut u8,
        pub width: usize,
        pub height: usize,
        pub stride: usize,
        pub bpp: usize,
        pub format: PixelFormat,
    }

    // Safety: the framebuffer is a shared resource; we protect it with a Mutex.
    unsafe impl Send for HardwareFb {}

    /// Back buffer.
    pub struct BackBuffer {
        pub pixels: Vec<u32>,
        pub width: usize,
        pub height: usize,
    }

    impl BackBuffer {
        pub fn new(width: usize, height: usize) -> Self {
            Self {
                pixels: alloc::vec![0u32; width * height],
                width,
                height,
            }
        }

        pub fn resize(&mut self, width: usize, height: usize) {
            self.width = width;
            self.height = height;
            self.pixels.resize(width * height, 0);
        }

        pub fn clear(&mut self, color: u32) {
            self.pixels.fill(color);
        }

        pub fn set_pixel(&mut self, x: usize, y: usize, color: u32) {
            if x < self.width && y < self.height {
                self.pixels[y * self.width + x] = color;
            }
        }

        pub fn get_pixel(&self, x: usize, y: usize) -> u32 {
            if x < self.width && y < self.height {
                self.pixels[y * self.width + x]
            } else {
                0
            }
        }
    }

    /// Cursor dimensions (imported from font module).
    pub const CURSOR_W: usize = DEFAULT_CURSOR_W;
    pub const CURSOR_H: usize = DEFAULT_CURSOR_H;
}

pub mod metrics {
    //! Metrics for the framebuffer.
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct FramebufferMetrics {
        pub frames_presented: AtomicU64,
        pub full_blits: AtomicU64,
        pub partial_blits: AtomicU64,
        pub dirty_rects_processed: AtomicU64,
        pub bytes_copied: AtomicU64,
        pub draw_calls: AtomicU64,
        pub merged_rects: AtomicU64,
    }

    impl FramebufferMetrics {
        pub fn inc_frame(&self, is_full: bool, rect_count: usize, bytes: usize) {
            self.frames_presented.fetch_add(1, Ordering::Relaxed);
            if is_full {
                self.full_blits.fetch_add(1, Ordering::Relaxed);
            } else {
                self.partial_blits.fetch_add(1, Ordering::Relaxed);
            }
            self.dirty_rects_processed
                .fetch_add(rect_count as u64, Ordering::Relaxed);
            self.bytes_copied.fetch_add(bytes as u64, Ordering::Relaxed);
        }

        pub fn inc_draw(&self) {
            self.draw_calls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn inc_merged(&self) {
            self.merged_rects.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> FramebufferMetricsSnapshot {
            FramebufferMetricsSnapshot {
                frames_presented: self.frames_presented.load(Ordering::Relaxed),
                full_blits: self.full_blits.load(Ordering::Relaxed),
                partial_blits: self.partial_blits.load(Ordering::Relaxed),
                dirty_rects_processed: self.dirty_rects_processed.load(Ordering::Relaxed),
                bytes_copied: self.bytes_copied.load(Ordering::Relaxed),
                draw_calls: self.draw_calls.load(Ordering::Relaxed),
                merged_rects: self.merged_rects.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct FramebufferMetricsSnapshot {
        pub frames_presented: u64,
        pub full_blits: u64,
        pub partial_blits: u64,
        pub dirty_rects_processed: u64,
        pub bytes_copied: u64,
        pub draw_calls: u64,
        pub merged_rects: u64,
    }
}

pub mod dirty {
    //! Dirty rectangle list with merging.
    use super::{
        config::FramebufferConfig,
        types::DirtyRect,
        metrics::FramebufferMetrics,
    };
    use core::fmt;

    /// Dirty list with a fixed maximum.
    pub struct DirtyList {
        rects: Vec<DirtyRect>,
        max: usize,
        full: bool, // if true, next present() will do full blit.
    }

    impl DirtyList {
        pub fn new(config: &FramebufferConfig) -> Self {
            Self {
                rects: Vec::with_capacity(config.max_dirty_rects),
                max: config.max_dirty_rects,
                full: true, // boot = full blit
            }
        }

        pub fn clear(&mut self) {
            self.rects.clear();
            self.full = false;
        }

        pub fn push(&mut self, r: DirtyRect, screen_w: usize, screen_h: usize, metrics: &FramebufferMetrics) {
            if self.full {
                return;
            }
            // Clamp to screen.
            if r.x >= screen_w || r.y >= screen_h {
                return;
            }
            let mut r = r;
            r.w = r.w.min(screen_w - r.x);
            r.h = r.h.min(screen_h - r.y);
            if r.w == 0 || r.h == 0 {
                return;
            }

            // Try to merge with existing rects.
            for i in 0..self.rects.len() {
                if self.rects[i].overlaps_or_adjacent(&r) {
                    self.rects[i] = self.rects[i].merge(&r);
                    metrics.inc_merged();
                    // Re-merge with others.
                    let merged = self.rects[i];
                    let mut j = 0;
                    while j < self.rects.len() {
                        if j != i && self.rects[j].overlaps_or_adjacent(&merged) {
                            self.rects[i] = self.rects[i].merge(&self.rects[j]);
                            self.rects.swap_remove(j);
                            metrics.inc_merged();
                        } else {
                            j += 1;
                        }
                    }
                    return;
                }
            }

            // Add new rect.
            if self.rects.len() < self.max {
                self.rects.push(r);
            } else {
                // Too many rects → fallback to full blit.
                self.full = true;
                self.rects.clear();
            }
        }

        pub fn is_dirty(&self) -> bool {
            self.full || !self.rects.is_empty()
        }

        pub fn rects(&self) -> &[DirtyRect] {
            &self.rects
        }

        pub fn is_full(&self) -> bool {
            self.full
        }

        pub fn set_full(&mut self) {
            self.full = true;
            self.rects.clear();
        }

        pub fn count(&self) -> usize {
            self.rects.len()
        }
    }
}

pub mod vram {
    //! Hardware framebuffer access and blitting.
    use super::{
        types::{HardwareFb, BackBuffer, DirtyRect},
        error::{FramebufferError, FramebufferResult},
        metrics::FramebufferMetrics,
    };
    use bootloader_api::info::PixelFormat;
    use core::ptr;

    /// Write a pixel to VRAM.
    #[inline]
    unsafe fn write_pixel_to_vram(
        base: *mut u8,
        offset: usize,
        bpp: usize,
        px: u32,
        fmt: PixelFormat,
    ) {
        let r = ((px >> 16) & 0xFF) as u8;
        let g = ((px >> 8) & 0xFF) as u8;
        let b = (px & 0xFF) as u8;
        match fmt {
            PixelFormat::Bgr => {
                *base.add(offset) = b;
                *base.add(offset + 1) = g;
                *base.add(offset + 2) = r;
                if bpp >= 4 {
                    *base.add(offset + 3) = 0xFF;
                }
            }
            PixelFormat::Rgb => {
                *base.add(offset) = r;
                *base.add(offset + 1) = g;
                *base.add(offset + 2) = b;
                if bpp >= 4 {
                    *base.add(offset + 3) = 0xFF;
                }
            }
            _ => {
                // Fallback: BGR.
                *base.add(offset) = b;
                *base.add(offset + 1) = g;
                *base.add(offset + 2) = r;
            }
        }
    }

    /// Blit a region from the back buffer to VRAM.
    pub fn blit_region(
        hw: &HardwareFb,
        back: &BackBuffer,
        rect: DirtyRect,
        metrics: &FramebufferMetrics,
    ) -> FramebufferResult<usize> {
        let x = rect.x;
        let y = rect.y;
        let w = rect.w;
        let h = rect.h;

        let x2 = (x + w).min(hw.width).min(back.width);
        let y2 = (y + h).min(hw.height).min(back.height);
        if x >= x2 || y >= y2 {
            return Ok(0);
        }

        let cols = x2 - x;
        let rows = y2 - y;
        let bytes_per_row = cols * hw.bpp;

        unsafe {
            for row in y..y2 {
                let src_base = row * back.width + x;
                let dst_base = (row * hw.stride + x) * hw.bpp;
                for col in 0..cols {
                    let px = back.pixels[src_base + col];
                    write_pixel_to_vram(hw.base, dst_base + col * hw.bpp, hw.bpp, px, hw.format);
                }
            }
        }

        let bytes_copied = rows * bytes_per_row;
        metrics.inc_frame(false, 1, bytes_copied);
        Ok(bytes_copied)
    }

    /// Blit the entire screen.
    pub fn blit_full(
        hw: &HardwareFb,
        back: &BackBuffer,
        metrics: &FramebufferMetrics,
    ) -> FramebufferResult<usize> {
        let rect = DirtyRect {
            x: 0,
            y: 0,
            w: hw.width,
            h: hw.height,
        };
        let bytes = blit_region(hw, back, rect, metrics)?;
        metrics.inc_frame(true, 0, bytes);
        Ok(bytes)
    }
}

pub mod draw {
    //! Drawing primitives on the back buffer.
    use super::{
        types::BackBuffer,
        metrics::FramebufferMetrics,
    };
    use crate::io::font;

    /// Pack RGB into u32.
    #[inline]
    pub fn pack_rgb(r: u8, g: u8, b: u8) -> u32 {
        ((r as u32) << 16) | ((g as u32) << 8) | (b as u32)
    }

    /// Set a pixel in the back buffer.
    pub fn set_pixel(back: &mut BackBuffer, x: usize, y: usize, color: u32) {
        if x < back.width && y < back.height {
            back.pixels[y * back.width + x] = color;
        }
    }

    /// Fill a rectangle.
    pub fn fill_rect(back: &mut BackBuffer, x: usize, y: usize, w: usize, h: usize, color: u32) {
        let x2 = (x + w).min(back.width);
        let y2 = (y + h).min(back.height);
        if x >= x2 || y >= y2 {
            return;
        }
        let rows = y2 - y;
        let cols = x2 - x;
        for row in 0..rows {
            let dst = (y + row) * back.width + x;
            for col in 0..cols {
                back.pixels[dst + col] = color;
            }
        }
    }

    /// Clear the entire back buffer.
    pub fn clear(back: &mut BackBuffer, color: u32) {
        back.pixels.fill(color);
    }

    /// Draw text using the built-in font.
    pub fn draw_text(back: &mut BackBuffer, x: usize, y: usize, text: &str, color: u32) {
        let mut cx = x;
        for ch in text.chars() {
            if let Some(glyph) = font::get_glyph(ch) {
                for row in 0..font::FONT_HEIGHT {
                    let row_data = glyph[row];
                    for col in 0..font::FONT_WIDTH {
                        if (row_data >> (font::FONT_WIDTH - 1 - col)) & 1 != 0 {
                            let px = x + col + cx;
                            let py = y + row;
                            if px < back.width && py < back.height {
                                back.pixels[py * back.width + px] = color;
                            }
                        }
                    }
                }
                cx += font::FONT_WIDTH;
            } else {
                cx += font::FONT_WIDTH; // skip unknown
            }
        }
    }

    /// Draw text with RGB separately.
    pub fn draw_text_col(back: &mut BackBuffer, x: usize, y: usize, text: &str, r: u8, g: u8, b: u8) {
        draw_text(back, x, y, text, pack_rgb(r, g, b));
    }

    /// Blend a pixel.
    pub fn blend_pixel(back: &mut BackBuffer, x: usize, y: usize, r: u8, g: u8, b: u8, alpha: u8) {
        if x >= back.width || y >= back.height {
            return;
        }
        let a = alpha as u32;
        let ia = 255 - a;
        let idx = y * back.width + x;
        let dst = back.pixels[idx];
        let nr = ((r as u32 * a + ((dst >> 16) & 0xFF) * ia) / 255) as u8;
        let ng = ((g as u32 * a + ((dst >> 8) & 0xFF) * ia) / 255) as u8;
        let nb = ((b as u32 * a + (dst & 0xFF) * ia) / 255) as u8;
        back.pixels[idx] = pack_rgb(nr, ng, nb);
    }

    /// Blit a mask (e.g., cursor).
    pub fn blit_mask(
        back: &mut BackBuffer,
        px: usize,
        py: usize,
        w: usize,
        h: usize,
        mask: &[u8],
        color: u32,
        stride: usize,
    ) {
        for row in 0..h {
            let sy = py + row;
            if sy >= back.height {
                break;
            }
            for col in 0..w {
                let sx = px + col;
                if sx >= back.width {
                    continue;
                }
                let bi = row * stride + col / 8;
                if bi < mask.len() && (mask[bi] & (0x80 >> (col % 8))) != 0 {
                    back.pixels[sy * back.width + sx] = color;
                }
            }
        }
    }

    /// Blit a pixel buffer.
    pub fn blit_pixels(
        back: &mut BackBuffer,
        dx: usize,
        dy: usize,
        w: usize,
        h: usize,
        pixels: &[u32],
        stride: usize,
    ) {
        let x2 = (dx + w).min(back.width);
        let y2 = (dy + h).min(back.height);
        if dx >= x2 || dy >= y2 {
            return;
        }
        let cols = x2 - dx;
        let rows = y2 - dy;
        for row in 0..rows {
            let src = row * stride;
            let dst = (dy + row) * back.width + dx;
            let n = cols.min(pixels.len().saturating_sub(src));
            if dst + n <= back.pixels.len() && src + n <= pixels.len() {
                back.pixels[dst..dst + n].copy_from_slice(&pixels[src..src + n]);
            }
        }
    }
}

pub mod presenter {
    //! The presenter handles the double‑buffer and dirty rect logic.
    use super::{
        config::FramebufferConfig,
        error::{FramebufferError, FramebufferResult},
        types::{HardwareFb, BackBuffer, DirtyRect},
        dirty::DirtyList,
        metrics::FramebufferMetrics,
        vram,
    };
    use bootloader_api::info::PixelFormat;

    /// The core framebuffer presenter.
    pub struct FramebufferPresenter {
        config: FramebufferConfig,
        metrics: FramebufferMetrics,
        hw: Option<HardwareFb>,
        back: BackBuffer,
        dirty: DirtyList,
    }

    impl FramebufferPresenter {
        pub fn new(config: FramebufferConfig) -> Self {
            config.validate().expect("invalid FramebufferConfig");
            let dirty = DirtyList::new(&config);
            let back = BackBuffer::new(0, 0);
            Self {
                config,
                metrics: FramebufferMetrics::default(),
                hw: None,
                back,
                dirty,
            }
        }

        pub fn init(&mut self, fb: &'static mut FrameBuffer) -> FramebufferResult<()> {
            let info = fb.info();
            let base = fb.buffer_mut().as_mut_ptr();
            let hw = HardwareFb {
                base,
                width: info.width,
                height: info.height,
                stride: info.stride,
                bpp: info.bytes_per_pixel,
                format: info.pixel_format,
            };
            self.hw = Some(hw);
            self.back.resize(info.width, info.height);
            self.dirty.set_full();
            if self.config.log_operations {
                tracing::info!(
                    width = info.width,
                    height = info.height,
                    "framebuffer initialised"
                );
            }
            Ok(())
        }

        pub fn width(&self) -> usize {
            self.back.width
        }

        pub fn height(&self) -> usize {
            self.back.height
        }

        pub fn metrics(&self) -> &FramebufferMetrics {
            &self.metrics
        }

        /// Mark a region as dirty.
        pub fn mark_dirty(&mut self, x: usize, y: usize, w: usize, h: usize) {
            let r = DirtyRect { x, y, w, h };
            self.dirty.push(r, self.back.width, self.back.height, &self.metrics);
        }

        /// Mark the entire screen as dirty.
        pub fn mark_all_dirty(&mut self) {
            self.dirty.set_full();
        }

        /// Present the dirty regions to the screen.
        pub fn present(&mut self) -> FramebufferResult<()> {
            if !self.dirty.is_dirty() {
                return Ok(());
            }
            let hw = self.hw.as_ref().ok_or(FramebufferError::NotInitialised)?;
            if self.back.pixels.is_empty() {
                return Ok(());
            }

            if self.dirty.is_full() {
                vram::blit_full(hw, &self.back, &self.metrics)?;
            } else {
                let rects: Vec<DirtyRect> = self.dirty.rects().to_vec();
                for r in rects {
                    vram::blit_region(hw, &self.back, r, &self.metrics)?;
                }
            }
            self.dirty.clear();
            Ok(())
        }

        /// Present the full screen (force full blit).
        pub fn present_full(&mut self) -> FramebufferResult<()> {
            self.dirty.set_full();
            self.present()
        }

        /// Get a mutable reference to the back buffer (for drawing).
        pub fn back_buffer_mut(&mut self) -> &mut BackBuffer {
            &mut self.back
        }

        /// Get a reference to the back buffer.
        pub fn back_buffer(&self) -> &BackBuffer {
            &self.back
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::FramebufferConfig;
pub use error::{FramebufferError, FramebufferResult};
pub use types::{DirtyRect, HardwareFb, BackBuffer, CURSOR_W, CURSOR_H};
pub use metrics::{FramebufferMetrics, FramebufferMetricsSnapshot};
pub use presenter::FramebufferPresenter;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Mutex;

static GLOBAL_PRESENTER: Mutex<Option<FramebufferPresenter>> = Mutex::new(None);

/// Initialise the framebuffer subsystem with the given FrameBuffer.
pub fn init(fb: &'static mut FrameBuffer) {
    let config = FramebufferConfig::default();
    let mut presenter = FramebufferPresenter::new(config);
    presenter.init(fb).expect("framebuffer init failed");
    *GLOBAL_PRESENTER.lock() = Some(presenter);
    crate::serial_println!("  [FB] double buffer {}x{}, dirty-rect ({} slots)",
        fb.info().width, fb.info().height, config.max_dirty_rects);
}

/// Get a mutable reference to the global presenter.
fn with_presenter<F, R>(f: F) -> R
where
    F: FnOnce(&mut FramebufferPresenter) -> R,
{
    let mut guard = GLOBAL_PRESENTER.lock();
    let presenter = guard.as_mut().expect("framebuffer not initialized");
    f(presenter)
}

/// Get a reference to the global presenter (read-only).
fn with_presenter_ro<F, R>(f: F) -> R
where
    F: FnOnce(&FramebufferPresenter) -> R,
{
    let guard = GLOBAL_PRESENTER.lock();
    let presenter = guard.as_ref().expect("framebuffer not initialized");
    f(presenter)
}

/// Mark a region as dirty.
pub fn mark_dirty(x: usize, y: usize, w: usize, h: usize) {
    with_presenter(|p| p.mark_dirty(x, y, w, h));
}

/// Mark the entire screen as dirty.
pub fn mark_all_dirty() {
    with_presenter(|p| p.mark_all_dirty());
}

/// Present dirty regions.
pub fn present() {
    let _ = with_presenter(|p| p.present());
}

/// Present full screen.
pub fn present_full() {
    let _ = with_presenter(|p| p.present_full());
}

/// Get screen width.
pub fn width() -> usize {
    with_presenter_ro(|p| p.width())
}

/// Get screen height.
pub fn height() -> usize {
    with_presenter_ro(|p| p.height())
}

/// Get screen size.
pub fn size() -> (usize, usize) {
    with_presenter_ro(|p| (p.width(), p.height()))
}

/// Set a pixel.
pub fn set_pixel(x: usize, y: usize, r: u8, g: u8, b: u8) {
    let color = draw::pack_rgb(r, g, b);
    with_presenter(|p| {
        draw::set_pixel(p.back_buffer_mut(), x, y, color);
        p.mark_dirty(x, y, 1, 1);
    });
}

/// Fill a rectangle.
pub fn fill_rect(x: usize, y: usize, w: usize, h: usize, r: u8, g: u8, b: u8) {
    let color = draw::pack_rgb(r, g, b);
    with_presenter(|p| {
        draw::fill_rect(p.back_buffer_mut(), x, y, w, h, color);
        p.mark_dirty(x, y, w, h);
    });
}

/// Clear the screen with a given color.
pub fn clear(rgb_val: u32) {
    with_presenter(|p| {
        draw::clear(p.back_buffer_mut(), rgb_val);
        p.mark_all_dirty();
    });
}

/// Blend a pixel.
pub fn blend_pixel(x: usize, y: usize, r: u8, g: u8, b: u8, alpha: u8) {
    with_presenter(|p| {
        draw::blend_pixel(p.back_buffer_mut(), x, y, r, g, b, alpha);
        p.mark_dirty(x, y, 1, 1);
    });
}

/// Draw text with colour.
pub fn draw_text_col(x: usize, y: usize, text: &str, r: u8, g: u8, b: u8) {
    let color = draw::pack_rgb(r, g, b);
    with_presenter(|p| {
        draw::draw_text(p.back_buffer_mut(), x, y, text, color);
        // Approximate dirty rect: width * len * 8, height = font height.
        let w = text.len() * 8;
        let h = crate::io::font::FONT_HEIGHT;
        p.mark_dirty(x, y, w, h);
    });
}

/// Draw a rectangle outline.
pub fn draw_rect(x: usize, y: usize, w: usize, h: usize, r: u8, g: u8, b: u8) {
    if w == 0 || h == 0 { return; }
    fill_rect(x, y, w, 1, r, g, b);
    fill_rect(x, y + h - 1, w, 1, r, g, b);
    fill_rect(x, y, 1, h, r, g, b);
    fill_rect(x + w - 1, y, 1, h, r, g, b);
    mark_dirty(x, y, w, h);
}

/// Horizontal line.
pub fn hline(x: usize, y: usize, w: usize, r: u8, g: u8, b: u8) {
    fill_rect(x, y, w, 1, r, g, b);
}

/// Vertical line.
pub fn vline(x: usize, y: usize, h: usize, r: u8, g: u8, b: u8) {
    fill_rect(x, y, 1, h, r, g, b);
}

/// Blit a mask (e.g., cursor).
pub fn blit_mask(px: usize, py: usize, w: usize, h: usize, mask: &[u8], r: u8, g: u8, b: u8) {
    let color = draw::pack_rgb(r, g, b);
    with_presenter(|p| {
        draw::blit_mask(p.back_buffer_mut(), px, py, w, h, mask, color, (w + 7) / 8);
        p.mark_dirty(px, py, w, h);
    });
}

/// Blit a pixel buffer.
pub fn blit_pixels(dx: usize, dy: usize, w: usize, h: usize, pixels: &[u32], stride: usize) {
    with_presenter(|p| {
        draw::blit_pixels(p.back_buffer_mut(), dx, dy, w, h, pixels, stride);
        p.mark_dirty(dx, dy, w, h);
    });
}

/// Draw the cursor at the given position.
pub fn draw_cursor(x: usize, y: usize) {
    use crate::io::font::{CURSOR_W, CURSOR_H, CURSOR_MASK, CURSOR_OUTLINE};
    blit_mask(x + 1, y + 1, CURSOR_W, CURSOR_H, &CURSOR_MASK, 30, 30, 30);
    blit_mask(x, y, CURSOR_W, CURSOR_H, &CURSOR_MASK, 255, 255, 255);
    blit_mask(x, y, CURSOR_W, CURSOR_H, &CURSOR_OUTLINE, 0, 0, 0);
    mark_dirty(x, y, CURSOR_W + 2, CURSOR_H + 2);
}

/// Erase the cursor.
pub fn erase_cursor(x: usize, y: usize, bg_rgb: u32) {
    let (r, g, b) = ((bg_rgb >> 16) as u8, ((bg_rgb >> 8) & 0xFF) as u8, (bg_rgb & 0xFF) as u8);
    fill_rect(x, y, CURSOR_W + 2, CURSOR_H + 2, r, g, b);
    mark_dirty(x, y, CURSOR_W + 2, CURSOR_H + 2);
}

/// Draw the boot splash screen.
pub fn draw_boot_splash() {
    let w = width();
    let h = height();
    if w == 0 || h == 0 { return; }
    fill_rect(0, 0, w, h, 0x0A, 0x0E, 0x1A);
    let logo = "IONA OS";
    let lw = logo.len() * 8;
    let lx = (w.saturating_sub(lw)) / 2;
    let ly = h / 2 - 20;
    draw_text_col(lx, ly, logo, 0x4A, 0x9E, 0xFF);
    let sub = "v0.6.0 — Booting...";
    let sw = sub.len() * 8;
    let sx = (w.saturating_sub(sw)) / 2;
    draw_text_col(sx, ly + 20, sub, 0x80, 0x80, 0xA0);
    present();
}

/// Alias for draw_boot_splash.
pub fn draw_logo() {
    draw_boot_splash();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dirty_rect_merge() {
        let r1 = DirtyRect { x: 0, y: 0, w: 10, h: 10 };
        let r2 = DirtyRect { x: 5, y: 5, w: 10, h: 10 };
        assert!(r1.overlaps_or_adjacent(&r2));
        let merged = r1.merge(&r2);
        assert_eq!(merged.x, 0);
        assert_eq!(merged.y, 0);
        assert_eq!(merged.w, 15);
        assert_eq!(merged.h, 15);
    }

    #[test]
    fn test_dirty_rect_adjacent() {
        let r1 = DirtyRect { x: 0, y: 0, w: 10, h: 10 };
        let r2 = DirtyRect { x: 10, y: 0, w: 5, h: 10 };
        assert!(r1.overlaps_or_adjacent(&r2));
        let merged = r1.merge(&r2);
        assert_eq!(merged.w, 15);
    }

    #[test]
    fn test_dirty_rect_no_overlap() {
        let r1 = DirtyRect { x: 0, y: 0, w: 10, h: 10 };
        let r2 = DirtyRect { x: 20, y: 20, w: 5, h: 5 };
        assert!(!r1.overlaps_or_adjacent(&r2));
    }

    #[test]
    fn test_config_validation() {
        let config = FramebufferConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.max_dirty_rects = 0;
        assert!(bad.validate().is_err());
    }
}
