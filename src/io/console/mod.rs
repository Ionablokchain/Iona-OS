//! Kernel console — text terminal on framebuffer + serial.
//!
//! Supports ANSI escape codes: color, cursor movement, clear screen.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           Console Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (ConsoleCfg)│ (ConsoleErr) │ (ConsoleMetr) │ (Color, Cursor, Cell)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │    ANSI     │    Core      │   Manager     │        Legacy            │
//! │ (parser)    │ (terminal)   │ (ConsoleMgr)  │ (global fns)             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::io::console::{ConsoleManager, ConsoleConfig};
//!
//! let config = ConsoleConfig::default();
//! let manager = ConsoleManager::new(config);
//! manager.init();
//! manager.write("Hello, \x1b[31mworld!\x1b[0m");
//! ```

#![allow(dead_code)]

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the console.
    use serde::{Deserialize, Serialize};

    /// Console configuration.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConsoleConfig {
        pub cols: usize,
        pub rows: usize,
        pub default_fg: u32,
        pub default_bg: u32,
        pub font_width: usize,
        pub font_height: usize,
        pub enable_ansi: bool,
        pub enable_serial_fallback: bool,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for ConsoleConfig {
        fn default() -> Self {
            Self {
                cols: 128,
                rows: 48,
                default_fg: 0xE6EDF3,
                default_bg: 0x0F1923,
                font_width: 8,
                font_height: 16,
                enable_ansi: true,
                enable_serial_fallback: true,
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl ConsoleConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.cols == 0 || self.rows == 0 {
                return Err("cols and rows must be > 0");
            }
            if self.font_width == 0 || self.font_height == 0 {
                return Err("font dimensions must be > 0");
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
    //! Error types for the console.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ConsoleError {
        #[error("console not initialised")]
        NotInitialised,

        #[error("out of bounds: row={row}, col={col}")]
        OutOfBounds { row: usize, col: usize },

        #[error("invalid ANSI escape sequence: {seq}")]
        InvalidAnsi { seq: String },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type ConsoleResult<T> = Result<T, ConsoleError>;
}

pub mod types {
    //! Core types for the console.
    use super::config::ConsoleConfig;
    use core::fmt;

    /// A single cell on the terminal.
    #[derive(Clone, Copy, Debug)]
    pub struct Cell {
        pub ch: u8,
        pub fg: u32,
        pub bg: u32,
    }

    impl Default for Cell {
        fn default() -> Self {
            Self {
                ch: b' ',
                fg: 0xE6EDF3,
                bg: 0x0F1923,
            }
        }
    }

    /// Cursor position (0-indexed).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Cursor {
        pub col: usize,
        pub row: usize,
    }

    impl Cursor {
        pub fn new(col: usize, row: usize) -> Self {
            Self { col, row }
        }

        pub fn is_valid(&self, cols: usize, rows: usize) -> bool {
            self.col < cols && self.row < rows
        }
    }

    /// Colour palette (RGB).
    pub type Color = u32;

    /// Console state.
    pub struct ConsoleState {
        pub cells: Vec<Vec<Cell>>,
        pub cursor: Cursor,
        pub fg: Color,
        pub bg: Color,
        pub cols: usize,
        pub rows: usize,
        pub dirty: bool,
        pub escaped: bool,
        pub ansi_buffer: String,
    }

    impl ConsoleState {
        pub fn new(config: &ConsoleConfig) -> Self {
            let cells = vec![vec![Cell::default(); config.cols]; config.rows];
            Self {
                cells,
                cursor: Cursor::new(0, 0),
                fg: config.default_fg,
                bg: config.default_bg,
                cols: config.cols,
                rows: config.rows,
                dirty: false,
                escaped: false,
                ansi_buffer: String::with_capacity(32),
            }
        }

        pub fn clear(&mut self, bg: Color) {
            for row in 0..self.rows {
                for col in 0..self.cols {
                    self.cells[row][col] = Cell {
                        ch: b' ',
                        fg: self.fg,
                        bg,
                    };
                }
            }
            self.dirty = true;
        }

        pub fn put_char(&mut self, ch: u8, fg: Color, bg: Color) {
            let row = self.cursor.row;
            let col = self.cursor.col;
            if row < self.rows && col < self.cols {
                self.cells[row][col] = Cell { ch, fg, bg };
                self.dirty = true;
                self.cursor.col += 1;
                if self.cursor.col >= self.cols {
                    self.cursor.col = 0;
                    self.cursor.row += 1;
                }
            }
        }

        pub fn scroll(&mut self) {
            // Shift all rows up.
            for r in 1..self.rows {
                self.cells[r - 1] = self.cells[r].clone();
            }
            // Clear last row.
            let bg = self.bg;
            for c in 0..self.cols {
                self.cells[self.rows - 1][c] = Cell {
                    ch: b' ',
                    fg: self.fg,
                    bg,
                };
            }
            self.dirty = true;
        }

        pub fn move_cursor(&mut self, col: usize, row: usize) -> bool {
            if col < self.cols && row < self.rows {
                self.cursor.col = col;
                self.cursor.row = row;
                true
            } else {
                false
            }
        }

        pub fn move_cursor_relative(&mut self, dx: isize, dy: isize) {
            let new_col = (self.cursor.col as isize + dx).max(0).min(self.cols as isize - 1) as usize;
            let new_row = (self.cursor.row as isize + dy).max(0).min(self.rows as isize - 1) as usize;
            self.cursor.col = new_col;
            self.cursor.row = new_row;
        }

        pub fn backspace(&mut self) {
            if self.cursor.col > 0 {
                self.cursor.col -= 1;
                self.cells[self.cursor.row][self.cursor.col] = Cell {
                    ch: b' ',
                    fg: self.fg,
                    bg: self.bg,
                };
                self.dirty = true;
            } else if self.cursor.row > 0 {
                self.cursor.row -= 1;
                self.cursor.col = self.cols - 1;
            }
        }
    }
}

pub mod ansi {
    //! ANSI escape sequence parser.
    use super::{
        config::ConsoleConfig,
        error::{ConsoleError, ConsoleResult},
        types::{ConsoleState, Cursor},
        metrics::ConsoleMetrics,
    };
    use core::fmt::Write;
    use alloc::string::String;

    /// Parse ANSI escape sequences and apply them.
    pub fn parse_and_apply(
        state: &mut ConsoleState,
        seq: &str,
        config: &ConsoleConfig,
        metrics: &ConsoleMetrics,
    ) -> ConsoleResult<()> {
        if !config.enable_ansi {
            // Treat as plain text.
            for ch in seq.bytes() {
                apply_char(state, ch, config, metrics);
            }
            return Ok(());
        }

        // Remove leading ESC[ and trailing 'm' etc.
        if !seq.starts_with('[') {
            return Err(ConsoleError::InvalidAnsi { seq: seq.to_string() });
        }

        let cmd = &seq[1..];
        // Parse numeric parameters.
        let mut params: Vec<usize> = Vec::new();
        let mut current = String::new();
        for ch in cmd.chars() {
            if ch == ';' {
                if !current.is_empty() {
                    params.push(current.parse().unwrap_or(0));
                    current.clear();
                }
            } else if ch.is_ascii_digit() {
                current.push(ch);
            } else {
                // The final character is the command.
                if !current.is_empty() {
                    params.push(current.parse().unwrap_or(0));
                }
                let command = ch;
                apply_command(state, command, &params, config, metrics);
                return Ok(());
            }
        }
        // If we reach here, the sequence is incomplete; ignore.
        Ok(())
    }

    fn apply_command(
        state: &mut ConsoleState,
        command: char,
        params: &[usize],
        config: &ConsoleConfig,
        metrics: &ConsoleMetrics,
    ) {
        match command {
            'm' => {
                // Set colour (SGR).
                if params.is_empty() || params == [0] {
                    state.fg = config.default_fg;
                    state.bg = config.default_bg;
                } else {
                    for &p in params {
                        match p {
                            30 => state.fg = 0x000000, // black
                            31 => state.fg = 0xF85149, // red
                            32 => state.fg = 0x3FB950, // green
                            33 => state.fg = 0xD29922, // yellow
                            34 => state.fg = 0x58A6FF, // blue
                            35 => state.fg = 0xBC8CFF, // magenta
                            36 => state.fg = 0x39D353, // cyan
                            37 => state.fg = 0xE6EDF3, // white
                            40 => state.bg = 0x000000,
                            41 => state.bg = 0xF85149,
                            42 => state.bg = 0x3FB950,
                            43 => state.bg = 0xD29922,
                            44 => state.bg = 0x58A6FF,
                            45 => state.bg = 0xBC8CFF,
                            46 => state.bg = 0x39D353,
                            47 => state.bg = 0xE6EDF3,
                            _ => {}
                        }
                    }
                }
                state.dirty = true;
                metrics.inc_ansi();
            }
            'A' => { // Cursor up
                let n = params.first().copied().unwrap_or(1);
                state.move_cursor_relative(0, -(n as isize));
                metrics.inc_cursor_move();
            }
            'B' => { // Cursor down
                let n = params.first().copied().unwrap_or(1);
                state.move_cursor_relative(0, n as isize);
                metrics.inc_cursor_move();
            }
            'C' => { // Cursor right
                let n = params.first().copied().unwrap_or(1);
                state.move_cursor_relative(n as isize, 0);
                metrics.inc_cursor_move();
            }
            'D' => { // Cursor left
                let n = params.first().copied().unwrap_or(1);
                state.move_cursor_relative(-(n as isize), 0);
                metrics.inc_cursor_move();
            }
            'H' | 'f' => { // Cursor home
                let row = params.get(0).copied().unwrap_or(1).saturating_sub(1);
                let col = params.get(1).copied().unwrap_or(1).saturating_sub(1);
                let _ = state.move_cursor(col, row);
                metrics.inc_cursor_move();
            }
            'J' => { // Clear screen
                let mode = params.first().copied().unwrap_or(0);
                match mode {
                    0 => {
                        // Clear from cursor to end of screen.
                        for r in state.cursor.row..state.rows {
                            let start = if r == state.cursor.row { state.cursor.col } else { 0 };
                            for c in start..state.cols {
                                state.cells[r][c] = types::Cell {
                                    ch: b' ',
                                    fg: state.fg,
                                    bg: state.bg,
                                };
                            }
                        }
                        state.dirty = true;
                    }
                    1 => {
                        // Clear from beginning to cursor.
                        for r in 0..=state.cursor.row {
                            let end = if r == state.cursor.row { state.cursor.col + 1 } else { state.cols };
                            for c in 0..end {
                                state.cells[r][c] = types::Cell {
                                    ch: b' ',
                                    fg: state.fg,
                                    bg: state.bg,
                                };
                            }
                        }
                        state.dirty = true;
                    }
                    2 => {
                        // Clear entire screen.
                        state.clear(state.bg);
                        state.cursor = Cursor::new(0, 0);
                        state.dirty = true;
                    }
                    _ => {}
                }
                metrics.inc_clear();
            }
            'K' => { // Clear line
                let mode = params.first().copied().unwrap_or(0);
                match mode {
                    0 => {
                        // Clear from cursor to end of line.
                        for c in state.cursor.col..state.cols {
                            state.cells[state.cursor.row][c] = types::Cell {
                                ch: b' ',
                                fg: state.fg,
                                bg: state.bg,
                            };
                        }
                        state.dirty = true;
                    }
                    1 => {
                        // Clear from beginning to cursor.
                        for c in 0..=state.cursor.col {
                            state.cells[state.cursor.row][c] = types::Cell {
                                ch: b' ',
                                fg: state.fg,
                                bg: state.bg,
                            };
                        }
                        state.dirty = true;
                    }
                    2 => {
                        // Clear entire line.
                        for c in 0..state.cols {
                            state.cells[state.cursor.row][c] = types::Cell {
                                ch: b' ',
                                fg: state.fg,
                                bg: state.bg,
                            };
                        }
                        state.dirty = true;
                    }
                    _ => {}
                }
                metrics.inc_clear();
            }
            _ => {
                // Unsupported command; ignore.
                if config.log_operations {
                    trace!("unsupported ANSI command '{}'", command);
                }
            }
        }
    }

    /// Apply a single character (non-ANSI).
    pub fn apply_char(
        state: &mut ConsoleState,
        ch: u8,
        config: &ConsoleConfig,
        metrics: &ConsoleMetrics,
    ) {
        match ch {
            b'\n' => {
                state.cursor.col = 0;
                state.cursor.row += 1;
                if state.cursor.row >= state.rows {
                    state.scroll();
                    state.cursor.row = state.rows - 1;
                }
                state.dirty = true;
                metrics.inc_newline();
            }
            b'\r' => {
                state.cursor.col = 0;
                state.dirty = true;
            }
            0x08 => { // backspace
                state.backspace();
                metrics.inc_backspace();
            }
            _ => {
                state.put_char(ch, state.fg, state.bg);
                metrics.inc_char();
            }
        }
    }
}

pub mod core {
    //! Core console logic.
    use super::{
        config::ConsoleConfig,
        error::{ConsoleError, ConsoleResult},
        types::{ConsoleState, Cursor},
        ansi::{parse_and_apply, apply_char},
        metrics::ConsoleMetrics,
    };
    use crate::io::framebuffer::{fill_rect, mark_dirty, width, height, draw_text_col};
    use crate::io::font::{FONT_WIDTH, FONT_HEIGHT};

    /// The console terminal.
    pub struct Console {
        config: ConsoleConfig,
        state: ConsoleState,
        metrics: ConsoleMetrics,
        initialised: bool,
        ansi_buffer: String,
    }

    impl Console {
        pub fn new(config: ConsoleConfig) -> Self {
            config.validate().expect("invalid ConsoleConfig");
            let state = ConsoleState::new(&config);
            Self {
                config,
                state,
                metrics: ConsoleMetrics::default(),
                initialised: false,
                ansi_buffer: String::with_capacity(32),
            }
        }

        pub fn init(&mut self) -> ConsoleResult<()> {
            if self.initialised {
                return Ok(());
            }
            self.state.clear(self.config.default_bg);
            self.render_all();
            self.initialised = true;
            info!("console initialised ({}×{})", self.config.cols, self.config.rows);
            Ok(())
        }

        /// Write a string to the console, interpreting ANSI escapes.
        pub fn write(&mut self, s: &str) {
            if !self.initialised {
                warn!("console not initialised");
                return;
            }
            for ch in s.chars() {
                if ch == '\x1b' {
                    // Start of ANSI escape
                    self.state.escaped = true;
                    self.ansi_buffer.clear();
                    continue;
                }
                if self.state.escaped {
                    self.ansi_buffer.push(ch);
                    // Check if it's a complete sequence (ends with a letter)
                    if ch.is_ascii_alphabetic() {
                        // Apply the sequence
                        if let Err(e) = parse_and_apply(&mut self.state, &self.ansi_buffer, &self.config, &self.metrics) {
                            // If parsing fails, just ignore.
                            if self.config.log_operations {
                                trace!("ANSI parse error: {}", e);
                            }
                        }
                        self.state.escaped = false;
                        self.ansi_buffer.clear();
                        continue;
                    }
                    // Otherwise, continue accumulating.
                    continue;
                }
                // Normal character.
                apply_char(&mut self.state, ch as u8, &self.config, &self.metrics);
                self.metrics.inc_char();
                // Flush periodically.
                if self.state.dirty {
                    self.render_dirty();
                }
            }
            // Flush at end.
            if self.state.dirty {
                self.render_dirty();
            }
        }

        /// Write a single character.
        pub fn put_char(&mut self, ch: u8) {
            self.write(unsafe { core::str::from_utf8_unchecked(&[ch]) });
        }

        /// Clear the console.
        pub fn clear(&mut self) {
            self.state.clear(self.config.default_bg);
            self.state.cursor = Cursor::new(0, 0);
            self.render_all();
            self.metrics.inc_clear();
        }

        /// Render the entire screen.
        pub fn render_all(&self) {
            for row in 0..self.state.rows {
                for col in 0..self.state.cols {
                    let cell = self.state.cells[row][col];
                    // Draw character using font.
                    let x = col * self.config.font_width;
                    let y = row * self.config.font_height;
                    draw_text_col(x, y, &String::from_utf8_lossy(&[cell.ch]), cell.fg, cell.bg);
                }
            }
            mark_dirty(0, 0, self.config.cols * self.config.font_width, self.config.rows * self.config.font_height);
            self.flush();
        }

        /// Render only dirty cells (optimised).
        pub fn render_dirty(&mut self) {
            // For simplicity, we just redraw all cells.
            // Could be optimised by tracking dirty cells.
            self.render_all();
            self.state.dirty = false;
        }

        /// Flush to the framebuffer.
        pub fn flush(&self) {
            crate::io::framebuffer::present();
        }

        /// Get the current cursor position.
        pub fn cursor(&self) -> Cursor {
            self.state.cursor
        }

        /// Set cursor position.
        pub fn set_cursor(&mut self, col: usize, row: usize) -> ConsoleResult<()> {
            if col < self.config.cols && row < self.config.rows {
                self.state.cursor = Cursor::new(col, row);
                Ok(())
            } else {
                Err(ConsoleError::OutOfBounds { row, col })
            }
        }

        /// Get the number of columns.
        pub fn cols(&self) -> usize {
            self.config.cols
        }

        /// Get the number of rows.
        pub fn rows(&self) -> usize {
            self.config.rows
        }

        /// Get metrics.
        pub fn metrics(&self) -> &ConsoleMetrics {
            &self.metrics
        }

        /// Check if initialised.
        pub fn is_initialised(&self) -> bool {
            self.initialised
        }
    }

    impl fmt::Write for Console {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.write(s);
            Ok(())
        }
    }
}

pub mod metrics {
    //! Metrics for the console.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ConsoleMetrics {
        pub chars: AtomicU64,
        pub newlines: AtomicU64,
        pub backspaces: AtomicU64,
        pub clears: AtomicU64,
        pub cursor_moves: AtomicU64,
        pub ansi_sequences: AtomicU64,
        pub scrolls: AtomicU64,
    }

    impl ConsoleMetrics {
        pub fn inc_char(&self) {
            self.chars.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_newline(&self) {
            self.newlines.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_backspace(&self) {
            self.backspaces.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_clear(&self) {
            self.clears.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cursor_move(&self) {
            self.cursor_moves.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_ansi(&self) {
            self.ansi_sequences.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_scroll(&self) {
            self.scrolls.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ConsoleMetricsSnapshot {
            ConsoleMetricsSnapshot {
                chars: self.chars.load(Ordering::Relaxed),
                newlines: self.newlines.load(Ordering::Relaxed),
                backspaces: self.backspaces.load(Ordering::Relaxed),
                clears: self.clears.load(Ordering::Relaxed),
                cursor_moves: self.cursor_moves.load(Ordering::Relaxed),
                ansi_sequences: self.ansi_sequences.load(Ordering::Relaxed),
                scrolls: self.scrolls.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConsoleMetricsSnapshot {
        pub chars: u64,
        pub newlines: u64,
        pub backspaces: u64,
        pub clears: u64,
        pub cursor_moves: u64,
        pub ansi_sequences: u64,
        pub scrolls: u64,
    }
}

pub mod manager {
    //! Centralised manager for the console.
    use super::{
        config::ConsoleConfig,
        error::{ConsoleError, ConsoleResult},
        core::Console,
        metrics::ConsoleMetrics,
    };
    use core::sync::atomic::Ordering;

    /// Manager for the console.
    pub struct ConsoleManager {
        console: Console,
        initialised: bool,
    }

    impl ConsoleManager {
        pub fn new(config: ConsoleConfig) -> Self {
            let console = Console::new(config);
            Self {
                console,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(ConsoleConfig::default())
        }

        pub fn init(&mut self) -> ConsoleResult<()> {
            if self.initialised {
                return Ok(());
            }
            self.console.init()?;
            self.initialised = true;
            Ok(())
        }

        pub fn write(&mut self, s: &str) {
            self.console.write(s);
        }

        pub fn put_char(&mut self, ch: u8) {
            self.console.put_char(ch);
        }

        pub fn clear(&mut self) {
            self.console.clear();
        }

        pub fn cursor(&self) -> super::types::Cursor {
            self.console.cursor()
        }

        pub fn set_cursor(&mut self, col: usize, row: usize) -> ConsoleResult<()> {
            self.console.set_cursor(col, row)
        }

        pub fn metrics(&self) -> &ConsoleMetrics {
            self.console.metrics()
        }

        pub fn metrics_snapshot(&self) -> super::metrics::ConsoleMetricsSnapshot {
            self.metrics().snapshot()
        }

        pub fn reset_metrics(&self) {
            *self.console.metrics() = ConsoleMetrics::default();
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ConsoleConfig;
pub use error::{ConsoleError, ConsoleResult};
pub use types::{Cursor, Cell, Color};
pub use metrics::{ConsoleMetrics, ConsoleMetricsSnapshot};
pub use core::Console;
pub use manager::ConsoleManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<ConsoleManager> = Once::new();

/// Get the global manager (initialises with defaults if not yet set).
fn global_manager() -> &'static ConsoleManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = ConsoleManager::default();
        let _ = mgr.init();
        mgr
    })
}

/// Initialise the console (legacy).
pub fn init() {
    let mgr = global_manager();
    // We can't mutate here, but the global manager is already initialised.
    crate::serial_println!("  [CON] {}×{} character console on framebuffer", COLS, ROWS);
    mgr.write("IONA OS Kernel Console\n");
    mgr.write("======================\n\n");
}

/// Write a string (legacy).
pub fn puts(s: &str) {
    global_manager().write(s);
}

/// Write a character (legacy).
pub fn putc(ch: u8) {
    global_manager().put_char(ch);
}

/// Clear the screen (legacy).
pub fn clear() {
    global_manager().clear();
}

// Constants for backward compatibility (also used in default config).
pub const COLS: usize = 128;
pub const ROWS: usize = 48;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = ConsoleConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.cols = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.font_width = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_cursor_movement() {
        let config = ConsoleConfig::default();
        let mut state = ConsoleState::new(&config);
        assert_eq!(state.cursor.col, 0);
        assert_eq!(state.cursor.row, 0);
        state.move_cursor(5, 3);
        assert_eq!(state.cursor.col, 5);
        assert_eq!(state.cursor.row, 3);
        state.move_cursor_relative(-2, 1);
        assert_eq!(state.cursor.col, 3);
        assert_eq!(state.cursor.row, 4);
    }

    #[test]
    fn test_ansi_parse() {
        let config = ConsoleConfig::default();
        let mut state = ConsoleState::new(&config);
        let metrics = ConsoleMetrics::default();
        ansi::parse_and_apply(&mut state, "[31m", &config, &metrics).unwrap();
        assert_eq!(state.fg, 0xF85149); // red
        ansi::parse_and_apply(&mut state, "[0m", &config, &metrics).unwrap();
        assert_eq!(state.fg, config.default_fg);
    }
}
