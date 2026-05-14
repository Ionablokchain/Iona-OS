//! Layout constants — SINGLE SOURCE OF TRUTH for shell hit regions.
//!
//! CHECK 4: draw code și hit-test code folosesc ACELEAȘI constante.
//! Dacă schimbi un număr aici, atât desenul cât și click-ul se actualizează.
//!
//! REGULĂ: nicio coordonată hardcodată în shell_events.rs sau app_grid.rs.
//! Toate vin din acest fișier.

// Shell bars
pub const TOPBAR_H:       usize = 50;
pub const SIDEBAR_W:      usize = 72;
pub const TASKBAR_H:      usize = 56;

// Shell content area (calculated from bars)
pub const CONTENT_X:      usize = SIDEBAR_W + 8;  // 8px gap
pub const CONTENT_Y:      usize = TOPBAR_H + 8;

// Sidebar dock
pub const DOCK_ITEM_H:    usize = 64;  // icon height
pub const DOCK_ITEM_GAP:  usize = 8;   // gap between items
pub const DOCK_ITEM_STRIDE: usize = DOCK_ITEM_H + DOCK_ITEM_GAP; // 72px total
pub const DOCK_ITEM_START_Y: usize = 12; // padding from topbar

// Taskbar items
pub const TASKBAR_ITEM_W: usize = 110;
pub const TASKBAR_ITEM_H: usize = 40;
pub const TASKBAR_ITEM_GAP: usize = 8;
pub const TASKBAR_SEP_W:  usize = 16;
pub const TASKBAR_SEP_EVERY: usize = 3; // separator every N items

// App grid (5-column)
pub const APP_GRID_COLS:  usize = 5;
pub const APP_CELL_W:     usize = 100; // calculated to fit content area
pub const APP_CELL_H:     usize = 90;
pub const APP_CELL_GAP:   usize = 10;

// Right panel
pub const RIGHT_PANEL_W:  usize = 240;

// Overlays
pub const CONTEXT_MENU_W: usize = 160;
pub const TOOLTIP_H:      usize = 26;
pub const TOOLTIP_PAD:    usize = 8;
