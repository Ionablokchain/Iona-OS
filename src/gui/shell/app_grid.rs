//! App grid — center-left content area showing app tiles
use crate::io::{framebuffer as fb, font};
use crate::gui::{
    theme::{palette::*, rgb, spacing::*},
    layout::{Rect, layout_grid, constants::*},
    primitives::draw as prim,
    icons::{Icon, draw_icon},
    text,
};

pub struct AppEntry { pub label: &'static str, pub icon: Icon, pub color: u32 }

pub static APPS: &[AppEntry] = &[
    AppEntry { label: "Terminal",  icon: Icon::Terminal, color: ACCENT       },
    AppEntry { label: "Files",     icon: Icon::Files,    color: 0x3DA8F0     },
    AppEntry { label: "Monitor",   icon: Icon::Monitor,  color: STATUS_OK    },
    AppEntry { label: "IONA Node", icon: Icon::Node,     color: ACCENT       },
    AppEntry { label: "Wallet",    icon: Icon::Wallet,   color: STATUS_OK    },
    AppEntry { label: "Browser",   icon: Icon::Browser,  color: 0x6060FF     },
    AppEntry { label: "Mail",      icon: Icon::Mail,     color: STATUS_WARN  },
    AppEntry { label: "Settings",  icon: Icon::Settings, color: TEXT_SECONDARY},
    AppEntry { label: "Calendar",  icon: Icon::Calendar, color: ACCENT       },
    AppEntry { label: "Music",     icon: Icon::Music,    color: 0xA029BF     },
];

pub fn draw(x: usize, y: usize, w: usize, h: usize, hovered: Option<usize>) {
    let n = APPS.len();
    let bounds = Rect::new(x as i32, y as i32, w as i32, h as i32);
    let cells = layout_grid(bounds, APP_GRID_COLS, APP_CELL_GAP as i32, n);

    for (i, (app, cell)) in APPS.iter().zip(cells.iter()).enumerate() {
        let is_hov = hovered == Some(i);
        let bg = if is_hov { GLASS_HOVER } else { GLASS };
        let border = if is_hov { ACCENT } else { GLASS_BORDER };

        prim::fill_card(cell.ux(), cell.uy(), cell.uw(), cell.uh(), bg, border, 14, if is_hov {60} else {40});

        let icon_x = cell.ux() + (cell.uw() - 24) / 2;
        let icon_y = cell.uy() + (cell.uh() as i32 / 2 - 20) as usize;
        draw_icon(icon_x, icon_y, app.icon, app.color, bg);

        let lbl = app.label;
        let lx = cell.ux() + cell.uw().saturating_sub(lbl.len()*font::FONT_WIDTH) / 2;
        let ly = icon_y + 24 + 4;
        if ly + font::FONT_HEIGHT < cell.uy() + cell.uh() {
            font::draw_string(lbl, lx, ly, if is_hov { TEXT_PRIMARY } else { TEXT_SECONDARY }, bg);
        }
    }
}
