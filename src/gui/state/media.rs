//! MediaState — shell-side media player state
//!
//! S-02 design decision:
//!   MediaState este gestionat de shell, nu de un app separat.
//!   "Playerul" shell nu controlează audio real — e un widget de status.
//!   Control audio real va veni prin syscall audio + un media service app.

use alloc::string::String;

#[derive(Clone)]
pub struct MediaState {
    pub title:    String,
    pub artist:   String,
    pub playing:  bool,
    pub progress: f32,   // 0.0..1.0
    pub duration: u32,   // seconds
    pub dirty:    bool,
}

impl Default for MediaState {
    fn default() -> Self {
        Self {
            title:    "Midnight Protocol".into(),
            artist:   "Iona Collective".into(),
            playing:  false,
            progress: 0.35,
            duration: 214,
            dirty:    true,
        }
    }
}

impl MediaState {
    pub fn toggle_play(&mut self) {
        self.playing = !self.playing;
        self.dirty = true;
    }

    pub fn advance(&mut self, delta_ms: u64) {
        if self.playing && self.duration > 0 {
            let delta_s = delta_ms as f32 / 1000.0;
            self.progress += delta_s / self.duration as f32;
            if self.progress >= 1.0 {
                self.progress = 0.0;
                self.playing  = false;
            }
            self.dirty = true;
        }
    }

    pub fn seek(&mut self, progress: f32) {
        self.progress = progress.clamp(0.0, 1.0);
        self.dirty = true;
    }
}
