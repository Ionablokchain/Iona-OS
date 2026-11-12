//! Audio — Intel HD Audio (HDA) controller driver.
//!
//! Minimal-but-correct HDA driver for single-stream PCM playback.
//!
//! # Supported
//!
//! * Controller detection and GCTL reset (with verification)
//! * CORB/RIRB DMA initialization (256-entry rings)
//! * Synchronous verb send/receive with RIRB ack
//! * Root-node codec enumeration (diagnostic)
//! * Output stream 0 setup (48 kHz, 16-bit, stereo)
//! * Single-shot PCM playback via cyclic BDL
//! * Best-effort volume control (output amp on discovered DAC + pin)
//!
//! # Not supported (documented limitations)
//!
//! * Interrupt-driven completion (polling only)
//! * Multi-stream / NCQ-style descriptor pipelining
//! * Full codec widget routing (mixers, connection select, capture)
//! * Hot-plug codec detection
//! * Sample rates other than 48 kHz; formats other than 16-bit stereo
//! * Volume control on arbitrary widgets (best-effort on DAC + pin only)
//! * 64-bit BAR0 (only low 32 bits of BAR0 are read)
//!
//! # Preconditions
//!
//! * Physical memory is identity-mapped at [`PHYS_OFFSET`].
//! * The global allocator returns physically-contiguous memory in that
//!   range (required for DMA).
//! * The HBA supports 256-entry CORB/RIRB (all ICH6+ controllers do).

use alloc::vec::Vec;
use spin::Mutex;

use crate::pci::PciDevice;

// ---------------------------------------------------------------------------
// Global registers
// ---------------------------------------------------------------------------

const GCAP:    u16 = 0x00;
const VMIN:    u16 = 0x02;
const VMAJ:    u16 = 0x03;
const GCTL:    u16 = 0x08;
const STATSTS: u16 = 0x0E;
const GSTS:    u16 = 0x10;

const GCTL_CRST: u32 = 1 << 0;

// ---------------------------------------------------------------------------
// Stream descriptor 0 (output)
// ---------------------------------------------------------------------------

const SD0_OFFSET: u16 = 0x80;

const SD_CTL:  u16 = 0x00;
const SD_STS:  u16 = 0x03;
const SD_LPIB: u16 = 0x04;
const SD_CBL:  u16 = 0x08;
const SD_LVI:  u16 = 0x0C;
const SD_FMT:  u16 = 0x12;
const SD_BDPL: u16 = 0x18;
const SD_BDPU: u16 = 0x1C;

const SD_CTL_SRST: u32 = 1 << 0;
const SD_CTL_RUN:  u32 = 1 << 1;
const SD_CTL_IOCE: u32 = 1 << 2;

// ---------------------------------------------------------------------------
// CORB / RIRB
// ---------------------------------------------------------------------------

const CORBLBASE: u16 = 0x40;
const CORBUBASE: u16 = 0x44;
const CORBWP:    u16 = 0x48;
const CORBRP:    u16 = 0x4A;
const CORBCTL:   u16 = 0x4C;
const CORBSTS:   u16 = 0x4D;
const CORBSIZE:  u16 = 0x4E;

const RIRBLBASE: u16 = 0x50;
const RIRBUBASE: u16 = 0x54;
const RIRBWP:    u16 = 0x58;
const RIRBCNT:   u16 = 0x5A;
const RIRBCTL:   u16 = 0x5C;
const RIRBSTS:   u16 = 0x5D;
const RIRBSIZE:  u16 = 0x5E;

const CORBCTL_RUN:      u8 = 1 << 1;
const RIRBCTL_RIRBDMAEN: u8 = 1 << 1;
const RIRBSTS_RINTFL:   u8 = 1 << 0;

// CORBSIZE / RIRBSIZE encoding
const SIZE_256: u8 = 0x02;

// ---------------------------------------------------------------------------
// Verbs and parameters
// ---------------------------------------------------------------------------

const VERB_SET_AMP_GAIN_MUTE: u32 = 0x3 << 16;
const VERB_GET_PARAMETER:     u32 = 0xF00 << 8;

const PARAM_NODE_COUNT:  u8 = 0x04;
const PARAM_WIDGET_TYPE: u8 = 0x09;
const PARAM_PIN_CAP:     u8 = 0x0C;

const WIDGET_TYPE_OUTPUT_DAC: u32 = 0x0;
const WIDGET_TYPE_PIN:        u32 = 0x4;

const PIN_CAP_OUTPUT: u32 = 1 << 4;

// ---------------------------------------------------------------------------
// DMA buffer sizes (HDA 1.0a §4.2, §4.4.1, §3.6.2)
// ---------------------------------------------------------------------------

const CORB_ENTRIES: usize = 256;
const RIRB_ENTRIES: usize = 256;
const CORB_BYTES:   usize = CORB_ENTRIES * 4; // 1024
const RIRB_BYTES:   usize = RIRB_ENTRIES * 8; // 2048
const CORB_ALIGN:   usize = 128;
const RIRB_ALIGN:   usize = 128;

const BDL_ENTRIES:  usize = 8;
const PERIOD_SIZE:  usize = 4096;
const STREAM_BYTES: usize = BDL_ENTRIES * PERIOD_SIZE; // 32768
const BDL_BYTES:    usize = BDL_ENTRIES * 16;          // 128
const STREAM_ALIGN: usize = 128;
const BDL_ALIGN:    usize = 128;

// HDA stream format (§3.7.1): base=48 kHz, mult=x1, 16-bit, 2 channels.
const STREAM_FORMAT_48K_16B_STEREO: u16 = 0x0101;

const SECTOR_SIZE: usize = 512; // not used, but kept for API parity

// ---------------------------------------------------------------------------
// Physical memory offset (identity map)
// ---------------------------------------------------------------------------

const PHYS_OFFSET: usize = 0xFFFF_8000_0000_0000;

// ---------------------------------------------------------------------------
// Poll budgets
// ---------------------------------------------------------------------------

const INIT_TIMEOUT:   usize = 100_000;
const VERB_TIMEOUT:   usize = 100_000;
const STREAM_TIMEOUT: usize = 100_000;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// BDL entry (16 bytes, HDA §3.6.2).
#[repr(C)]
struct BdlEntry {
    addr:   u64,
    length: u32,
    flags:  u32, // bit 0 = IOC
}

const _: () = assert!(core::mem::size_of::<BdlEntry>() == 16);

/// Owned DMA buffer with aligned logical region inside.
///
/// The allocation is stable as long as `raw` is not resized. The aligned
/// pointer is what must be handed to the HBA.
struct DmaBuffer {
    raw:    Vec<u8>,
    offset: usize,
    len:    usize,
}

impl DmaBuffer {
    fn new(len: usize, align: usize) -> Option<Self> {
        if len == 0 || !align.is_power_of_two() {
            return None;
        }
        let raw = alloc::vec![0u8; len.checked_add(align)?];
        let base = raw.as_ptr() as usize;
        let aligned = (base + align - 1) & !(align - 1);
        Some(Self { raw, offset: aligned - base, len })
    }

    fn virt(&self) -> *mut u8 {
        unsafe { self.raw.as_ptr().add(self.offset) as *mut u8 }
    }

    fn phys(&self) -> Option<u64> {
        virt_to_phys(self.virt() as *const u8)
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.virt(), self.len) }
    }
}

// ---------------------------------------------------------------------------
// Controller
// ---------------------------------------------------------------------------

pub struct HdaController {
    mmio:       usize,
    codec_mask: u16,

    corb: DmaBuffer,
    rirb: DmaBuffer,
    bdl:  DmaBuffer,
    stream: DmaBuffer,

    /// Index of the last written CORB slot.
    corb_wp: u16,
    /// Index of the next CORB slot to read (from RIRB perspective).
    rirb_rp: u16,

    stream_running: bool,

    // Discovered output path (best-effort, updated by `discover_output_path`).
    output_dac: Option<u8>,
    output_pin: Option<u8>,
}

impl HdaController {
    /// Initialise the controller from a PCI device.
    ///
    /// # Safety
    /// `dev` must be an HDA controller with a valid MMIO BAR0.
    unsafe fn try_init(dev: &PciDevice) -> Option<Self> {
        // HDA PCI class is 0x04 (multimedia) subclass 0x03.
        if dev.class != 0x04 || dev.subclass != 0x03 {
            return None;
        }

        let bar0 = (dev.bar[0] as usize) & !0xF;
        if bar0 == 0 {
            return None;
        }
        let mmio = bar0.checked_add(PHYS_OFFSET)?;

        // GCTL reset with verification (HDA §4.2).
        write32(mmio, GCTL, 0);
        if !wait_until(INIT_TIMEOUT, || read32(mmio, GCTL) & GCTL_CRST == 0) {
            return None;
        }
        write32(mmio, GCTL, GCTL_CRST);
        if !wait_until(INIT_TIMEOUT, || read32(mmio, GCTL) & GCTL_CRST != 0) {
            return None;
        }

        // Wait for codecs to appear (§4.3).
        wait_until(INIT_TIMEOUT, || read16(mmio, STATSTS) & 0x7FFF != 0);
        let statsts = read16(mmio, STATSTS);
        let codec_mask = statsts & 0x7FFF;
        if codec_mask == 0 {
            crate::serial_println!("  [HDA] no codecs detected");
            return None;
        }
        write16(mmio, STATSTS, statsts); // W1C

        let maj = read8(mmio, VMAJ);
        let min = read8(mmio, VMIN);
        let gcap = read16(mmio, GCAP);
        let oss = (gcap >> 12) & 0xF;
        let iss = (gcap >> 8) & 0xF;
        crate::serial_println!(
            "  [HDA] v{}.{}, {} out / {} in streams, codecs={:04b}",
            maj, min, oss, iss, codec_mask
        );

        // Allocate DMA buffers. Failure to get physically-contiguous
        // memory aborts init rather than producing a broken driver.
        let corb   = DmaBuffer::new(CORB_BYTES,   CORB_ALIGN)?;
        let rirb   = DmaBuffer::new(RIRB_BYTES,   RIRB_ALIGN)?;
        let bdl    = DmaBuffer::new(BDL_BYTES,    BDL_ALIGN)?;
        let stream = DmaBuffer::new(STREAM_BYTES, STREAM_ALIGN)?;

        // Verify all buffers are usable for DMA.
        corb.phys()?;
        rirb.phys()?;
        bdl.phys()?;
        stream.phys()?;

        let mut ctrl = Self {
            mmio,
            codec_mask,
            corb,
            rirb,
            bdl,
            stream,
            corb_wp: 0,
            rirb_rp: 0,
            stream_running: false,
            output_dac: None,
            output_pin: None,
        };

        ctrl.init_corb_rirb();
        ctrl.init_stream();
        ctrl.discover_output_path();

        crate::serial_println!(
            "  [HDA] init complete (dac={:?}, pin={:?})",
            ctrl.output_dac,
            ctrl.output_pin
        );

        Some(ctrl)
    }

    /// Program CORB and RIRB base addresses and enable DMA (HDA §4.4.1).
    unsafe fn init_corb_rirb(&mut self) {
        let b = self.mmio;

        // 1. Stop both engines.
        write8(b, CORBCTL, 0);
        write8(b, RIRBCTL, 0);

        // 2. Set sizes (256 entries each; supported on all ICH6+).
        write8(b, CORBSIZE, SIZE_256);
        write8(b, RIRBSIZE, SIZE_256);

        // 3. Program base addresses.
        let corb_p = self.corb.phys().unwrap_or(0);
        let rirb_p = self.rirb.phys().unwrap_or(0);
        write32(b, CORBLBASE, corb_p as u32);
        write32(b, CORBUBASE, (corb_p >> 32) as u32);
        write32(b, RIRBLBASE, rirb_p as u32);
        write32(b, RIRBUBASE, (rirb_p >> 32) as u32);

        // 4. Reset ring pointers.
        write16(b, CORBWP, 0);
        write16(b, CORBRP, 0x8000); // self-clearing reset bit
        write16(b, RIRBWP, 0x8000); // self-clearing reset bit

        // 5. Enable DMA.
        write8(b, CORBCTL, CORBCTL_RUN);
        write8(b, RIRBCTL, RIRBCTL_RIRBDMAEN);

        self.corb_wp = 0;
        self.rirb_rp = 0;
    }

    /// Reset stream 0 and program its format and BDL (HDA §3.3.7).
    unsafe fn init_stream(&mut self) {
        let sd = self.mmio + SD0_OFFSET as usize;

        // Reset stream: set SRST, wait for hardware ack, clear SRST,
        // wait for hardware ack again. (§3.3.7)
        let ctl = read32(sd, SD_CTL);
        write32(sd, SD_CTL, ctl | SD_CTL_SRST);
        wait_until(STREAM_TIMEOUT, || read32(sd, SD_CTL) & SD_CTL_SRST != 0);

        let ctl = read32(sd, SD_CTL);
        write32(sd, SD_CTL, ctl & !SD_CTL_SRST);
        wait_until(STREAM_TIMEOUT, || read32(sd, SD_CTL) & SD_CTL_SRST == 0);

        // Format: 48 kHz, 16-bit, stereo.
        write16(sd, SD_FMT, STREAM_FORMAT_48K_16B_STEREO);

        // BDL: one entry per period, all pointing into the persistent
        // stream buffer. IOC on the last entry (for future interrupt use).
        let bdl_p    = self.bdl.phys().unwrap_or(0);
        let stream_p = self.stream.phys().unwrap_or(0);

        let bdl = self.bdl.virt() as *mut BdlEntry;
        for i in 0..BDL_ENTRIES {
            bdl.add(i).write_volatile(BdlEntry {
                addr:   stream_p + (i * PERIOD_SIZE) as u64,
                length: PERIOD_SIZE as u32,
                flags:  if i == BDL_ENTRIES - 1 { 1 } else { 0 },
            });
        }

        write32(sd, SD_CBL, STREAM_BYTES as u32);
        write16(sd, SD_LVI, (BDL_ENTRIES - 1) as u16);
        write32(sd, SD_BDPL, bdl_p as u32);
        write32(sd, SD_BDPU, (bdl_p >> 32) as u32);

        self.stream_running = false;
    }

    /// Send a 20-bit verb+payload to `(codec, node)` and return the response.
    ///
    /// Blocks until either the codec responds or the poll budget expires.
    /// Returns `None` on timeout.
    unsafe fn send_verb(&mut self, codec: u8, node: u8, verb_payload: u32) -> Option<u32> {
        let b = self.mmio;
        let verb = ((codec as u32) << 28)
            | ((node as u32) << 20)
            | (verb_payload & 0x000F_FFFF);

        // Drain any stale responses before sending (should be none in
        // single-threaded use, but the HBA may have replied late).
        loop {
            let hw_wp = read16(b, RIRBWP) & 0xFF;
            if hw_wp == self.rirb_rp {
                break;
            }
            self.rirb_rp = (self.rirb_rp + 1) % (RIRB_ENTRIES as u16);
        }

        // Write command into CORB, then publish via CORBWP.
        let next = ((self.corb_wp + 1) % (CORB_ENTRIES as u16)) as u16;
        let corb = self.corb.virt() as *mut u32;
        corb.add(next as usize).write_volatile(verb);
        write16(b, CORBWP, next);
        self.corb_wp = next;

        // Wait for response.
        for _ in 0..VERB_TIMEOUT {
            let hw_wp = read16(b, RIRBWP) & 0xFF;
            if hw_wp != self.rirb_rp {
                let rirb = self.rirb.virt() as *const u64;
                let resp = rirb.add(self.rirb_rp as usize).read_volatile();
                self.rirb_rp = (self.rirb_rp + 1) % (RIRB_ENTRIES as u16);

                // Clear RIRB interrupt status so the codec can post more.
                let sts = read8(b, RIRBSTS);
                if sts & RIRBSTS_RINTFL != 0 {
                    write8(b, RIRBSTS, RIRBSTS_RINTFL);
                }
                return Some(resp as u32);
            }
            core::hint::spin_loop();
        }
        None
    }

    /// Walk every codec's top-level widget list and record the first
    /// output DAC and the first output-capable pin complex.
    unsafe fn discover_output_path(&mut self) {
        // Codec 0 is the safest bet on consumer hardware; some systems
        // expose multiple codecs (HDMI audio on a GPU is typically a
        // separate controller).
        let codec = 0u8;
        if self.codec_mask & (1 << codec) == 0 {
            return;
        }

        let Some(root) = self.send_verb(codec, 0, VERB_GET_PARAMETER | PARAM_NODE_COUNT as u32) else {
            return;
        };
        let num = ((root >> 16) & 0xFF) as u8;
        let start = (root & 0xFF) as u8;

        for n in start..start.saturating_add(num) {
            // Function group: enumerate its children.
            let Some(fg) = self.send_verb(codec, n, VERB_GET_PARAMETER | PARAM_NODE_COUNT as u32) else {
                continue;
            };
            let fg_num = ((fg >> 16) & 0xFF) as u8;
            let fg_start = (fg & 0xFF) as u8;

            for w in fg_start..fg_start.saturating_add(fg_num) {
                let Some(ty) = self.send_verb(codec, w, VERB_GET_PARAMETER | PARAM_WIDGET_TYPE as u32) else {
                    continue;
                };
                let widget_type = (ty >> 20) & 0xF;

                match widget_type {
                    WIDGET_TYPE_OUTPUT_DAC => {
                        if self.output_dac.is_none() {
                            self.output_dac = Some(w);
                        }
                    }
                    WIDGET_TYPE_PIN => {
                        let Some(cap) = self.send_verb(codec, w, VERB_GET_PARAMETER | PARAM_PIN_CAP as u32) else {
                            continue;
                        };
                        if (cap & PIN_CAP_OUTPUT) != 0 && self.output_pin.is_none() {
                            self.output_pin = Some(w);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Apply an output-amp gain to `node`.
    unsafe fn set_amp(&mut self, codec: u8, node: u8, gain: u8, mute: bool) {
        // SET_AMP_GAIN_MUTE is a 4-bit verb with a 16-bit payload (§7.3.4.10):
        //   [15]   = output amp
        //   [14]   = input amp (0)
        //   [13]   = left
        //   [12]   = right
        //   [11:8] = index (0 = direct)
        //   [7]    = mute
        //   [6:0]  = gain
        let mut payload: u32 = 0xB000 | (gain as u32 & 0x7F);
        if mute {
            payload |= 1 << 7;
        }
        self.send_verb(codec, node, VERB_SET_AMP_GAIN_MUTE | payload);
    }
}

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------

static HDA: Mutex<Option<HdaController>> = Mutex::new(None);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Initialise the HDA controller from a PCI device. Idempotent; the first
/// successful call wins.
pub fn try_init(dev: &PciDevice) -> bool {
    let ctrl = unsafe { HdaController::try_init(dev) };
    let mut global = HDA.lock();
    if ctrl.is_some() && global.is_none() {
        *global = ctrl;
        true
    } else {
        false
    }
}

/// Returns `true` if an HDA controller was successfully initialised.
pub fn is_available() -> bool {
    HDA.lock().is_some()
}

/// Returns the codec presence mask (bits 0-14).
pub fn codec_mask() -> u16 {
    HDA.lock().as_ref().map(|h| h.codec_mask).unwrap_or(0)
}

/// Returns `true` if the output stream is currently running.
pub fn is_playing() -> bool {
    HDA.lock()
        .as_ref()
        .map(|h| h.stream_running)
        .unwrap_or(false)
}

/// Send a raw 20-bit verb+payload to a codec node. Useful for diagnostics
/// and for playing with codecs interactively. Returns `None` on timeout or
/// if the controller is not initialised.
pub fn codec_verb_raw(codec: u8, node: u8, verb_payload: u32) -> Option<u32> {
    let mut guard = HDA.lock();
    let ctrl = guard.as_mut()?;
    unsafe { ctrl.send_verb(codec, node, verb_payload) }
}

/// Enumerate every codec reachable from the controller and print widget
/// types to the serial console. Intended as a diagnostic aid.
pub fn enumerate_codecs() {
    let mut guard = HDA.lock();
    let Some(ctrl) = guard.as_mut() else {
        return;
    };
    let mask = ctrl.codec_mask;
    unsafe {
        for codec in 0..15u8 {
            if mask & (1 << codec) == 0 {
                continue;
            }
            let Some(root) = ctrl.send_verb(codec, 0, VERB_GET_PARAMETER | PARAM_NODE_COUNT as u32) else {
                continue;
            };
            let num = ((root >> 16) & 0xFF) as u8;
            let start = (root & 0xFF) as u8;
            crate::serial_println!(
                "  [HDA] codec {}: {} nodes starting at {}",
                codec, num, start
            );

            for n in start..start.saturating_add(num) {
                let Some(ty) = ctrl.send_verb(codec, n, VERB_GET_PARAMETER | PARAM_WIDGET_TYPE as u32) else {
                    continue;
                };
                let widget_type = (ty >> 20) & 0xF;
                crate::serial_println!("    node {} widget_type={}", n, widget_type);
            }
        }
    }
}

/// Set the output volume (0-100). Applies to the discovered output DAC
/// and pin complex; silently does nothing if the controller is not
/// initialised or if no output path was found.
pub fn set_volume(percent: u8) {
    let mut guard = HDA.lock();
    let Some(ctrl) = guard.as_mut() else {
        return;
    };

    let gain = ((percent.min(100) as u32) * 0x7F / 100) as u8;
    let mute = percent == 0;

    unsafe {
        if let Some(dac) = ctrl.output_dac {
            ctrl.set_amp(0, dac, gain, mute);
        }
        if let Some(pin) = ctrl.output_pin {
            ctrl.set_amp(0, pin, gain, mute);
        }
    }

    crate::serial_println!(
        "[HDA] volume={}% (gain=0x{:02x}, mute={})",
        percent, gain, mute
    );
}

/// Start PCM playback of 16-bit signed samples at 48 kHz stereo.
///
/// The samples are copied into a persistent DMA buffer (up to 32 KiB /
/// ~170 ms of audio at 48 kHz). The stream is cyclic — it will loop
/// until [`stop_output_stream`] is called.
///
/// Returns `true` if the stream was started.
pub fn play_pcm(data: &[i16]) -> bool {
    if data.is_empty() {
        return false;
    }

    // Convert to little-endian bytes.
    let mut bytes: Vec<u8> = Vec::with_capacity(data.len() * 2);
    for &s in data {
        bytes.extend_from_slice(&s.to_le_bytes());
    }

    let mut guard = HDA.lock();
    let Some(ctrl) = guard.as_mut() else {
        return false;
    };

    unsafe {
        // Stop and reset the stream before rewriting the buffer, so the
        // HBA cannot read half-written data.
        stop_stream(ctrl);

        // Copy PCM into the persistent DMA buffer.
        let dst = ctrl.stream.as_mut_slice();
        let n = bytes.len().min(dst.len());
        dst[..n].fill(0);
        dst[..n].copy_from_slice(&bytes[..n]);

        // Start.
        let sd = ctrl.mmio + SD0_OFFSET as usize;
        let ctl = read32(sd, SD_CTL);
        write32(sd, SD_CTL, ctl | SD_CTL_RUN);
        ctrl.stream_running = true;
    }

    crate::serial_println!("[HDA] playback started ({} samples)", data.len());
    true
}

/// Stop the output stream.
pub fn stop_output_stream() {
    let mut guard = HDA.lock();
    if let Some(ctrl) = guard.as_mut() {
        unsafe { stop_stream(ctrl) };
    }
}

unsafe fn stop_stream(ctrl: &mut HdaController) {
    let sd = ctrl.mmio + SD0_OFFSET as usize;
    let ctl = read32(sd, SD_CTL);
    write32(sd, SD_CTL, ctl & !SD_CTL_RUN);
    wait_until(STREAM_TIMEOUT, || read32(sd, SD_CTL) & SD_CTL_RUN == 0);
    ctrl.stream_running = false;
}

// ---------------------------------------------------------------------------
// MMIO helpers
// ---------------------------------------------------------------------------

#[inline(always)]
unsafe fn read8(base: usize, off: u16) -> u8 {
    core::ptr::read_volatile((base + off as usize) as *const u8)
}
#[inline(always)]
unsafe fn read16(base: usize, off: u16) -> u16 {
    core::ptr::read_volatile((base + off as usize) as *const u16)
}
#[inline(always)]
unsafe fn read32(base: usize, off: u16) -> u32 {
    core::ptr::read_volatile((base + off as usize) as *const u32)
}
#[inline(always)]
unsafe fn write8(base: usize, off: u16, v: u8) {
    core::ptr::write_volatile((base + off as usize) as *mut u8, v);
}
#[inline(always)]
unsafe fn write16(base: usize, off: u16, v: u16) {
    core::ptr::write_volatile((base + off as usize) as *mut u16, v);
}
#[inline(always)]
unsafe fn write32(base: usize, off: u16, v: u32) {
    core::ptr::write_volatile((base + off as usize) as *mut u32, v);
}

/// Poll `cond` until true or `max_iters` exhausted. Returns whether it
/// became true.
#[inline]
fn wait_until<F: Fn() -> bool>(max_iters: usize, cond: F) -> bool {
    for _ in 0..max_iters {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
    }
    cond()
}

/// Convert a virtual address to a physical one under the identity map.
fn virt_to_phys(ptr: *const u8) -> Option<u64> {
    let addr = ptr as usize;
    if addr < PHYS_OFFSET {
        return None;
    }
    Some((addr - PHYS_OFFSET) as u64)
}

// Silence "unused" for constants kept as documentation anchors.
#[allow(dead_code)]
const _UNUSED_DOCS: [u16; 6] = [SD_STS, SD_LPIB, SD_CTL_IOCE, RIRBCNT, CORBSTS, SECTOR_SIZE as u16];
