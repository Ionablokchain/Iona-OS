//! Network driver abstraction — uniform interface over NIC backends.
//!
//! Single entry point for all Ethernet I/O in the kernel. Currently
//! fronts the VirtIO-net driver, but is structured so additional
//! backends (e1000, USB CDC-ECM, loopback) can be added without
//! changing call sites.
//!
//! # Two API tiers
//!
//! * **Recommended** (`try_*` functions) — validate arguments, return
//!   a typed [`NetError`], document exact failure modes. All new code
//!   should use these.
//!
//! * **Legacy** (`send_frame`, `recv_frame`, `is_present`, `mac`) —
//!   raw re-exports of the VirtIO-net functions with their original
//!   `bool` / `Option` signatures. Kept for backward compatibility;
//!   they do no validation and their failure modes are not enumerated.
//!
//! # Frame sizes
//!
//! A frame on the wire is `14` bytes of header + `0..=1500` bytes of
//! payload + `4` bytes of FCS. Callers supply header + payload only;
//! the driver appends the FCS. This module therefore accepts
//! `MIN_FRAME_LEN..=MAX_FRAME_LEN`, i.e. `14..=1514` bytes.
//!
//! # Concurrency
//!
//! All functions are safe to call from any context. `try_send_frame`
//! may block briefly while waiting for a TX descriptor; do not call it
//! from an interrupt handler that could preempt the driver's own
//! polling loop.
//!
//! # Example
//!
//! ```rust,ignore
//! use crate::drivers::net::{
//!     try_mac, try_send_frame, try_recv_frame, NetError,
//! };
//!
//! match try_mac() {
//!     Ok(mac) => crate::serial_println!("MAC {:02X?}", mac),
//!     Err(NetError::NotAvailable) => { /* no NIC installed */ }
//!     Err(e) => crate::serial_println!("MAC unavailable: {e}"),
//! }
//!
//! if let Err(e) = try_send_frame(&frame) {
//!     crate::serial_println!("send failed: {e}");
//! }
//!
//! while let Ok(Some(frame)) = try_recv_frame() {
//!     // dispatch(frame);
//! }
//! ```

use alloc::vec::Vec;

// The driver this module currently fronts. Aliased to keep the
// internal call sites unambiguous (module-level re-exports below
// expose the same names for backward compatibility).
use crate::drivers::virtio::net as virtio;

// ---------------------------------------------------------------------------
// Ethernet constants
// ---------------------------------------------------------------------------

/// Length of the Ethernet frame header in bytes (destination MAC +
/// source MAC + EtherType).
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Length of the Ethernet frame trailer (FCS).
///
/// The driver appends the FCS; callers must not include it in the
/// frame they pass to [`try_send_frame`], and frames returned by
/// [`try_recv_frame`] do not include it either.
pub const ETHERNET_FCS_LEN: usize = 4;

/// Minimum frame length accepted by this module.
///
/// Frames shorter than this on the wire are padded by hardware, but
/// the header itself must be present for the driver to route the
/// frame, so we reject anything below `ETHERNET_HEADER_LEN`.
pub const MIN_FRAME_LEN: usize = ETHERNET_HEADER_LEN;

/// Maximum frame length accepted by this module.
///
/// Standard Ethernet with a 1500-byte MTU: `14 + 1500 = 1514`. Jumbo
/// frames are not supported by any current backend.
pub const MAX_FRAME_LEN: usize = 1514;

/// Largest payload (MTU) that fits in a single frame.
pub const MAX_MTU: usize = MAX_FRAME_LEN - ETHERNET_HEADER_LEN; // 1500

/// All-zeros MAC address. Sentinel for "no MAC assigned".
pub const MAC_ZERO: [u8; 6] = [0x00; 6];

/// All-ones MAC address. Sentinel for "invalid / not assigned".
pub const MAC_BROADCAST: [u8; 6] = [0xFF; 6];

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the `try_*` API.
///
/// Callers should generally log and drop on any error except
/// [`NetError::TransmitFailed`], which indicates temporary congestion
/// and may succeed if retried after a short delay. There is currently
/// no error path for RX: an empty ring is `Ok(None)`, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    /// No network device is present or initialised.
    NotAvailable,

    /// The underlying driver rejected the frame. For VirtIO-net this
    /// typically means the TX queue is full; retrying after a short
    /// delay (or after the next RX interrupt) usually succeeds.
    TransmitFailed,

    /// Frame is shorter than the Ethernet minimum of 14 bytes.
    FrameTooSmall {
        /// Actual frame length.
        len: usize,
    },

    /// Frame exceeds [`MAX_FRAME_LEN`] bytes.
    FrameTooLarge {
        /// Actual frame length.
        len: usize,
    },

    /// A device is present but has not reported a usable MAC address
    /// (e.g. EEPROM read failed at init, or the address is all-zero
    /// or all-ones).
    MacUnavailable,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAvailable => f.write_str("no network device available"),
            Self::TransmitFailed => f.write_str("transmit failed (queue congested?)"),
            Self::FrameTooSmall { len } => {
                write!(f, "frame too small: {len} bytes (minimum {MIN_FRAME_LEN})")
            }
            Self::FrameTooLarge { len } => {
                write!(f, "frame too large: {len} bytes (maximum {MAX_FRAME_LEN})")
            }
            Self::MacUnavailable => f.write_str("MAC address not available"),
        }
    }
}

/// Result alias for network operations.
pub type NetResult<T> = Result<T, NetError>;

// ---------------------------------------------------------------------------
// Recommended (validated) API
// ---------------------------------------------------------------------------

/// Send an Ethernet frame.
///
/// `frame` must include the 14-byte Ethernet header but must **not**
/// include the 4-byte FCS; the driver appends it.
///
/// # Errors
///
/// * [`NetError::NotAvailable`] — no NIC is installed.
/// * [`NetError::FrameTooSmall`] — `frame.len() < 14`.
/// * [`NetError::FrameTooLarge`] — `frame.len() > 1514`.
/// * [`NetError::TransmitFailed`] — the TX ring is congested. Retry
///   after a short delay; this is not fatal.
pub fn try_send_frame(frame: &[u8]) -> NetResult<()> {
    if !virtio::is_present() {
        return Err(NetError::NotAvailable);
    }
    if frame.len() < MIN_FRAME_LEN {
        return Err(NetError::FrameTooSmall { len: frame.len() });
    }
    if frame.len() > MAX_FRAME_LEN {
        return Err(NetError::FrameTooLarge { len: frame.len() });
    }
    if virtio::send_frame(frame) {
        Ok(())
    } else {
        Err(NetError::TransmitFailed)
    }
}

/// Receive one Ethernet frame if one is ready.
///
/// Returns `Ok(None)` when the RX queue is empty. That is not an
/// error — it just means the caller should come back later (usually
/// after the next RX interrupt or the next poll iteration).
///
/// The returned frame does not include the FCS.
///
/// # Errors
///
/// * [`NetError::NotAvailable`] — no NIC is installed.
pub fn try_recv_frame() -> NetResult<Option<Vec<u8>>> {
    if !virtio::is_present() {
        return Err(NetError::NotAvailable);
    }
    Ok(virtio::recv_frame())
}

/// Return the MAC address of the active NIC.
///
/// Validates the result: all-zero and all-ones MAC addresses are
/// treated as missing.
///
/// # Errors
///
/// * [`NetError::NotAvailable`] — no NIC is installed.
/// * [`NetError::MacUnavailable`] — a NIC is present but has not
///   produced a usable MAC address.
pub fn try_mac() -> NetResult<[u8; 6]> {
    if !virtio::is_present() {
        return Err(NetError::NotAvailable);
    }
    match virtio::mac() {
        Some(m) if m != MAC_ZERO && m != MAC_BROADCAST => Ok(m),
        _ => Err(NetError::MacUnavailable),
    }
}

/// Return `true` if a network backend is installed and initialised.
///
/// Equivalent to the legacy [`is_present`] re-export, with a name that
/// reflects the semantic (link availability) rather than the
/// implementation (driver presence).
#[must_use]
pub fn link_up() -> bool {
    virtio::is_present()
}

// ---------------------------------------------------------------------------
// Backward-compatible re-exports
//
// The four functions below preserve the original re-export surface so
// existing code compiles unchanged. They are unvalidated and their
// failure modes are not enumerated. New code should use the `try_*`
// functions above.
// ---------------------------------------------------------------------------

/// **Legacy — prefer [`try_send_frame`].**
///
/// Send an Ethernet frame without validation. Returns `false` on any
/// failure (no NIC, invalid frame, congested queue) with no way to
/// distinguish between them.
pub use crate::drivers::virtio::net::send_frame;

/// **Legacy — prefer [`try_recv_frame`].**
///
/// Receive one Ethernet frame. Returns `None` when the ring is empty
/// or when no NIC is present.
pub use crate::drivers::virtio::net::recv_frame;

/// **Legacy — prefer [`link_up`].**
///
/// Return `true` if a NIC is present.
pub use crate::drivers::virtio::net::is_present;

/// **Legacy — prefer [`try_mac`].**
///
/// Return the NIC's MAC address with no validation. May return
/// `Some([0x00; 6])` or `Some([0xFF; 6])` on hardware that failed to
/// report a valid address.
pub use crate::drivers::virtio::net::mac;
