//! Network driver abstraction — re‑exports virtio‑net driver.
//!
//! This module provides a uniform interface for network drivers.
//! Currently, it re‑exports the VirtIO network driver functions.
//!
//! # Functions
//! - `send_frame(frame)` – Send an Ethernet frame.
//! - `recv_frame()` – Receive an Ethernet frame (blocking or polling).
//! - `is_present()` – Check if a network device is available.
//! - `mac()` – Get the MAC address of the network interface.
//!
//! # Example
//! ```rust,ignore
//! use crate::drivers::net::{send_frame, recv_frame, mac};
//!
//! if is_present() {
//!     let my_mac = mac();
//!     send_frame(&packet);
//!     if let Some(frame) = recv_frame() {
//!         // process
//!     }
//! }
//! ```

pub use crate::drivers::virtio::net::{send_frame, recv_frame, is_present, mac};
