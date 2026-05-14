//! Network driver abstraction — re-exports virtio-net
pub use crate::drivers::virtio::net::{send_frame, recv_frame, is_present, mac};
