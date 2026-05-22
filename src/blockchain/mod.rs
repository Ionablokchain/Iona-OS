//! Blockchain integration modules
//!
//! This module provides the core components for integrating IONA with
//! external blockchain systems and protocols. It includes:
//!
//! - **redb_adapter** – persistent storage backend using the Redb embedded database.
//! - **gossipsub** – P2P networking using the Gossipsub protocol (libp2p).
//! - **revm_port** – EVM execution engine via the REVM library.
//!
//! These modules together enable IONA to function as a fully‑featured
//! blockchain node with transaction propagation, state persistence, and
//! EVM compatibility.

pub mod redb_adapter;
pub mod gossipsub;
pub mod revm_port;
