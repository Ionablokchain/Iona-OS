//! DNS resolver — A record queries via UDP.
//!
//! Implements RFC 1035 with caching, configurable timeouts, and fallback.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            DNS Module                                  │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     cache     │        query             │
//! │ (DnsConfig) │ (DnsError)   │ (LRU cache)   │ (build & send)           │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   parser    │   manager    │    metrics    │        legacy            │
//! │ (response)  │ (DnsManager) │ (metrics)     │ (global functions)       │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::net::dns::{DnsManager, DnsConfig};
//!
//! let config = DnsConfig::default();
//! let manager = DnsManager::new(config);
//! let ip = manager.resolve("example.com")?;
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::time::Duration;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the DNS resolver.
    use serde::{Deserialize, Serialize};

    /// Configuration for the DNS resolver.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DnsConfig {
        pub timeout_ms: u64,
        pub retries: usize,
        pub cache_size: usize,
        pub cache_ttl_secs: u64,
        pub default_dns_server: [u8; 4],
        pub fallback_servers: Vec<[u8; 4]>,
        pub collect_metrics: bool,
        pub log_queries: bool,
    }

    impl Default for DnsConfig {
        fn default() -> Self {
            Self {
                timeout_ms: 3000,
                retries: 3,
                cache_size: 128,
                cache_ttl_secs: 300,
                default_dns_server: [8, 8, 8, 8],
                fallback_servers: vec![[1, 1, 1, 1], [9, 9, 9, 9]],
                collect_metrics: true,
                log_queries: true,
            }
        }
    }

    impl DnsConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.timeout_ms == 0 { return Err("timeout_ms must be > 0"); }
            if self.retries == 0 { return Err("retries must be > 0"); }
            if self.cache_size == 0 { return Err("cache_size must be > 0"); }
            if self.cache_ttl_secs == 0 { return Err("cache_ttl_secs must be > 0"); }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for DNS operations.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum DnsError {
        #[error("DNS query timeout")]
        Timeout,

        #[error("DNS server error: rcode={0}")]
        ServerError(u8),

        #[error("NXDOMAIN (no such domain)")]
        NxDomain,

        #[error("no A record found")]
        NoARecord,

        #[error("truncated response (TC bit set)")]
        Truncated,

        #[error("malformed DNS packet: {0}")]
        MalformedPacket(&'static str),

        #[error("I/O error: {0}")]
        Io(String),

        #[error("cache full")]
        CacheFull,

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type DnsResult<T> = Result<T, DnsError>;
}

pub mod cache {
    //! DNS cache with TTL and LRU eviction.
    use super::{
        config::DnsConfig,
        error::{DnsError, DnsResult},
        metrics::DnsMetrics,
    };
    use alloc::{
        collections::{BTreeMap, VecDeque},
        string::String,
        vec::Vec,
    };
    use core::time::{Duration, Instant};

    /// Cache entry with TTL.
    #[derive(Clone)]
    pub struct CacheEntry {
        pub ip: [u8; 4],
        pub expires_at: u64, // milliseconds since boot
    }

    /// DNS cache with LRU eviction.
    pub struct DnsCache {
        entries: BTreeMap<String, CacheEntry>,
        order: VecDeque<String>,
        capacity: usize,
        ttl_secs: u64,
    }

    impl DnsCache {
        pub fn new(config: &DnsConfig) -> Self {
            Self {
                entries: BTreeMap::new(),
                order: VecDeque::with_capacity(config.cache_size),
                capacity: config.cache_size,
                ttl_secs: config.cache_ttl_secs,
            }
        }

        /// Get an entry if not expired.
        pub fn get(&self, name: &str, now_ms: u64) -> Option<[u8; 4]> {
            self.entries.get(name).and_then(|entry| {
                if entry.expires_at > now_ms {
                    Some(entry.ip)
                } else {
                    None
                }
            })
        }

        /// Insert an entry, evicting oldest if full.
        pub fn insert(&mut self, name: String, ip: [u8; 4], now_ms: u64, metrics: &DnsMetrics) -> DnsResult<()> {
            let expires_at = now_ms + (self.ttl_secs * 1000);
            if self.entries.contains_key(&name) {
                // Update existing.
                self.entries.get_mut(&name).unwrap().expires_at = expires_at;
                // Move to back of order.
                self.order.retain(|n| n != &name);
                self.order.push_back(name);
                return Ok(());
            }

            // Evict if full.
            if self.entries.len() >= self.capacity {
                if let Some(evicted) = self.order.pop_front() {
                    self.entries.remove(&evicted);
                    metrics.inc_evictions();
                } else {
                    return Err(DnsError::CacheFull);
                }
            }

            self.entries.insert(name.clone(), CacheEntry { ip, expires_at });
            self.order.push_back(name);
            Ok(())
        }

        /// Clear the cache.
        pub fn clear(&mut self) {
            self.entries.clear();
            self.order.clear();
        }
    }
}

pub mod query {
    //! DNS query builder and sender.
    use super::{
        config::DnsConfig,
        error::{DnsError, DnsResult},
        parser::{skip_name, parse_response},
        metrics::DnsMetrics,
    };
    use alloc::vec::Vec;
    use tracing::{debug, warn};

    /// Build a DNS A record query packet.
    pub fn build_query(name: &str, tx_id: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(512);
        // Header
        q.extend_from_slice(&tx_id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // Flags: RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // Question
        for part in name.split('.') {
            q.push(part.len() as u8);
            q.extend_from_slice(part.as_bytes());
        }
        q.push(0); // root label
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        q
    }

    /// Send a DNS query and wait for response.
    pub fn send_query(
        hostname: &str,
        dns_server: [u8; 4],
        timeout_ms: u64,
        retries: usize,
        metrics: &DnsMetrics,
        log: bool,
    ) -> DnsResult<[u8; 4]> {
        let tx_id = (crate::arch::x86_64::timer::uptime_ms() & 0xFFFF) as u16;
        let query = build_query(hostname, tx_id);

        // Bind to ephemeral port.
        let fd = crate::net::udp::udp_bind([0, 0, 0, 0], 0)
            .ok_or_else(|| DnsError::Io("failed to bind UDP socket".into()))?;

        let mut last_error = DnsError::Timeout;

        for attempt in 0..retries {
            if attempt > 0 {
                // Exponential backoff.
                let delay = 100 * (1 << attempt);
                crate::arch::x86_64::timer::sleep_ms(delay);
            }

            // Send query.
            crate::net::udp::udp_sendto(fd, &query, dns_server, 53);

            let deadline = crate::arch::x86_64::timer::uptime_ms() + timeout_ms;
            let mut buf = [0u8; 512];

            while crate::arch::x86_64::timer::uptime_ms() < deadline {
                let (n, _src_ip, _src_port) = crate::net::udp::udp_recvfrom(fd, &mut buf);
                if n >= 12 {
                    let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                    if resp_id == tx_id {
                        match parse_response(&buf[..n]) {
                            Ok(ip) => {
                                if log {
                                    debug!("DNS {} → {}.{}.{}.{}", hostname, ip[0], ip[1], ip[2], ip[3]);
                                }
                                metrics.inc_success();
                                crate::net::udp::udp_close(fd);
                                return Ok(ip);
                            }
                            Err(e) => {
                                last_error = e;
                                // If NXDOMAIN, don't retry.
                                if matches!(last_error, DnsError::NxDomain | DnsError::NoARecord) {
                                    break;
                                }
                            }
                        }
                    }
                }
                // Sleep a bit to avoid busy loop.
                crate::arch::x86_64::timer::sleep_ms(10);
            }

            // Timeout for this attempt.
            if attempt + 1 < retries {
                if log {
                    warn!("DNS timeout attempt {}/{}", attempt + 1, retries);
                }
            }
        }

        crate::net::udp::udp_close(fd);
        metrics.inc_failures();
        Err(last_error)
    }
}

pub mod parser {
    //! DNS response parser.
    use super::error::{DnsError, DnsResult};
    use alloc::vec::Vec;

    /// Skip a DNS name (labels or pointer).
    pub fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
        loop {
            if pos >= data.len() { return None; }
            let len = data[pos] as usize;
            if len == 0 { return Some(pos + 1); }
            if len & 0xC0 == 0xC0 { return Some(pos + 2); } // pointer
            pos += 1 + len;
        }
    }

    /// Parse a DNS response, returning the first A record.
    pub fn parse_response(data: &[u8]) -> DnsResult<[u8; 4]> {
        if data.len() < 12 {
            return Err(DnsError::MalformedPacket("too short"));
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

        // Must be a response (QR=1)
        if flags & 0x8000 == 0 {
            return Err(DnsError::MalformedPacket("not a response"));
        }

        // Handle rcode.
        match rcode {
            0 => {} // success
            3 => return Err(DnsError::NxDomain),
            _ => return Err(DnsError::ServerError(rcode as u8)),
        }

        if ancount == 0 {
            return Err(DnsError::NoARecord);
        }

        // TC bit: truncated.
        if flags & 0x0200 != 0 {
            return Err(DnsError::Truncated);
        }

        // Skip question section.
        let mut pos = 12;
        for _ in 0..qdcount {
            pos = skip_name(data, pos).ok_or(DnsError::MalformedPacket("bad QNAME"))?;
            pos += 4; // QTYPE + QCLASS
            if pos > data.len() { return Err(DnsError::MalformedPacket("overflow")); }
        }

        // Parse answer records.
        for _ in 0..ancount {
            pos = skip_name(data, pos).ok_or(DnsError::MalformedPacket("bad NAME"))?;
            if pos + 10 > data.len() {
                return Err(DnsError::MalformedPacket("answer too short"));
            }
            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > data.len() {
                return Err(DnsError::MalformedPacket("RDATA overflow"));
            }

            if rtype == 1 && rdlen == 4 {
                return Ok([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            }
            // Skip other record types.
            pos += rdlen;
        }
        Err(DnsError::NoARecord)
    }
}

pub mod metrics {
    //! Metrics for DNS operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct DnsMetrics {
        pub queries_total: AtomicU64,
        pub cache_hits: AtomicU64,
        pub cache_misses: AtomicU64,
        pub cache_evictions: AtomicU64,
        pub successes: AtomicU64,
        pub failures: AtomicU64,
        pub timeouts: AtomicU64,
        pub nxdomain: AtomicU64,
    }

    impl DnsMetrics {
        pub fn inc_queries(&self) { self.queries_total.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_cache_hit(&self) { self.cache_hits.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_cache_miss(&self) { self.cache_misses.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_evictions(&self) { self.cache_evictions.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_success(&self) { self.successes.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_failures(&self) { self.failures.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_timeout(&self) { self.timeouts.fetch_add(1, Ordering::Relaxed); }
        pub fn inc_nxdomain(&self) { self.nxdomain.fetch_add(1, Ordering::Relaxed); }

        pub fn snapshot(&self) -> DnsMetricsSnapshot {
            DnsMetricsSnapshot {
                queries_total: self.queries_total.load(Ordering::Relaxed),
                cache_hits: self.cache_hits.load(Ordering::Relaxed),
                cache_misses: self.cache_misses.load(Ordering::Relaxed),
                cache_evictions: self.cache_evictions.load(Ordering::Relaxed),
                successes: self.successes.load(Ordering::Relaxed),
                failures: self.failures.load(Ordering::Relaxed),
                timeouts: self.timeouts.load(Ordering::Relaxed),
                nxdomain: self.nxdomain.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DnsMetricsSnapshot {
        pub queries_total: u64,
        pub cache_hits: u64,
        pub cache_misses: u64,
        pub cache_evictions: u64,
        pub successes: u64,
        pub failures: u64,
        pub timeouts: u64,
        pub nxdomain: u64,
    }
}

pub mod manager {
    //! Centralised DNS resolver.
    use super::{
        config::DnsConfig,
        error::{DnsError, DnsResult},
        cache::DnsCache,
        query::send_query,
        metrics::DnsMetrics,
    };
    use alloc::string::String;
    use core::sync::atomic::Ordering;
    use spin::RwLock;
    use tracing::{debug, info, warn};

    /// Centralised DNS manager.
    pub struct DnsManager {
        config: DnsConfig,
        cache: RwLock<DnsCache>,
        metrics: DnsMetrics,
        dns_servers: RwLock<Vec<[u8; 4]>>,
    }

    impl DnsManager {
        pub fn new(config: DnsConfig) -> Self {
            config.validate().expect("invalid DnsConfig");
            let cache = DnsCache::new(&config);
            let mut servers = Vec::with_capacity(1 + config.fallback_servers.len());
            servers.push(config.default_dns_server);
            servers.extend_from_slice(&config.fallback_servers);
            Self {
                config,
                cache: RwLock::new(cache),
                metrics: DnsMetrics::default(),
                dns_servers: RwLock::new(servers),
            }
        }

        pub fn default() -> Self {
            Self::new(DnsConfig::default())
        }

        /// Get metrics snapshot.
        pub fn metrics(&self) -> super::metrics::DnsMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Get configuration.
        pub fn config(&self) -> &DnsConfig {
            &self.config
        }

        /// Update the DNS server list (e.g., from DHCP).
        pub fn set_dns_servers(&self, servers: &[[u8; 4]]) {
            let mut list = self.dns_servers.write();
            list.clear();
            list.extend_from_slice(servers);
            if list.is_empty() {
                list.push(self.config.default_dns_server);
            }
        }

        /// Resolve a hostname to an IPv4 address.
        pub fn resolve(&self, hostname: &str) -> DnsResult<[u8; 4]> {
            self.metrics.inc_queries();
            let now_ms = crate::arch::x86_64::timer::uptime_ms();

            // Check cache.
            {
                let cache = self.cache.read();
                if let Some(ip) = cache.get(hostname, now_ms) {
                    self.metrics.inc_cache_hit();
                    if self.config.log_queries {
                        debug!("DNS cache hit: {} -> {}.{}.{}.{}", hostname, ip[0], ip[1], ip[2], ip[3]);
                    }
                    return Ok(ip);
                }
            }
            self.metrics.inc_cache_miss();

            // Parse as direct IP.
            if let Some(ip) = parse_ipv4(hostname) {
                // Cache it anyway.
                let mut cache = self.cache.write();
                let _ = cache.insert(hostname.to_string(), ip, now_ms, &self.metrics);
                return Ok(ip);
            }

            // Hardcoded localhost.
            if hostname == "localhost" || hostname == "127.0.0.1" {
                return Ok([127, 0, 0, 1]);
            }

            // Try each DNS server in order.
            let servers = self.dns_servers.read();
            let mut last_err = DnsError::Timeout;
            for server in servers.iter() {
                match send_query(
                    hostname,
                    *server,
                    self.config.timeout_ms,
                    self.config.retries,
                    &self.metrics,
                    self.config.log_queries,
                ) {
                    Ok(ip) => {
                        // Cache result.
                        let mut cache = self.cache.write();
                        let _ = cache.insert(hostname.to_string(), ip, now_ms, &self.metrics);
                        return Ok(ip);
                    }
                    Err(e) => {
                        last_err = e;
                        if matches!(last_err, DnsError::NxDomain | DnsError::NoARecord) {
                            break;
                        }
                    }
                }
            }

            self.metrics.inc_failures();
            Err(last_err)
        }

        /// Insert an entry into the cache (manual).
        pub fn cache_insert(&self, name: &str, ip: [u8; 4]) {
            let now_ms = crate::arch::x86_64::timer::uptime_ms();
            let mut cache = self.cache.write();
            let _ = cache.insert(name.to_string(), ip, now_ms, &self.metrics);
        }

        /// Clear the DNS cache.
        pub fn clear_cache(&self) {
            let mut cache = self.cache.write();
            cache.clear();
        }
    }

    /// Parse IPv4 address from string.
    fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() != 4 { return None; }
        let mut ip = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            ip[i] = part.parse::<u8>().ok()?;
        }
        Some(ip)
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::DnsConfig;
pub use error::{DnsError, DnsResult};
pub use metrics::{DnsMetrics, DnsMetricsSnapshot};
pub use manager::DnsManager;

// -----------------------------------------------------------------------------
// Legacy global API (wrappers around a global singleton)
// -----------------------------------------------------------------------------

static GLOBAL_MANAGER: spin::Once<DnsManager> = spin::Once::new();

/// Initialize the global DNS manager.
pub fn init() {
    GLOBAL_MANAGER.call_once(|| DnsManager::default());
    crate::serial_println!("  [DNS] resolver initialized");
}

/// Get a reference to the global manager.
fn global_manager() -> &'static DnsManager {
    GLOBAL_MANAGER.get().expect("DNS manager not initialized")
}

/// Resolve a hostname to IPv4.
pub fn resolve(hostname: &str) -> Option<[u8; 4]> {
    global_manager().resolve(hostname).ok()
}

/// Insert a cache entry.
pub fn cache_insert(name: &str, ip: [u8; 4]) {
    global_manager().cache_insert(name, ip);
}

/// Clear the cache.
pub fn clear_cache() {
    global_manager().clear_cache();
}

/// Set DNS servers.
pub fn set_dns_servers(servers: &[[u8; 4]]) {
    global_manager().set_dns_servers(servers);
}

/// Get metrics snapshot.
pub fn metrics() -> DnsMetricsSnapshot {
    global_manager().metrics()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = DnsConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.timeout_ms = 0;
        assert!(bad.validate().is_err());

        let mut bad2 = config;
        bad2.cache_size = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("256.0.0.1"), None);
    }

    #[test]
    fn test_cache_insert_and_get() {
        let config = DnsConfig::default();
        let mut cache = cache::DnsCache::new(&config);
        let metrics = DnsMetrics::default();
        let now = 1000;
        cache.insert("example.com".into(), [1, 2, 3, 4], now, &metrics).unwrap();
        assert_eq!(cache.get("example.com", now), Some([1, 2, 3, 4]));
        // Expired.
        let later = now + 300 * 1000 + 1;
        assert_eq!(cache.get("example.com", later), None);
    }
}
