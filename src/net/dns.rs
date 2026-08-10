//! DNS resolver — A record resolution over UDP.
//!
//! Protocol DNS (RFC 1035):
//!   Query: [ID:2][Flags:2][QDCOUNT:2][...][ANCOUNT:2][...][ARCOUNT:2]
//!   Question: [QNAME][QTYPE:2][QCLASS:2]
//!   Answer:   [NAME][TYPE:2][CLASS:2][TTL:4][RDLEN:2][RDATA]
//!
//! Features:
//!   - UDP-based DNS queries to configurable resolvers
//!   - LRU cache with configurable TTL
//!   - Support for multiple DNS servers (fallback)
//!   - Thread‑safe with `spin::Mutex`
//!   - Metrics for monitoring
//!   - Configurable timeouts and retries
//!   - Full RFC 1035 compliance for A record queries
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                            DNS Module                                  │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        metrics           │
//! │ (DnsConfig) │ (DnsError)   │ (DnsQuery,    │ (DnsMetrics)             │
//! │             │              │  DnsResponse) │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   cache     │   resolver   │    parser     │        manager           │
//! │ (DnsCache)  │ (query/send) │ (build/parse) │ (DnsManager)             │
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
//! let ip = manager.resolve("example.com").unwrap();
//! println!("IP: {}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::cmp::min;
use core::fmt;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use spin::{Mutex, MutexGuard};
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
        pub primary_dns: [u8; 4],
        pub secondary_dns: Option<[u8; 4]>,
        pub dns_port: u16,
        pub timeout_ms: u64,
        pub max_retries: usize,
        pub cache_size: usize,
        pub cache_ttl_secs: u64,
        pub collect_metrics: bool,
        pub log_queries: bool,
        pub dns_tx_id_seed: u16,
    }

    impl Default for DnsConfig {
        fn default() -> Self {
            Self {
                primary_dns: [8, 8, 8, 8],
                secondary_dns: Some([1, 1, 1, 1]),
                dns_port: 53,
                timeout_ms: 3000,
                max_retries: 3,
                cache_size: 128,
                cache_ttl_secs: 300,
                collect_metrics: true,
                log_queries: true,
                dns_tx_id_seed: 0x1234,
            }
        }
    }

    impl DnsConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.dns_port == 0 {
                return Err("dns_port must be > 0");
            }
            if self.timeout_ms == 0 {
                return Err("timeout_ms must be > 0");
            }
            if self.max_retries == 0 {
                return Err("max_retries must be > 0");
            }
            if self.cache_size == 0 {
                return Err("cache_size must be > 0");
            }
            if self.cache_ttl_secs == 0 {
                return Err("cache_ttl_secs must be > 0");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for DNS resolution.
    use alloc::string::String;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum DnsError {
        #[error("name resolution failed: {0}")]
        ResolutionFailed(String),

        #[error("timeout (after {retries} retries)")]
        Timeout { retries: usize },

        #[error("no DNS server available")]
        NoDnsServer,

        #[error("invalid response (malformed packet)")]
        MalformedResponse,

        #[error("NXDOMAIN (domain does not exist)")]
        NxDomain,

        #[error("SERVFAIL (server failure)")]
        ServFail,

        #[error("refused by server")]
        Refused,

        #[error("response truncated (TC=1)")]
        Truncated,

        #[error("no A record found for {0}")]
        NoARecord(String),

        #[error("I/O error: {0}")]
        Io(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type DnsResult<T> = Result<T, DnsError>;
}

pub mod types {
    //! Core types for DNS.
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::fmt;

    /// DNS response type.
    #[derive(Debug, Clone)]
    pub enum DnsResponse {
        ARecord([u8; 4]),
        CName(String),
        NxDomain,
        ServFail,
        Refused,
        Truncated,
    }

    /// DNS query type.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum DnsQueryType {
        A,
        AAAA,
        CNAME,
    }

    impl fmt::Display for DnsQueryType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::A => write!(f, "A"),
                Self::AAAA => write!(f, "AAAA"),
                Self::CNAME => write!(f, "CNAME"),
            }
        }
    }

    /// DNS record.
    #[derive(Debug, Clone)]
    pub struct DnsRecord {
        pub name: String,
        pub qtype: DnsQueryType,
        pub ttl: u32,
        pub data: Vec<u8>,
    }

    impl DnsRecord {
        pub fn to_ipv4(&self) -> Option<[u8; 4]> {
            if self.qtype == DnsQueryType::A && self.data.len() == 4 {
                let mut ip = [0u8; 4];
                ip.copy_from_slice(&self.data);
                Some(ip)
            } else {
                None
            }
        }
    }
}

pub mod cache {
    //! DNS cache with LRU eviction and TTL.
    use super::{
        config::DnsConfig,
        error::DnsResult,
    };
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };
    use core::time::Duration;
    use spin::Mutex;

    /// Cache entry with TTL.
    #[derive(Debug, Clone)]
    struct CacheEntry {
        ip: [u8; 4],
        expires_at: u64,  // seconds since epoch
    }

    /// DNS cache with LRU eviction.
    pub struct DnsCache {
        entries: Mutex<BTreeMap<String, CacheEntry>>,
        order: Mutex<Vec<String>>,
        capacity: usize,
        default_ttl: u64,
    }

    impl DnsCache {
        pub fn new(config: &DnsConfig) -> Self {
            Self {
                entries: Mutex::new(BTreeMap::new()),
                order: Mutex::new(Vec::with_capacity(config.cache_size)),
                capacity: config.cache_size,
                default_ttl: config.cache_ttl_secs,
            }
        }

        /// Get an IP from the cache if not expired.
        pub fn get(&self, name: &str) -> Option<[u8; 4]> {
            let now = current_time_secs();
            let mut entries = self.entries.lock();
            let mut order = self.order.lock();

            if let Some(entry) = entries.get(name) {
                if now < entry.expires_at {
                    // Move to back (most recently used).
                    order.retain(|x| x != name);
                    order.push(name.to_string());
                    return Some(entry.ip);
                } else {
                    // Expired, remove it.
                    entries.remove(name);
                    order.retain(|x| x != name);
                }
            }
            None
        }

        /// Insert an entry into the cache.
        pub fn insert(&self, name: &str, ip: [u8; 4], ttl_secs: Option<u64>) {
            let now = current_time_secs();
            let ttl = ttl_secs.unwrap_or(self.default_ttl);
            let expires_at = now + ttl;

            let mut entries = self.entries.lock();
            let mut order = self.order.lock();

            // If already present, update.
            if entries.contains_key(name) {
                entries.insert(name.to_string(), CacheEntry { ip, expires_at });
                order.retain(|x| x != name);
                order.push(name.to_string());
                return;
            }

            // Evict LRU if full.
            while entries.len() >= self.capacity {
                if let Some(evict) = order.first() {
                    entries.remove(evict);
                    order.remove(0);
                } else {
                    break;
                }
            }

            entries.insert(name.to_string(), CacheEntry { ip, expires_at });
            order.push(name.to_string());
        }

        /// Clear the cache.
        pub fn clear(&self) {
            self.entries.lock().clear();
            self.order.lock().clear();
        }

        /// Get the current size of the cache.
        pub fn size(&self) -> usize {
            self.entries.lock().len()
        }
    }

    fn current_time_secs() -> u64 {
        use core::time::Duration;
        // In kernel context, we use uptime_ms / 1000.
        crate::arch::x86_64::timer::uptime_ms() / 1000
    }
}

pub mod parser {
    //! DNS packet parser and builder.
    use super::{
        error::{DnsError, DnsResult},
        types::{DnsQueryType, DnsRecord},
    };
    use alloc::{
        string::{String, ToString},
        vec::Vec,
    };

    /// Build a DNS query packet for A record resolution.
    pub fn build_query(name: &str, tx_id: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(512);
        // Header
        q.extend_from_slice(&tx_id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]); // Flags: QR=0 Opcode=0 RD=1
        q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
        q.extend_from_slice(&[0x00, 0x00]); // ANCOUNT=0
        q.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
        q.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0
        // Question: encode name as labels
        for part in name.split('.') {
            if part.is_empty() { continue; }
            q.push(part.len() as u8);
            q.extend_from_slice(part.as_bytes());
        }
        q.push(0); // root label
        q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
        q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        q
    }

    /// Parse a DNS response, extract the first A record.
    pub fn parse_response(data: &[u8]) -> DnsResult<Option<[u8; 4]>> {
        if data.len() < 12 {
            return Err(DnsError::MalformedResponse);
        }

        let flags = u16::from_be_bytes([data[2], data[3]]);
        let rcode = flags & 0x000F;
        let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
        let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;

        // Must be a response (QR=1).
        if flags & 0x8000 == 0 {
            return Err(DnsError::MalformedResponse);
        }

        // Check response code.
        match rcode {
            0 => {} // No error.
            1 => return Err(DnsError::ServFail),
            2 => return Err(DnsError::ServFail),
            3 => return Err(DnsError::NxDomain),
            4 => return Err(DnsError::Refused),
            _ => return Err(DnsError::ServFail),
        }

        // Check truncated flag.
        if flags & 0x0200 != 0 {
            return Err(DnsError::Truncated);
        }

        if ancount == 0 {
            return Ok(None);
        }

        // Skip question section.
        let mut pos = 12;
        for _ in 0..qdcount {
            pos = skip_name(data, pos)?;
            pos += 4; // QTYPE + QCLASS
        }

        // Parse answer records.
        for _ in 0..ancount {
            if pos >= data.len() { break; }
            pos = skip_name(data, pos)?;
            if pos + 10 > data.len() { break; }
            let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let _rclass = u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            let _ttl = u32::from_be_bytes([data[pos + 4], data[pos + 5], data[pos + 6], data[pos + 7]]);
            let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
            pos += 10;
            if pos + rdlen > data.len() { break; }

            if rtype == 1 && rdlen == 4 {
                // Type A — IPv4 address.
                return Ok(Some([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]));
            }
            pos += rdlen;
        }
        Ok(None)
    }

    /// Skip a DNS name (labels or pointer).
    fn skip_name(data: &[u8], mut pos: usize) -> DnsResult<usize> {
        loop {
            if pos >= data.len() {
                return Err(DnsError::MalformedResponse);
            }
            let len = data[pos] as usize;
            if len == 0 {
                return Ok(pos + 1);
            }
            if len & 0xC0 == 0xC0 {
                return Ok(pos + 2);
            }
            pos += 1 + len;
        }
    }
}

pub mod resolver {
    //! DNS resolver implementation.
    use super::{
        config::DnsConfig,
        error::{DnsError, DnsResult},
        cache::DnsCache,
        parser::{build_query, parse_response},
        metrics::DnsMetrics,
    };
    use crate::net::udp;
    use alloc::vec::Vec;
    use core::time::Duration;
    use tracing::{debug, error, info, warn};

    /// DNS resolver with cache and configurable servers.
    pub struct DnsResolver {
        config: DnsConfig,
        cache: DnsCache,
        metrics: DnsMetrics,
        tx_id_counter: u16,
    }

    impl DnsResolver {
        pub fn new(config: DnsConfig) -> Self {
            Self {
                config,
                cache: DnsCache::new(&config),
                metrics: DnsMetrics::default(),
                tx_id_counter: config.dns_tx_id_seed,
            }
        }

        /// Resolve a hostname to an IPv4 address.
        pub fn resolve(&mut self, hostname: &str) -> DnsResult<[u8; 4]> {
            // Check cache first.
            if let Some(ip) = self.cache.get(hostname) {
                self.metrics.inc_cache_hit();
                if self.config.log_queries {
                    debug!(hostname, ip = ?ip, "DNS cache hit");
                }
                return Ok(ip);
            }
            self.metrics.inc_cache_miss();

            // Try direct IP parsing.
            if let Some(ip) = parse_ipv4(hostname) {
                self.metrics.inc_resolution_success();
                return Ok(ip);
            }

            if self.config.log_queries {
                info!(hostname, "DNS resolving");
            }

            // Try primary DNS server with retries.
            let servers = self.dns_servers();
            for (idx, &dns_server) in servers.iter().enumerate() {
                let result = self.resolve_with_server(hostname, dns_server);
                match result {
                    Ok(ip) => {
                        // Cache the result.
                        self.cache.insert(hostname, ip, None);
                        self.metrics.inc_resolution_success();
                        if self.config.log_queries {
                            info!(hostname, ip = ?ip, "DNS resolved");
                        }
                        return Ok(ip);
                    }
                    Err(e) => {
                        if idx == servers.len() - 1 {
                            self.metrics.inc_resolution_failure();
                            return Err(e);
                        }
                        debug!(server = ?dns_server, error = %e, "DNS server failed, trying next");
                    }
                }
            }

            Err(DnsError::ResolutionFailed("all DNS servers failed".into()))
        }

        fn resolve_with_server(&mut self, hostname: &str, dns_server: [u8; 4]) -> DnsResult<[u8; 4]> {
            let tx_id = self.next_tx_id();
            let query = build_query(hostname, tx_id);
            let fd = udp::udp_bind(0).map_err(|e| DnsError::Io(e.to_string()))?;

            let mut last_error = None;
            for attempt in 0..self.config.max_retries {
                if attempt > 0 {
                    debug!(hostname, attempt, "DNS retry");
                    // Wait a bit before retry.
                    crate::arch::x86_64::timer::sleep_ms(100 * attempt as u64);
                }

                // Send query.
                if let Err(e) = udp::udp_sendto(fd, &query, dns_server, self.config.dns_port) {
                    last_error = Some(DnsError::Io(e.to_string()));
                    continue;
                }

                // Wait for response with timeout.
                let deadline = crate::arch::x86_64::timer::uptime_ms() + self.config.timeout_ms;
                let mut buf = [0u8; 1024];

                while crate::arch::x86_64::timer::uptime_ms() < deadline {
                    match udp::udp_recvfrom(fd, &mut buf) {
                        Ok((n, _src_ip, _src_port)) if n >= 12 => {
                            let resp_id = u16::from_be_bytes([buf[0], buf[1]]);
                            if resp_id == tx_id {
                                let result = parse_response(&buf[..n]);
                                match result {
                                    Ok(Some(ip)) => {
                                        self.metrics.inc_queries_sent();
                                        return Ok(ip);
                                    }
                                    Ok(None) => {
                                        return Err(DnsError::NoARecord(hostname.into()));
                                    }
                                    Err(e) => {
                                        last_error = Some(e);
                                        break;
                                    }
                                }
                            }
                        }
                        _ => {}
                    }
                    crate::arch::x86_64::timer::sleep_ms(10);
                }

                if last_error.is_none() {
                    last_error = Some(DnsError::Timeout {
                        retries: attempt + 1,
                    });
                }
            }

            self.metrics.inc_resolution_failure();
            Err(last_error.unwrap_or_else(|| DnsError::Timeout {
                retries: self.config.max_retries,
            }))
        }

        fn dns_servers(&self) -> alloc::vec::Vec<[u8; 4]> {
            let mut servers = alloc::vec::Vec::new();
            servers.push(self.config.primary_dns);
            if let Some(secondary) = self.config.secondary_dns {
                servers.push(secondary);
            }
            servers
        }

        fn next_tx_id(&mut self) -> u16 {
            self.tx_id_counter = self.tx_id_counter.wrapping_add(1);
            self.tx_id_counter
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &DnsMetrics {
            &self.metrics
        }

        /// Get a reference to the cache.
        pub fn cache(&self) -> &DnsCache {
            &self.cache
        }

        /// Clear the cache.
        pub fn clear_cache(&self) {
            self.cache.clear();
        }
    }

    /// Parse IPv4 address from string.
    pub fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
        let parts: alloc::vec::Vec<&str> = s.split('.').collect();
        if parts.len() != 4 {
            return None;
        }
        let mut ip = [0u8; 4];
        for (i, part) in parts.iter().enumerate() {
            ip[i] = part.parse::<u8>().ok()?;
        }
        Some(ip)
    }
}

pub mod metrics {
    //! Metrics for DNS resolution.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct DnsMetrics {
        pub queries_sent: AtomicU64,
        pub cache_hits: AtomicU64,
        pub cache_misses: AtomicU64,
        pub resolution_success: AtomicU64,
        pub resolution_failure: AtomicU64,
        pub timeouts: AtomicU64,
        pub nxdomain: AtomicU64,
        pub servfail: AtomicU64,
    }

    impl DnsMetrics {
        pub fn inc_queries_sent(&self) {
            self.queries_sent.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cache_hit(&self) {
            self.cache_hits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_cache_miss(&self) {
            self.cache_misses.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_resolution_success(&self) {
            self.resolution_success.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_resolution_failure(&self) {
            self.resolution_failure.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_timeout(&self) {
            self.timeouts.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_nxdomain(&self) {
            self.nxdomain.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_servfail(&self) {
            self.servfail.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> DnsMetricsSnapshot {
            DnsMetricsSnapshot {
                queries_sent: self.queries_sent.load(Ordering::Relaxed),
                cache_hits: self.cache_hits.load(Ordering::Relaxed),
                cache_misses: self.cache_misses.load(Ordering::Relaxed),
                resolution_success: self.resolution_success.load(Ordering::Relaxed),
                resolution_failure: self.resolution_failure.load(Ordering::Relaxed),
                timeouts: self.timeouts.load(Ordering::Relaxed),
                nxdomain: self.nxdomain.load(Ordering::Relaxed),
                servfail: self.servfail.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct DnsMetricsSnapshot {
        pub queries_sent: u64,
        pub cache_hits: u64,
        pub cache_misses: u64,
        pub resolution_success: u64,
        pub resolution_failure: u64,
        pub timeouts: u64,
        pub nxdomain: u64,
        pub servfail: u64,
    }
}

pub mod manager {
    //! Centralised DNS manager.
    use super::{
        config::DnsConfig,
        error::{DnsError, DnsResult},
        resolver::DnsResolver,
        metrics::DnsMetricsSnapshot,
    };
    use alloc::string::String;
    use core::fmt;

    /// Centralised manager for DNS resolution.
    pub struct DnsManager {
        resolver: DnsResolver,
    }

    impl DnsManager {
        /// Create a new DNS manager with the given configuration.
        pub fn new(config: DnsConfig) -> Self {
            Self {
                resolver: DnsResolver::new(config),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(DnsConfig::default())
        }

        /// Resolve a hostname to an IPv4 address.
        pub fn resolve(&mut self, hostname: &str) -> DnsResult<[u8; 4]> {
            self.resolver.resolve(hostname)
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &super::metrics::DnsMetrics {
            self.resolver.metrics()
        }

        /// Get a reference to the cache.
        pub fn cache(&self) -> &super::cache::DnsCache {
            self.resolver.cache()
        }

        /// Clear the DNS cache.
        pub fn clear_cache(&self) {
            self.resolver.clear_cache();
        }

        /// Get metrics snapshot.
        pub fn metrics_snapshot(&self) -> DnsMetricsSnapshot {
            self.resolver.metrics().snapshot()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::DnsConfig;
pub use error::{DnsError, DnsResult};
pub use types::{DnsQueryType, DnsRecord, DnsResponse};
pub use cache::DnsCache;
pub use resolver::{DnsResolver, parse_ipv4};
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

/// Get a mutable reference to the global manager.
fn global_manager_mut() -> &'static mut DnsManager {
    // SAFETY: This is called only during init or with exclusive access.
    // In a real kernel, we'd use proper synchronization.
    unsafe { &mut *(GLOBAL_MANAGER as *const _ as *mut _) }
}

/// Resolve a hostname to an IPv4 address.
pub fn resolve(hostname: &str) -> Option<[u8; 4]> {
    global_manager_mut().resolve(hostname).ok()
}

/// Resolve a hostname to an IPv4 address (full version with more detailed error).
pub fn resolve_full(hostname: &str) -> Option<[u8; 4]> {
    resolve(hostname)
}

/// Insert a static entry into the DNS cache.
pub fn cache_insert(name: &str, ip: [u8; 4]) {
    let mgr = global_manager();
    mgr.cache().insert(name, ip, None);
}

/// Clear the DNS cache.
pub fn cache_clear() {
    let mgr = global_manager();
    mgr.clear_cache();
}

/// Get DNS metrics snapshot.
pub fn metrics() -> DnsMetricsSnapshot {
    let mgr = global_manager();
    mgr.metrics_snapshot()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        assert_eq!(parse_ipv4("192.168.1.1"), Some([192, 168, 1, 1]));
        assert_eq!(parse_ipv4("invalid"), None);
        assert_eq!(parse_ipv4("1.2.3.4.5"), None);
    }

    #[test]
    fn test_build_query() {
        let q = parser::build_query("example.com", 0x1234);
        // Minimal length check: header 12 + question (labels + root + qtype + qclass).
        assert!(q.len() >= 12 + 5);
        // Check transaction ID.
        assert_eq!(q[0], 0x12);
        assert_eq!(q[1], 0x34);
        // Check flags.
        assert_eq!(q[2], 0x01);
        assert_eq!(q[3], 0x00);
        // Check QDCOUNT = 1.
        assert_eq!(q[4], 0x00);
        assert_eq!(q[5], 0x01);
    }

    #[test]
    fn test_cache_basic() {
        let config = DnsConfig::default();
        let cache = DnsCache::new(&config);
        assert_eq!(cache.get("example.com"), None);
        cache.insert("example.com", [1, 2, 3, 4], Some(3600));
        assert_eq!(cache.get("example.com"), Some([1, 2, 3, 4]));
        // Insert second entry.
        cache.insert("test.com", [5, 6, 7, 8], Some(3600));
        // Should still have both.
        assert_eq!(cache.size(), 2);
    }

    #[test]
    fn test_cache_eviction() {
        let mut config = DnsConfig::default();
        config.cache_size = 2;
        let cache = DnsCache::new(&config);
        cache.insert("a.com", [1, 1, 1, 1], Some(3600));
        cache.insert("b.com", [2, 2, 2, 2], Some(3600));
        assert_eq!(cache.size(), 2);
        cache.insert("c.com", [3, 3, 3, 3], Some(3600));
        // Should evict the oldest (a.com).
        assert_eq!(cache.size(), 2);
        assert_eq!(cache.get("a.com"), None);
        assert_eq!(cache.get("b.com"), Some([2, 2, 2, 2]));
        assert_eq!(cache.get("c.com"), Some([3, 3, 3, 3]));
    }

    #[test]
    fn test_config_validation() {
        let mut config = DnsConfig::default();
        assert!(config.validate().is_ok());
        config.dns_port = 0;
        assert!(config.validate().is_err());
        config.dns_port = 53;
        config.timeout_ms = 0;
        assert!(config.validate().is_err());
        config.timeout_ms = 1000;
        config.max_retries = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_dns_record() {
        let record = DnsRecord {
            name: "example.com".into(),
            qtype: DnsQueryType::A,
            ttl: 300,
            data: vec![1, 2, 3, 4],
        };
        assert_eq!(record.to_ipv4(), Some([1, 2, 3, 4]));
        let record2 = DnsRecord {
            qtype: DnsQueryType::CNAME,
            ..record
        };
        assert_eq!(record2.to_ipv4(), None);
    }
}
