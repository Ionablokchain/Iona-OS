//! P2P networking — HTTP client + minimal gossip via TCP syscalls
//! Înlocuiește libp2p/gossipsub cu implementare directă pe syscall-uri TCP

use alloc::string::String;
use alloc::vec::Vec;
use iona_syscall as sys;

pub struct HttpClient;

impl HttpClient {
    /// GET simplu via TCP
    pub fn get(url: &str) -> Result<Vec<u8>, &'static str> {
        let (host, port, path) = parse_url(url)?;
        let fd = sys::tcp_connect(host, port);
        if fd == u64::MAX { return Err("TCP connect failed"); }

        let request = alloc::format!(
            "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path,
            core::str::from_utf8(&host).unwrap_or("host")
        );
        sys::tcp_send(fd, request.as_bytes());

        let mut response = Vec::new();
        let mut buf = alloc::vec![0u8; 4096];
        loop {
            let n = sys::tcp_recv(fd, &mut buf);
            if n == 0 { break; }
            response.extend_from_slice(&buf[..n]);
        }
        sys::tcp_close(fd);

        // Extragem body (după \r\n\r\n)
        if let Some(pos) = find_body(&response) {
            Ok(response[pos..].to_vec())
        } else {
            Ok(response)
        }
    }

    /// POST simplu via TCP
    pub fn post(url: &str, body: &[u8]) -> Result<Vec<u8>, &'static str> {
        let (host, port, path) = parse_url(url)?;
        let fd = sys::tcp_connect(host, port);
        if fd == u64::MAX { return Err("TCP connect failed"); }

        let header = alloc::format!(
            "POST {} HTTP/1.0\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            path,
            core::str::from_utf8(&host).unwrap_or("host"),
            body.len()
        );
        sys::tcp_send(fd, header.as_bytes());
        sys::tcp_send(fd, body);

        let mut response = Vec::new();
        let mut buf = alloc::vec![0u8; 4096];
        loop {
            let n = sys::tcp_recv(fd, &mut buf);
            if n == 0 { break; }
            response.extend_from_slice(&buf[..n]);
        }
        sys::tcp_close(fd);

        if let Some(pos) = find_body(&response) {
            Ok(response[pos..].to_vec())
        } else {
            Ok(response)
        }
    }
}

fn parse_url(url: &str) -> Result<([u8; 4], u16, &str), &'static str> {
    // Suportăm http://a.b.c.d:port/path
    let url = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = url.split_once('/').unwrap_or((url, ""));
    let path = alloc::format!("/{}", path);
    let path: &str = alloc::format!("/{}", path).leak();

    let (host_str, port_str) = host_port.split_once(':').unwrap_or((host_port, "9001"));
    let port: u16 = port_str.parse().unwrap_or(9001);

    let mut ip = [127u8, 0, 0, 1];
    let parts: Vec<&str> = host_str.split('.').collect();
    if parts.len() == 4 {
        for (i, p) in parts.iter().enumerate() {
            ip[i] = p.parse().unwrap_or(0);
        }
    }
    Ok((ip, port, path))
}

fn find_body(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(3) {
        if &data[i..i+4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

/// Minimal gossip: broadcast un mesaj la peers cunoscuți
pub struct GossipNode {
    pub peers: Vec<([u8; 4], u16)>,
    pub topic: String,
}

impl GossipNode {
    pub fn new(topic: &str) -> Self {
        Self {
            peers: Vec::new(),
            topic: topic.into(),
        }
    }

    pub fn add_peer(&mut self, ip: [u8; 4], port: u16) {
        self.peers.push((ip, port));
    }

    /// Broadcast mesaj la toți peers via TCP
    pub fn broadcast(&self, msg: &[u8]) {
        for &(ip, port) in &self.peers {
            let fd = sys::tcp_connect(ip, port);
            if fd != u64::MAX {
                // Trimitem topic + length + data
                let header = alloc::format!("GOSSIP {} {}\n", self.topic, msg.len());
                sys::tcp_send(fd, header.as_bytes());
                sys::tcp_send(fd, msg);
                sys::tcp_close(fd);
            }
        }
    }
}
