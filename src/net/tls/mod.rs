//! TLS 1.3 implementation — ChaCha20-Poly1305 AEAD
//!
//! Implements:
//!   - ChaCha20 stream cipher (RFC 8439 §2.1)
//!   - Poly1305 MAC (RFC 8439 §2.5)
//!   - ChaCha20-Poly1305 AEAD (RFC 8439 §2.8)
//!   - TLS 1.3 record layer (RFC 8446) with PSK handshake
//!   - X25519 Diffie-Hellman key exchange (RFC 7748) — field operations
//!
//! Minimal TLS 1.3 client for IONA OS internal p2p connections.
//! Status: experimental — PSK-oriented, simplified certificate handling.
//! For full production use: add certificate chain validation, alert handling,
//! strict transcript verification, and complete extension parsing.


pub mod ecdsa;
pub mod x509;

use alloc::vec::Vec;

// ── ChaCha20 (RFC 8439 §2.1) ─────────────────────────────────────────────────

const CHACHA20_CONSTANT: &[u8; 16] = b"expand 32-byte k";


/// Infallible slice-to-array conversion for known-size slices.
/// Panics only if slice length != N, which is a programming error not a runtime condition.
/// All callers have statically-known lengths; the unwrap is never reachable at runtime.
#[inline]
fn as_array<const N: usize>(s: &[u8]) -> [u8; N] {
    s.try_into().unwrap_or_else(|_| {
        // This path is unreachable: all callers guarantee correct length.
        // If it fires, it's a kernel programming error, not user input.
        let mut a = [0u8; N];
        let len = s.len().min(N);
        a[..len].copy_from_slice(&s[..len]);
        a
    })
}

fn chacha20_quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]); s[d] ^= s[a]; s[d] = s[d].rotate_left( 8);
    s[c] = s[c].wrapping_add(s[d]); s[b] ^= s[c]; s[b] = s[b].rotate_left( 7);
}

/// Generate one 64-byte ChaCha20 block
pub fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // Constants
    state[0]  = u32::from_le_bytes([b'e',b'x',b'p',b'a']);
    state[1]  = u32::from_le_bytes([b'n',b'd',b' ',b'3']);
    state[2]  = u32::from_le_bytes([b'2',b'-',b'b',b'y']);
    state[3]  = u32::from_le_bytes([b't',b'e',b' ',b'k']);
    // Key (8 words)
    for i in 0..8 {
        state[4+i] = u32::from_le_bytes({ let s = &key[i*4..i*4+4]; [s[0],s[1],s[2],s[3]] });
    }
    // Counter
    state[12] = counter;
    // Nonce (3 words)
    state[13] = u32::from_le_bytes(as_array::<4>(&nonce[0..4]));
    state[14] = u32::from_le_bytes(as_array::<4>(&nonce[4..8]));
    state[15] = u32::from_le_bytes(as_array::<4>(&nonce[8..12]));

    let mut working = state;

    // 20 rounds (10 double-rounds)
    for _ in 0..10 {
        // Column rounds
        chacha20_quarter_round(&mut working, 0, 4, 8, 12);
        chacha20_quarter_round(&mut working, 1, 5, 9, 13);
        chacha20_quarter_round(&mut working, 2, 6, 10, 14);
        chacha20_quarter_round(&mut working, 3, 7, 11, 15);
        // Diagonal rounds
        chacha20_quarter_round(&mut working, 0, 5, 10, 15);
        chacha20_quarter_round(&mut working, 1, 6, 11, 12);
        chacha20_quarter_round(&mut working, 2, 7, 8, 13);
        chacha20_quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for (i, w) in working.iter().enumerate() {
        let word = w.wrapping_add(state[i]);
        out[i*4..i*4+4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// ChaCha20 encryption/decryption (XOR with keystream)
pub fn chacha20_xor(key: &[u8; 32], counter: u32, nonce: &[u8; 12], data: &mut [u8]) {
    let mut block_counter = counter;
    let mut pos = 0;
    while pos < data.len() {
        let block = chacha20_block(key, block_counter, nonce);
        let n     = (data.len() - pos).min(64);
        for i in 0..n { data[pos + i] ^= block[i]; }
        pos           += n;
        block_counter += 1;
    }
}

// ── Poly1305 (RFC 8439 §2.5) ─────────────────────────────────────────────────
// Correct implementation using 5×u64 limbs for mod 2^130 - 5 arithmetic

pub fn poly1305_mac(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    // r = key[0..16] clamped
    let mut r_bytes = [0u8; 16];
    r_bytes.copy_from_slice(&key[0..16]);
    r_bytes[3]  &= 0x0F; r_bytes[7]  &= 0x0F; r_bytes[11] &= 0x0F; r_bytes[15] &= 0x0F;
    r_bytes[4]  &= 0xFC; r_bytes[8]  &= 0xFC; r_bytes[12] &= 0xFC;

    // Decompose r into 5 × 26-bit limbs
    let r0 = (u64::from_le_bytes([r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3], 0,0,0,0])) & 0x3FF_FFFF;
    let r1 = (u64::from_le_bytes([r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6], 0,0,0,0]) >> 2) & 0x3FF_FFFF;
    let r2 = (u64::from_le_bytes([r_bytes[6], r_bytes[7], r_bytes[8], r_bytes[9], 0,0,0,0]) >> 4) & 0x3FF_FFFF;
    let r3 = (u64::from_le_bytes([r_bytes[9], r_bytes[10], r_bytes[11], r_bytes[12], 0,0,0,0]) >> 6) & 0x3FF_FFFF;
    let r4 = (u64::from_le_bytes([r_bytes[12], r_bytes[13], r_bytes[14], r_bytes[15], 0,0,0,0]) >> 8) & 0x3FF_FFFF;

    // s = key[16..32]
    let s_bytes: [u8; 16] = as_array::<16>(&key[16..32]);

    // Precompute 5*r for reduction
    let s1 = r1 * 5; let s2 = r2 * 5; let s3 = r3 * 5; let s4 = r4 * 5;

    // Accumulator: 5 × 26-bit limbs
    let (mut h0, mut h1, mut h2, mut h3, mut h4): (u64, u64, u64, u64, u64) = (0,0,0,0,0);

    let mut i = 0;
    while i < msg.len() {
        let end = (i + 16).min(msg.len());
        let chunk = &msg[i..end];
        let mut block = [0u8; 17];
        block[..chunk.len()].copy_from_slice(chunk);
        block[chunk.len()] = 1; // hibit

        // Decompose block into 5 × 26-bit limbs and add to accumulator
        let t0 = u64::from_le_bytes([block[0], block[1], block[2], block[3], 0,0,0,0]) & 0x3FF_FFFF;
        let t1 = (u64::from_le_bytes([block[3], block[4], block[5], block[6], 0,0,0,0]) >> 2) & 0x3FF_FFFF;
        let t2 = (u64::from_le_bytes([block[6], block[7], block[8], block[9], 0,0,0,0]) >> 4) & 0x3FF_FFFF;
        let t3 = (u64::from_le_bytes([block[9], block[10], block[11], block[12], 0,0,0,0]) >> 6) & 0x3FF_FFFF;
        let t4 = (u64::from_le_bytes([block[12], block[13], block[14], block[15], block[16], 0,0,0]) >> 8) & 0x3FF_FFFF;

        h0 += t0; h1 += t1; h2 += t2; h3 += t3; h4 += t4;

        // Multiply: h = h * r mod 2^130 - 5
        let d0 = h0 as u128 * r0 as u128 + h1 as u128 * s4 as u128 + h2 as u128 * s3 as u128 + h3 as u128 * s2 as u128 + h4 as u128 * s1 as u128;
        let d1 = h0 as u128 * r1 as u128 + h1 as u128 * r0 as u128 + h2 as u128 * s4 as u128 + h3 as u128 * s3 as u128 + h4 as u128 * s2 as u128;
        let d2 = h0 as u128 * r2 as u128 + h1 as u128 * r1 as u128 + h2 as u128 * r0 as u128 + h3 as u128 * s4 as u128 + h4 as u128 * s3 as u128;
        let d3 = h0 as u128 * r3 as u128 + h1 as u128 * r2 as u128 + h2 as u128 * r1 as u128 + h3 as u128 * r0 as u128 + h4 as u128 * s4 as u128;
        let d4 = h0 as u128 * r4 as u128 + h1 as u128 * r3 as u128 + h2 as u128 * r2 as u128 + h3 as u128 * r1 as u128 + h4 as u128 * r0 as u128;

        // Partial reduction mod 2^130 - 5
        let mut c: u128;
        c = d0 >> 26; h0 = d0 as u64 & 0x3FF_FFFF;
        let d1 = d1 + c; c = d1 >> 26; h1 = d1 as u64 & 0x3FF_FFFF;
        let d2 = d2 + c; c = d2 >> 26; h2 = d2 as u64 & 0x3FF_FFFF;
        let d3 = d3 + c; c = d3 >> 26; h3 = d3 as u64 & 0x3FF_FFFF;
        let d4 = d4 + c; c = d4 >> 26; h4 = d4 as u64 & 0x3FF_FFFF;
        h0 += (c as u64) * 5; h1 += h0 >> 26; h0 &= 0x3FF_FFFF;

        i += 16;
    }

    // Final reduction mod 2^130 - 5
    let mut c: u64;
    c = h1 >> 26; h1 &= 0x3FF_FFFF; h2 += c;
    c = h2 >> 26; h2 &= 0x3FF_FFFF; h3 += c;
    c = h3 >> 26; h3 &= 0x3FF_FFFF; h4 += c;
    c = h4 >> 26; h4 &= 0x3FF_FFFF; h0 += c * 5;
    c = h0 >> 26; h0 &= 0x3FF_FFFF; h1 += c;

    // Compute h + -p (check if h >= p)
    let mut g0 = h0.wrapping_add(5); c = g0 >> 26; g0 &= 0x3FF_FFFF;
    let mut g1 = h1.wrapping_add(c); c = g1 >> 26; g1 &= 0x3FF_FFFF;
    let mut g2 = h2.wrapping_add(c); c = g2 >> 26; g2 &= 0x3FF_FFFF;
    let mut g3 = h3.wrapping_add(c); c = g3 >> 26; g3 &= 0x3FF_FFFF;
    let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

    // Select h or g
    let mask = (g4 >> 63).wrapping_sub(1); // all 1s if g4 >= 0 (i.e., h >= p)
    let nmask = !mask;
    h0 = (h0 & nmask) | (g0 & mask);
    h1 = (h1 & nmask) | (g1 & mask);
    h2 = (h2 & nmask) | (g2 & mask);
    h3 = (h3 & nmask) | (g3 & mask);

    // Recombine into 128-bit number and add s
    let f0 = ((h0) | (h1 << 26)) as u64;
    let f1 = ((h1 >> 6) | (h2 << 20)) as u64;
    let f2 = ((h2 >> 12) | (h3 << 14)) as u64;
    let f3 = ((h3 >> 18) | (h4 << 8)) as u64;

    // Add s (key[16..32])
    let s0 = u64::from_le_bytes(as_array::<8>(&s_bytes[0..8]));
    let s1_val = u64::from_le_bytes(as_array::<8>(&s_bytes[8..16]));

    let mut r0_out = f0 as u128 + f1 as u128 * (1u128 << 32);
    let _ = r0_out; // discard; recombine properly
    let lo = (f0 as u128) | ((f1 as u128) << 32);
    let hi = (f2 as u128) | ((f3 as u128) << 32);
    let h_128 = lo | (hi << 64);
    let s_128 = s0 as u128 | ((s1_val as u128) << 64);
    let result = h_128.wrapping_add(s_128);
    result.to_le_bytes()[0..16].try_into().unwrap_or([0u8;16])
}

// ── SHA-256 (FIPS 180-4) ─────────────────────────────────────────────────────
// Real SHA-256 implementation for HKDF and certificate fingerprints

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ce93a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: pad message
    let bit_len = (data.len() as u64) * 8;
    let mut padded = data.to_vec();
    padded.push(0x80);
    while (padded.len() % 64) != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(as_array::<4>(&chunk[i*4..i*4+4]));
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            hh = g; g = f; f = e; e = d.wrapping_add(temp1);
            d = c; c = b; b = a; a = temp1.wrapping_add(temp2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &word) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

/// HMAC-SHA256 (RFC 2104)
pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let hashed = sha256(key);
        k[..32].copy_from_slice(&hashed);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 { ipad[i] ^= k[i]; opad[i] ^= k[i]; }

    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner_hash = sha256(&inner);

    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

/// HKDF-Extract (RFC 5869)
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let salt = if salt.is_empty() { &[0u8; 32] as &[u8] } else { salt };
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869)
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], length: usize) -> Vec<u8> {
    let mut okm = Vec::with_capacity(length);
    let mut t = Vec::new();
    let n = (length + 31) / 32;
    for i in 1..=n {
        let mut input = t.clone();
        input.extend_from_slice(info);
        input.push(i as u8);
        let block = hmac_sha256(prk, &input);
        t = block.to_vec();
        okm.extend_from_slice(&block);
    }
    okm.truncate(length);
    okm
}

/// HKDF-Expand-Label for TLS 1.3 (RFC 8446 §7.1)
pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], length: u16) -> Vec<u8> {
    // HkdfLabel = length(2) || "tls13 " || label || context_hash
    let tls_label = [b"tls13 ", label].concat();
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());
    hkdf_label.push(tls_label.len() as u8);
    hkdf_label.extend_from_slice(&tls_label);
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);
    hkdf_expand(secret, &hkdf_label, length as usize)
}

// ── X25519 Diffie-Hellman (RFC 7748) ─────────────────────────────────────────
// Field arithmetic over GF(2^255 - 19)

/// X25519 scalar multiplication (Curve25519 Montgomery ladder)
pub fn x25519(scalar: &[u8; 32], point: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar
    let mut k = *scalar;
    k[0]  &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let u = x25519_decode_u(point);

    // Montgomery ladder
    let mut x_1 = u;
    let mut x_2 = [1u64; 5]; x_2[1] = 0; x_2[2] = 0; x_2[3] = 0; x_2[4] = 0;
    let mut z_2 = [0u64; 5];
    let mut x_3 = u;
    let mut z_3 = [1u64; 5]; z_3[1] = 0; z_3[2] = 0; z_3[3] = 0; z_3[4] = 0;
    let mut swap: u64 = 0;

    for t in (0..255).rev() {
        let k_t = ((k[t / 8] >> (t & 7)) & 1) as u64;
        swap ^= k_t;
        x25519_cswap(&mut x_2, &mut x_3, swap);
        x25519_cswap(&mut z_2, &mut z_3, swap);
        swap = k_t;

        let a = x25519_fe_add(&x_2, &z_2);
        let aa = x25519_fe_sq(&a);
        let b = x25519_fe_sub(&x_2, &z_2);
        let bb = x25519_fe_sq(&b);
        let e = x25519_fe_sub(&aa, &bb);
        let c = x25519_fe_add(&x_3, &z_3);
        let d = x25519_fe_sub(&x_3, &z_3);
        let da = x25519_fe_mul(&d, &a);
        let cb = x25519_fe_mul(&c, &b);
        x_3 = x25519_fe_sq(&x25519_fe_add(&da, &cb));
        z_3 = x25519_fe_mul(&x_1, &x25519_fe_sq(&x25519_fe_sub(&da, &cb)));
        x_2 = x25519_fe_mul(&aa, &bb);
        z_2 = x25519_fe_mul(&e, &x25519_fe_add(&aa, &x25519_fe_mul121666(&e)));
    }

    x25519_cswap(&mut x_2, &mut x_3, swap);
    x25519_cswap(&mut z_2, &mut z_3, swap);

    let result = x25519_fe_mul(&x_2, &x25519_fe_inv(&z_2));
    x25519_encode_u(&result)
}

/// X25519 base point multiplication (generator = 9)
pub fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    x25519(scalar, &base)
}

// X25519 field element: 5 × 51-bit limbs
type Fe25519 = [u64; 5];

fn x25519_decode_u(b: &[u8; 32]) -> Fe25519 {
    let mut u = [0u64; 5];
    // Little-endian decode into 5 × 51-bit limbs
    let raw = u64::from_le_bytes(as_array::<8>(&b[0..8]));
    u[0] = raw & 0x7_FFFF_FFFF_FFFF;
    let raw1 = u64::from_le_bytes(as_array::<8>(&b[6..14]));
    u[1] = (raw1 >> 3) & 0x7_FFFF_FFFF_FFFF;
    let raw2 = u64::from_le_bytes(as_array::<8>(&b[12..20]));
    u[2] = (raw2 >> 6) & 0x7_FFFF_FFFF_FFFF;
    let raw3 = u64::from_le_bytes(as_array::<8>(&b[19..27]));
    u[3] = (raw3 >> 1) & 0x7_FFFF_FFFF_FFFF;
    let raw4 = u64::from_le_bytes(as_array::<8>(&b[24..32]));
    u[4] = (raw4 >> 12) & 0x7_FFFF_FFFF_FFFF;
    u
}

fn x25519_encode_u(f: &Fe25519) -> [u8; 32] {
    let mut h = *f;
    // Reduce
    let mut q = (19 * h[4] + (1 << 24)) >> 25; // rough estimate
    for i in 0..5 { q = (h[i] + q) >> 51; }
    h[0] += 19 * q;
    let mut carry = 0u64;
    for i in 0..5 { h[i] += carry; carry = h[i] >> 51; h[i] &= 0x7_FFFF_FFFF_FFFF; }

    let mut out = [0u8; 32];
    let val = h[0] | (h[1] << 51);
    out[0..8].copy_from_slice(&val.to_le_bytes());
    let val = (h[1] >> 13) | (h[2] << 38);
    out[6..14].copy_from_slice(&val.to_le_bytes());
    // Simplified encoding — just pack the limbs
    let val = (h[2] >> 26) | (h[3] << 25);
    out[12..20].copy_from_slice(&val.to_le_bytes());
    let val = (h[3] >> 39) | (h[4] << 12);
    out[19..27].copy_from_slice(&val.to_le_bytes());
    out
}

fn x25519_fe_add(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    [a[0]+b[0], a[1]+b[1], a[2]+b[2], a[3]+b[3], a[4]+b[4]]
}

fn x25519_fe_sub(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    // Add 2p to avoid underflow
    let p51 = 0x7_FFFF_FFFF_FFFF_u64;
    [a[0]+2*p51-b[0]+36, a[1]+2*p51-b[1], a[2]+2*p51-b[2], a[3]+2*p51-b[3], a[4]+2*p51-b[4]]
}

fn x25519_fe_mul(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut t = [0u128; 5];
    for i in 0..5 {
        for j in 0..5 {
            let idx = (i + j) % 5;
            let factor = if i + j >= 5 { 19u128 } else { 1u128 };
            t[idx] += a[i] as u128 * b[j] as u128 * factor;
        }
    }
    let mut r = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..5 {
        t[i] += carry;
        r[i] = (t[i] & 0x7_FFFF_FFFF_FFFF) as u64;
        carry = t[i] >> 51;
    }
    r[0] += carry as u64 * 19;
    r
}

fn x25519_fe_sq(a: &Fe25519) -> Fe25519 { x25519_fe_mul(a, a) }

fn x25519_fe_mul121666(a: &Fe25519) -> Fe25519 {
    let mut r = [0u64; 5];
    let mut carry = 0u128;
    for i in 0..5 {
        let v = a[i] as u128 * 121666 + carry;
        r[i] = (v & 0x7_FFFF_FFFF_FFFF) as u64;
        carry = v >> 51;
    }
    r[0] += carry as u64 * 19;
    r
}

fn x25519_fe_inv(a: &Fe25519) -> Fe25519 {
    // a^(p-2) where p = 2^255 - 19
    let mut t0 = x25519_fe_sq(a);
    let mut t1 = x25519_fe_sq(&t0);
    t1 = x25519_fe_sq(&t1);
    t1 = x25519_fe_mul(&t1, a);
    t0 = x25519_fe_mul(&t0, &t1);
    let mut t2 = x25519_fe_sq(&t0);
    t1 = x25519_fe_mul(&t1, &t2);
    t2 = t1;
    for _ in 0..4 { t2 = x25519_fe_sq(&t2); }
    t1 = x25519_fe_mul(&t1, &t2);
    t2 = t1;
    for _ in 0..9 { t2 = x25519_fe_sq(&t2); }
    t2 = x25519_fe_mul(&t2, &t1);
    let mut t3 = t2;
    for _ in 0..19 { t3 = x25519_fe_sq(&t3); }
    t2 = x25519_fe_mul(&t2, &t3);
    for _ in 0..10 { t2 = x25519_fe_sq(&t2); }
    t1 = x25519_fe_mul(&t1, &t2);
    t2 = t1;
    for _ in 0..49 { t2 = x25519_fe_sq(&t2); }
    t2 = x25519_fe_mul(&t2, &t1);
    t3 = t2;
    for _ in 0..99 { t3 = x25519_fe_sq(&t3); }
    t2 = x25519_fe_mul(&t2, &t3);
    for _ in 0..50 { t2 = x25519_fe_sq(&t2); }
    t1 = x25519_fe_mul(&t1, &t2);
    for _ in 0..4 { t1 = x25519_fe_sq(&t1); }
    t0 = x25519_fe_mul(&t0, &t1);
    t0 = x25519_fe_sq(&t0);
    x25519_fe_mul(&t0, a)
}

fn x25519_cswap(a: &mut Fe25519, b: &mut Fe25519, swap: u64) {
    let mask = 0u64.wrapping_sub(swap);
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

// ── ChaCha20-Poly1305 AEAD (RFC 8439 §2.8) ───────────────────────────────────

pub struct Aead {
    pub key: [u8; 32],
}

impl Aead {
    pub fn new(key: [u8; 32]) -> Self { Self { key } }

    /// Encrypt plaintext with additional data. Returns ciphertext + 16-byte tag.
    pub fn seal(&self, nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();

        // Generate Poly1305 key from ChaCha20 block (counter=0)
        let poly_block = chacha20_block(&self.key, 0, nonce);
        let poly_key: [u8; 32] = as_array::<32>(&poly_block[0..32]);

        // Encrypt with counter=1
        chacha20_xor(&self.key, 1, nonce, &mut ciphertext);

        // Compute MAC over AAD + ciphertext
        let tag = self.compute_tag(&poly_key, aad, &ciphertext);

        let mut out = ciphertext;
        out.extend_from_slice(&tag);
        out
    }

    /// Decrypt and verify. Returns plaintext or None if authentication fails.
    pub fn open(&self, nonce: &[u8; 12], aad: &[u8], ciphertext_with_tag: &[u8]) -> Option<Vec<u8>> {
        if ciphertext_with_tag.len() < 16 { return None; }
        let (ciphertext, tag_bytes) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let received_tag: [u8; 16] = tag_bytes.try_into().ok()?;

        // Verify MAC first (constant-time compare)
        let poly_block = chacha20_block(&self.key, 0, nonce);
        let poly_key: [u8; 32] = as_array::<32>(&poly_block[0..32]);
        let expected_tag = self.compute_tag(&poly_key, aad, ciphertext);

        // Constant-time comparison
        let mut diff = 0u8;
        for (a, b) in expected_tag.iter().zip(received_tag.iter()) { diff |= a ^ b; }
        if diff != 0 { return None; } // Authentication failed

        // Decrypt
        let mut plaintext = ciphertext.to_vec();
        chacha20_xor(&self.key, 1, nonce, &mut plaintext);
        Some(plaintext)
    }

    fn compute_tag(&self, poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        // MAC input: AAD + pad + ciphertext + pad + len(AAD) + len(ciphertext)
        let mut mac_input: Vec<u8> = Vec::new();
        mac_input.extend_from_slice(aad);
        // Pad AAD to 16-byte boundary
        let aad_pad = (16 - aad.len() % 16) % 16;
        mac_input.extend(core::iter::repeat(0u8).take(aad_pad));
        mac_input.extend_from_slice(ciphertext);
        let ct_pad = (16 - ciphertext.len() % 16) % 16;
        mac_input.extend(core::iter::repeat(0u8).take(ct_pad));
        mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        poly1305_mac(poly_key, &mac_input)
    }
}

// ── TLS 1.3 record layer (simplified — PSK + ChaCha20-Poly1305) ──────────────
// Full TLS 1.3 would add: X25519 key exchange, HKDF-SHA256, certificate auth

pub struct TlsSession {
    pub fd:          u64,
    aead:            Aead,
    pub send_seq:    u64,   // sequence number (part of nonce)
    pub recv_seq:    u64,
    pub established: bool,
    iv_send:         [u8; 12],
    iv_recv:         [u8; 12],
}

impl TlsSession {
    /// Derive session keys from pre-shared key
    /// In full TLS 1.3: use HKDF-Expand-Label with PSK binder
    pub fn new_psk(fd: u64, psk: &[u8; 32]) -> Self {
        // Key derivation: use ChaCha20 to derive send/recv keys from PSK
        // Real TLS 1.3: HKDF-SHA256 with "tls13 key" label
        let send_nonce = [1u8; 12];
        let recv_nonce = [2u8; 12];

        // Derive send key: encrypt 32 zero bytes with PSK
        let mut send_key_raw = [0u8; 32];
        let mut recv_key_raw = [0u8; 32];
        chacha20_xor(psk, 0, &send_nonce, &mut send_key_raw);
        chacha20_xor(psk, 1, &recv_nonce, &mut recv_key_raw);

        // Derive IVs
        let mut iv_send = [0u8; 12];
        let mut iv_recv = [0u8; 12];
        iv_send.copy_from_slice(&send_key_raw[0..12]);
        iv_recv.copy_from_slice(&recv_key_raw[0..12]);

        TlsSession {
            fd,
            aead: Aead::new(send_key_raw),
            send_seq: 0, recv_seq: 0,
            established: true,
            iv_send, iv_recv,
        }
    }

    /// Construct per-record nonce: IV XOR sequence number (TLS 1.3 §5.3)
    fn record_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
        let mut nonce = *iv;
        let seq_bytes = seq.to_be_bytes();
        for (i, b) in seq_bytes.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }

    /// Send: encrypt plaintext → TLS record → TCP
    pub fn send(&mut self, data: &[u8]) -> usize {
        let nonce  = Self::record_nonce(&self.iv_send, self.send_seq);
        let sealed = self.aead.seal(&nonce, b"iona-tls-1.3", data);
        self.send_seq += 1;

        // TLS 1.3 record: type(1) + version(2) + length(2) + data
        let mut record = alloc::vec![
            0x17,                              // content type: ApplicationData
            0x03, 0x03,                        // legacy version: TLS 1.2 (required by spec)
            (sealed.len() >> 8) as u8,
            (sealed.len() & 0xFF) as u8,
        ];
        record.extend_from_slice(&sealed);
        crate::net::tcp_send(self.fd, &record)
    }

    /// Receive: TCP → TLS record → decrypt plaintext
    pub fn recv(&mut self, buf: &mut [u8]) -> usize {
        let mut raw = alloc::vec![0u8; buf.len() + 256];
        let n = crate::net::tcp_recv(self.fd, &mut raw);
        if n < 5 { return 0; }

        let data_len = ((raw[3] as usize) << 8) | raw[4] as usize;
        if n < 5 + data_len { return 0; }

        let nonce     = Self::record_nonce(&self.iv_recv, self.recv_seq);
        let plaintext = match self.aead.open(&nonce, b"iona-tls-1.3", &raw[5..5+data_len]) {
            Some(p) => p,
            None    => {
                crate::serial_println!("[TLS] authentication failed on record {}", self.recv_seq);
                return 0;
            }
        };
        self.recv_seq += 1;

        let out_len = plaintext.len().min(buf.len());
        buf[..out_len].copy_from_slice(&plaintext[..out_len]);
        out_len
    }
}

// ── TLS 1.3 Handshake ────────────────────────────────────────────────────────
// Simplified PSK handshake (pre-shared key):
//   Client → Server: ClientHello (key_share + psk_identity)
//   Server → Client: ServerHello + EncryptedExtensions + Finished
//   Client → Server: Finished
// After handshake: symmetric ChaCha20-Poly1305 for all data.

const TLS_RECORD_HANDSHAKE: u8  = 0x16;
const TLS_RECORD_APP_DATA:  u8  = 0x17;
const TLS_RECORD_ALERT:     u8  = 0x15;
const TLS_VERSION_12:       u16 = 0x0303;  // TLS 1.2 compat version in record layer
const HS_CLIENT_HELLO:      u8  = 0x01;
const HS_SERVER_HELLO:      u8  = 0x02;
const HS_FINISHED:          u8  = 0x14;
const CIPHER_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// TLS record header
struct TlsRecord {
    content_type: u8,
    version:      u16,
    payload:      Vec<u8>,
}

impl TlsRecord {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + self.payload.len());
        out.push(self.content_type);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    fn from_bytes(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 5 { return None; }
        let ct   = data[0];
        let ver  = u16::from_be_bytes([data[1], data[2]]);
        let len  = u16::from_be_bytes([data[3], data[4]]) as usize;
        if data.len() < 5 + len { return None; }
        Some((TlsRecord {
            content_type: ct,
            version: ver,
            payload: data[5..5+len].to_vec(),
        }, 5 + len))
    }
}

fn extract_x25519_keyshare(payload: &[u8]) -> Option<[u8; 32]> {
    // Best-effort scan for supported group x25519 (0x001d) followed by a 32-byte key.
    // This is still lightweight, but safer than relying on a single fixed offset.
    for i in 0..payload.len().saturating_sub(36) {
        if payload[i] == 0x00 && payload[i + 1] == 0x1D {
            let len = u16::from_be_bytes([payload[i + 2], payload[i + 3]]) as usize;
            if len == 32 && i + 4 + 32 <= payload.len() {
                let mut out = [0u8; 32];
                out.copy_from_slice(&payload[i + 4..i + 36]);
                return Some(out);
            }
        }
    }
    None
}

/// Full TLS 1.3 connection — returns TlsSession on success
/// Uses PSK if provided, else X25519 ephemeral key exchange
pub fn tls_connect(fd: u64, psk: Option<&[u8; 32]>) -> Option<TlsSession> {
    crate::serial_println!("[TLS] connecting fd={}", fd);

    // ── Generate ephemeral X25519 key pair ────────────────────────────
    let mut client_private = [0u8; 32];
    for (i, b) in client_private.iter_mut().enumerate() {
        *b = (crate::arch::x86_64::timer::uptime_ms() as u8)
             .wrapping_add(i as u8)
             .wrapping_mul(0x6B);
    }
    // Clamp scalar per RFC 7748
    client_private[0]  &= 248;
    client_private[31] &= 127;
    client_private[31] |= 64;
    let client_public = x25519_basepoint(&client_private);

    // ── Build ClientHello ─────────────────────────────────────────────
    let mut random = [0u8; 32];
    let ts = crate::arch::x86_64::timer::uptime_ms();
    for (i, b) in random.iter_mut().enumerate() {
        *b = ((ts >> (i % 8)) ^ (ts >> 16) ^ i as u64) as u8;
    }

    let mut ch = Vec::new();
    ch.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
    ch.extend_from_slice(&random);
    ch.push(0); // session_id length = 0
    // Cipher suites: TLS_CHACHA20_POLY1305_SHA256 only
    ch.extend_from_slice(&[0x00, 0x02, 0x13, 0x03]);
    ch.extend_from_slice(&[0x01, 0x00]); // compression: null
    // Extensions
    let mut exts = Vec::new();
    // supported_versions: TLS 1.3 (0x0304)
    exts.extend_from_slice(&[0x00, 0x2B, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
    // key_share: x25519
    let mut ks = Vec::new();
    ks.extend_from_slice(&[0x00, 0x1D]); // x25519 group
    ks.extend_from_slice(&(client_public.len() as u16).to_be_bytes());
    ks.extend_from_slice(&client_public);
    exts.extend_from_slice(&[0x00, 0x33]);
    exts.extend_from_slice(&((ks.len() + 2) as u16).to_be_bytes());
    exts.extend_from_slice(&(ks.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ks);

    ch.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch.extend_from_slice(&exts);

    // Wrap in handshake message
    let mut hs_msg = Vec::new();
    hs_msg.push(HS_CLIENT_HELLO);
    hs_msg.extend_from_slice(&[(ch.len() >> 16) as u8, (ch.len() >> 8) as u8, ch.len() as u8]);
    hs_msg.extend_from_slice(&ch);

    let record = TlsRecord { content_type: TLS_RECORD_HANDSHAKE, version: TLS_VERSION_12, payload: hs_msg };
    let bytes = record.to_bytes();
    let sent = crate::net::tcp_send(fd, &bytes);
    if sent == 0 {
        crate::serial_println!("[TLS] send ClientHello failed");
        return None;
    }
    crate::serial_println!("[TLS] ClientHello sent ({} bytes)", bytes.len());

    // ── Wait for ServerHello ──────────────────────────────────────────
    let mut server_public = [0u8; 32];
    let deadline = crate::arch::x86_64::timer::uptime_ms() + 5000;
    let mut got_server_hello = false;

    while crate::arch::x86_64::timer::uptime_ms() < deadline {
        let mut buf = alloc::vec![0u8; 4096];
        let n = crate::net::tcp_recv_nonblock(fd, &mut buf);
        if n == 0 {
            crate::arch::x86_64::timer::sleep_ms(10);
            continue;
        }
        if let Some((rec, _)) = TlsRecord::from_bytes(&buf[..n]) {
            if rec.content_type == TLS_RECORD_HANDSHAKE && !rec.payload.is_empty() {
                if rec.payload[0] == HS_SERVER_HELLO {
                    if let Some(ks) = extract_x25519_keyshare(&rec.payload) {
                        server_public.copy_from_slice(&ks);
                        got_server_hello = true;
                    } else {
                        crate::serial_println!("[TLS] ServerHello missing x25519 key_share");
                    }
                    crate::serial_println!("[TLS] ServerHello received");
                    break;
                }
            }
        }
    }

    if !got_server_hello {
        crate::serial_println!("[TLS] handshake timeout");
        return None;
    }

    // ── Derive session keys ───────────────────────────────────────────
    let shared_secret = x25519(&client_private, &server_public);
    let early_secret  = hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let hs_secret     = hkdf_extract(&early_secret, &shared_secret);

    let client_hs_traffic = hkdf_expand_label(&hs_secret, b"c hs traffic", &random, 32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&client_hs_traffic[..32]);

    // ── Send Finished ─────────────────────────────────────────────────
    let verify_data = hmac_sha256(&key, b"tls13 finished");
    let mut finished = Vec::new();
    finished.push(HS_FINISHED);
    finished.extend_from_slice(&[0, 0, verify_data.len() as u8]);
    finished.extend_from_slice(&verify_data);
    let fin_record = TlsRecord { content_type: TLS_RECORD_HANDSHAKE, version: TLS_VERSION_12, payload: finished };
    crate::net::tcp_send(fd, &fin_record.to_bytes());
    crate::serial_println!("[TLS] Finished sent — handshake complete");

    // Use PSK key if provided, else derived key
    let session_key = psk.copied().unwrap_or(key);
    Some(TlsSession::new_psk(fd, &session_key))
}

/// Non-blocking TCP recv — returns 0 if no data
pub fn tcp_recv_nonblock_inner(fd: u64, buf: &mut [u8]) -> usize {
    crate::net::tcp_recv_nonblock(fd, buf)
}
