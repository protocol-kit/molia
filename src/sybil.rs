//! PoW, admission tokens, cost stamps, EWMA scoring, and token buckets.

use crate::crypto::{cost_stamp, leading_zero_bits, verify_ephemeral_pow};
use crate::types::{Key, NodeId};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub struct TokenBucket {
    tokens: f64,
    cap: f64,
    rate_per_s: f64,
    last: Instant,
}

impl TokenBucket {
    pub fn new(cap: f64, rate_per_s: f64) -> Self {
        Self {
            tokens: cap,
            cap,
            rate_per_s,
            last: Instant::now(),
        }
    }

    pub fn take(&mut self, n: f64) -> bool {
        let now = Instant::now();
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + dt * self.rate_per_s).min(self.cap);
        self.last = now;
        if self.tokens >= n {
            self.tokens -= n;
            true
        } else {
            false
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Score {
    pub ewma: f64,
    pub quarantine: u8,
}

impl Default for Score {
    fn default() -> Self {
        Self {
            ewma: 0.5,
            quarantine: 0,
        }
    }
}

pub struct Sybil {
    pub pow_nonce: [u8; 16],
    pub pow_bits: u8,
    pub op_bits: u8,
    ip_buckets: HashMap<IpAddr, TokenBucket>,
    prefix_buckets: HashMap<[u8; 3], TokenBucket>,
    peer_buckets: HashMap<NodeId, TokenBucket>,
    scores: HashMap<NodeId, Score>,
    tokens: HashMap<NodeId, (u64, Instant)>,
    token_secret: [u8; 32],
}

impl Sybil {
    pub fn new() -> Self {
        Self {
            pow_nonce: [0x42; 16],
            pow_bits: 0,
            op_bits: 0,
            ip_buckets: HashMap::new(),
            prefix_buckets: HashMap::new(),
            peer_buckets: HashMap::new(),
            scores: HashMap::new(),
            tokens: HashMap::new(),
            token_secret: *blake3::hash(b"molia-admission-dev").as_bytes(),
        }
    }

    pub fn allow_pre_handshake(&mut self, src: SocketAddr) -> bool {
        let ip = src.ip();
        let b = self
            .ip_buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(20.0, 10.0));
        if !b.take(1.0) {
            return false;
        }
        if let IpAddr::V4(v4) = ip {
            let o = v4.octets();
            let p = [o[0], o[1], o[2]];
            let pb = self
                .prefix_buckets
                .entry(p)
                .or_insert_with(|| TokenBucket::new(80.0, 40.0));
            return pb.take(1.0);
        }
        true
    }

    pub fn allow_peer(&mut self, id: NodeId, cost: f64) -> bool {
        let q = self.scores.get(&id).map(|s| s.quarantine).unwrap_or(0);
        let cap = if q > 0 { 4.0 } else { 40.0 };
        let b = self
            .peer_buckets
            .entry(id)
            .or_insert_with(|| TokenBucket::new(cap, cap / 2.0));
        b.take(cost)
    }

    pub fn check_pow(&self, ephemeral: &[u8; 32]) -> bool {
        verify_ephemeral_pow(ephemeral, &self.pow_nonce, self.pow_bits)
    }

    pub fn mint_token(&mut self, id: NodeId) -> [u8; 32] {
        let now = Instant::now();
        let raw = {
            let mut h = blake3::Hasher::new_keyed(&self.token_secret);
            h.update(&id.0);
            h.update(&now.elapsed().as_nanos().to_le_bytes());
            h.finalize()
        };
        let tok: [u8; 32] = raw.into();
        self.tokens.insert(id, (u64::from_le_bytes(tok[..8].try_into().unwrap()), now));
        tok
    }

    pub fn check_token(&self, id: NodeId, tok: &[u8]) -> bool {
        let Some((head, at)) = self.tokens.get(&id) else {
            return false;
        };
        if at.elapsed() > Duration::from_secs(600) {
            return false;
        }
        tok.len() >= 8 && u64::from_le_bytes(tok[..8].try_into().unwrap()) == *head
    }

    pub fn check_cost_stamp(&self, key: &Key, salt: &[u8], nonce: &[u8]) -> bool {
        if self.op_bits == 0 {
            return true;
        }
        leading_zero_bits(&cost_stamp(key, salt, nonce)) >= u32::from(self.op_bits)
    }

    pub fn reward(&mut self, id: NodeId) {
        let s = self.scores.entry(id).or_default();
        s.ewma = s.ewma * 0.8 + 0.2;
        if s.ewma > 0.7 {
            s.quarantine = 0;
        }
    }

    pub fn penalize(&mut self, id: NodeId) {
        let s = self.scores.entry(id).or_default();
        s.ewma *= 0.7;
        if s.ewma < 0.2 {
            s.quarantine = s.quarantine.saturating_add(1).min(3);
        }
    }

    pub fn alpha_cap(&self, id: NodeId) -> usize {
        match self.scores.get(&id).map(|s| s.quarantine).unwrap_or(0) {
            0 => 8,
            1 => 3,
            _ => 1,
        }
    }

    pub fn raise_difficulty(&mut self) {
        self.pow_bits = self.pow_bits.saturating_add(1).min(16);
    }
}

impl Default for Sybil {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn bucket_eventually_denies() {
        let mut s = Sybil::new();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 1));
        let mut ok = 0;
        for _ in 0..50 {
            if s.allow_pre_handshake(addr) {
                ok += 1;
            }
        }
        assert!(ok < 50);
    }
}
