//! k-bucket routing table: LRU, PNS, replacement cache.

use crate::types::{bucket_index, xor_distance, Key, NodeId, PeerInfo, K_DEFAULT, K_MAX};
use arrayvec::ArrayVec;
use std::net::IpAddr;
use std::time::Instant;

#[derive(Clone, Debug)]
pub struct PeerEntry {
    pub info: PeerInfo,
    pub last_seen: Instant,
    pub fail_count: u32,
    pub srtt_us: u32,
}

pub struct RoutingTable {
    self_id: NodeId,
    k: usize,
    buckets: Vec<ArrayVec<PeerEntry, K_MAX>>,
    replacement: Vec<ArrayVec<PeerEntry, 8>>,
}

impl RoutingTable {
    pub fn new(self_id: NodeId) -> Self {
        Self {
            self_id,
            k: K_DEFAULT,
            buckets: (0..256).map(|_| ArrayVec::new()).collect(),
            replacement: (0..256).map(|_| ArrayVec::new()).collect(),
        }
    }

    pub fn self_id(&self) -> NodeId {
        self.self_id
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|b| b.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert or LRU-touch. Returns the LRU entry if the bucket is full (caller should PING).
    pub fn insert(&mut self, info: PeerInfo) -> Option<PeerEntry> {
        if info.id == self.self_id {
            return None;
        }
        if !self.prefix_ok(&info) {
            return None;
        }
        let i = bucket_index(&self.self_id, &info.id);
        if let Some(pos) = self.buckets[i].iter().position(|e| e.id() == info.id) {
            self.buckets[i][pos].info = info;
            self.buckets[i][pos].last_seen = Instant::now();
            self.buckets[i][pos].fail_count = 0;
            let e = self.buckets[i].remove(pos);
            self.buckets[i].push(e);
            return None;
        }
        if self.buckets[i].len() < self.k.min(K_MAX) {
            self.buckets[i].push(PeerEntry {
                info,
                last_seen: Instant::now(),
                fail_count: 0,
                srtt_us: 200_000,
            });
            return None;
        }
        let lru = self.buckets[i][0].clone();
        if self.replacement[i].len() < 8 {
            self.replacement[i].push(PeerEntry {
                info,
                last_seen: Instant::now(),
                fail_count: 0,
                srtt_us: 200_000,
            });
        }
        Some(lru)
    }

    pub fn evict_and_replace(&mut self, dead: NodeId) {
        let i = bucket_index(&self.self_id, &dead);
        self.buckets[i].retain(|e| e.id() != dead);
        if let Some(e) = self.replacement[i].pop() {
            let _ = self.buckets[i].try_push(e);
        }
    }

    pub fn touch_ok(&mut self, id: NodeId, rtt_us: u32) {
        let i = bucket_index(&self.self_id, &id);
        if let Some(e) = self.buckets[i].iter_mut().find(|e| e.id() == id) {
            e.fail_count = 0;
            e.last_seen = Instant::now();
            e.srtt_us = ewma(e.srtt_us, rtt_us);
            e.info.rtt_ms = e.srtt_us / 1000;
        }
    }

    pub fn mark_fail(&mut self, id: NodeId) {
        let i = bucket_index(&self.self_id, &id);
        if let Some(e) = self.buckets[i].iter_mut().find(|e| e.id() == id) {
            e.fail_count = e.fail_count.saturating_add(1);
            if e.fail_count >= 3 {
                self.evict_and_replace(id);
            }
        }
    }

    pub fn closest(&self, target: &Key, n: usize) -> ArrayVec<PeerInfo, K_MAX> {
        let mut all: Vec<&PeerEntry> = self.buckets.iter().flatten().collect();
        all.sort_by(|a, b| {
            let da = xor_distance(&a.info.id.0, &target.0);
            let db = xor_distance(&b.info.id.0, &target.0);
            da.cmp(&db)
                .then(a.info.rtt_ms.cmp(&b.info.rtt_ms))
        });
        let mut out = ArrayVec::new();
        for e in all.into_iter().take(n.min(K_MAX)) {
            let _ = out.try_push(e.info.clone());
        }
        out
    }

    pub fn get(&self, id: NodeId) -> Option<&PeerEntry> {
        let i = bucket_index(&self.self_id, &id);
        self.buckets[i].iter().find(|e| e.id() == id)
    }

    pub fn all_peers(&self) -> impl Iterator<Item = &PeerEntry> {
        self.buckets.iter().flatten()
    }

    pub fn timeout_us(&self, id: NodeId) -> u32 {
        let srtt = self.get(id).map(|e| e.srtt_us).unwrap_or(200_000);
        (srtt.saturating_mul(2)).clamp(50_000, 600_000)
    }

    fn prefix_ok(&self, info: &PeerInfo) -> bool {
        // Diversity stub: at most 8 peers per IPv4 /24 in the same bucket.
        let Some(addr) = info.primary_addr() else {
            return true;
        };
        let IpAddr::V4(v4) = addr.ip() else {
            return true;
        };
        let oct = v4.octets();
        let prefix = (oct[0], oct[1], oct[2]);
        let i = bucket_index(&self.self_id, &info.id);
        let same = self.buckets[i]
            .iter()
            .filter(|e| {
                e.info
                    .primary_addr()
                    .map(|a| match a.ip() {
                        IpAddr::V4(x) => {
                            let o = x.octets();
                            (o[0], o[1], o[2]) == prefix
                        }
                        _ => false,
                    })
                    .unwrap_or(false)
            })
            .count();
        same < 8
    }
}

impl PeerEntry {
    pub fn id(&self) -> NodeId {
        self.info.id
    }
}

fn ewma(old: u32, sample: u32) -> u32 {
    (old * 7 + sample) / 8
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn peer(b: u8, port: u16) -> PeerInfo {
        let mut id = [0u8; 32];
        id[31] = b;
        PeerInfo::new(
            NodeId(id),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port),
        )
    }

    #[test]
    fn insert_and_closest() {
        let self_id = NodeId([0; 32]);
        let mut rt = RoutingTable::new(self_id);
        for i in 1..=10u8 {
            rt.insert(peer(i, 4000 + u16::from(i)));
        }
        assert_eq!(rt.len(), 10);
        let closest = rt.closest(&Key([0; 32]), 3);
        assert_eq!(closest.len(), 3);
    }

    #[test]
    fn evict_dead() {
        let self_id = NodeId([0; 32]);
        let mut rt = RoutingTable::new(self_id);
        let p = peer(1, 4001);
        rt.insert(p.clone());
        rt.evict_and_replace(p.id);
        assert!(rt.is_empty());
    }
}
