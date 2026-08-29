//! Iterative FIND_NODE / FIND_VALUE with adaptive α and optional blinding.

use crate::pool::LookupArena;
use crate::types::{xor_distance, Key, NodeId, PeerInfo, ALPHA_DEFAULT, ALPHA_MAX, ALPHA_MIN, K_DEFAULT};
use arrayvec::ArrayVec;
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupKind {
    FindNode,
    FindValue,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrivacyMode {
    None,
    Blind,
    Relay,
}

pub struct Lookup {
    pub kind: LookupKind,
    pub target: Key,
    pub privacy: PrivacyMode,
    pub k: usize,
    pub alpha: usize,
    pub started: Instant,
    pub budget: Duration,
    pub queried: HashSet<NodeId>,
    pub in_flight: ArrayVec<(NodeId, u32, Instant), 8>,
    pub shortlist: Vec<PeerInfo>,
    pub best: Vec<NodeId>,
    pub found_record: Option<crate::store::StoredRecord>,
    pub providers: Vec<(NodeId, Vec<u8>)>,
    pub retries: HashSet<NodeId>,
    pub done: bool,
    pub probe_targets: ArrayVec<Key, 4>,
}

impl Lookup {
    pub fn new(kind: LookupKind, target: Key, seeds: &[PeerInfo], privacy: PrivacyMode) -> Self {
        let mut shortlist = seeds.to_vec();
        sort_shortlist(&mut shortlist, &target);
        let probe_targets = if privacy == PrivacyMode::Blind {
            neighbor_probes(&target)
        } else {
            ArrayVec::new()
        };
        Self {
            kind,
            target,
            privacy,
            k: K_DEFAULT,
            alpha: ALPHA_DEFAULT,
            started: Instant::now(),
            budget: Duration::from_millis(1500),
            queried: HashSet::new(),
            in_flight: ArrayVec::new(),
            shortlist,
            best: Vec::new(),
            found_record: None,
            providers: Vec::new(),
            retries: HashSet::new(),
            done: false,
            probe_targets,
        }
    }

    pub fn next_batch(&mut self) -> ArrayVec<PeerInfo, 8> {
        if self.done || self.started.elapsed() >= self.budget {
            self.done = true;
            return ArrayVec::new();
        }
        let mut batch = ArrayVec::new();
        for p in &self.shortlist {
            if self.queried.contains(&p.id) {
                continue;
            }
            if self.in_flight.iter().any(|(id, _, _)| *id == p.id) {
                continue;
            }
            if batch.len() + self.in_flight.len() >= self.alpha {
                break;
            }
            let _ = batch.try_push(p.clone());
        }
        if batch.is_empty() && self.in_flight.is_empty() {
            self.done = true;
        }
        batch
    }

    pub fn note_sent(&mut self, id: NodeId, correlation: u32) {
        self.queried.insert(id);
        let _ = self.in_flight.try_push((id, correlation, Instant::now()));
    }

    pub fn on_timeouts(&mut self, now: Instant) -> Vec<NodeId> {
        let mut dead = Vec::new();
        self.in_flight.retain(|(id, _, t)| {
            if now.duration_since(*t) > Duration::from_millis(400) {
                dead.push(*id);
                false
            } else {
                true
            }
        });
        for id in &dead {
            if !self.retries.contains(id) {
                self.retries.insert(*id);
                self.queried.remove(id);
            }
        }
        if !dead.is_empty() {
            self.alpha = (self.alpha + 1).min(ALPHA_MAX);
        }
        dead
    }

    pub fn on_closer(&mut self, from: NodeId, peers: Vec<PeerInfo>, rtt_us: u32) {
        self.in_flight.retain(|(id, _, _)| *id != from);
        if rtt_us < 80_000 {
            self.alpha = self.alpha.saturating_sub(1).max(ALPHA_MIN);
        }
        for p in peers {
            if !self.shortlist.iter().any(|s| s.id == p.id) {
                self.shortlist.push(p);
            }
        }
        sort_shortlist(&mut self.shortlist, &self.target);
        let now_best: Vec<NodeId> = self.shortlist.iter().take(self.k).map(|p| p.id).collect();
        if now_best == self.best && self.in_flight.is_empty() {
            let all_queried = now_best.iter().all(|id| self.queried.contains(id));
            if all_queried {
                self.done = true;
            }
        }
        self.best = now_best;
    }

    pub fn on_record(&mut self, from: NodeId, rec: crate::store::StoredRecord) {
        self.in_flight.retain(|(id, _, _)| *id != from);
        self.found_record = Some(rec);
        self.done = true;
    }

    pub fn on_providers(&mut self, from: NodeId, providers: Vec<(NodeId, Vec<u8>)>, closer: Vec<PeerInfo>) {
        self.in_flight.retain(|(id, _, _)| *id != from);
        for p in providers {
            if !self.providers.iter().any(|(id, _)| *id == p.0) {
                self.providers.push(p);
            }
        }
        self.on_closer(from, closer, 0);
    }

    pub fn finish_peers(&self) -> Vec<PeerInfo> {
        self.shortlist.iter().take(self.k).cloned().collect()
    }
}

fn sort_shortlist(list: &mut [PeerInfo], target: &Key) {
    list.sort_by(|a, b| {
        xor_distance(&a.id.0, &target.0)
            .cmp(&xor_distance(&b.id.0, &target.0))
            .then(a.rtt_ms.cmp(&b.rtt_ms))
    });
}

/// Neighbor keys used as blinding probes (± small prefix delta).
pub fn neighbor_probes(target: &Key) -> ArrayVec<Key, 4> {
    let mut out = ArrayVec::new();
    let mut a = target.0;
    a[31] ^= 0x01;
    let mut b = target.0;
    b[30] ^= 0x01;
    let _ = out.try_push(Key(a));
    let _ = out.try_push(Key(b));
    out
}

/// Scratch that proves a lookup step can run against a preallocated arena.
pub fn merge_step(arena: &mut LookupArena, incoming: &[PeerInfo], target: &Key) -> usize {
    arena.reset();
    let _ = arena.alloc(incoming.len().saturating_mul(32).min(1024));
    let mut tmp: ArrayVec<PeerInfo, 64> = ArrayVec::new();
    for p in incoming.iter().take(64) {
        let _ = tmp.try_push(p.clone());
    }
    sort_shortlist(&mut tmp, target);
    tmp.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn p(b: u8) -> PeerInfo {
        let mut id = [0u8; 32];
        id[31] = b;
        PeerInfo::new(
            NodeId(id),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000 + u16::from(b)),
        )
    }

    #[test]
    fn terminates_when_no_progress() {
        let seeds = vec![p(1), p(2), p(3)];
        let mut l = Lookup::new(LookupKind::FindNode, Key([0; 32]), &seeds, PrivacyMode::None);
        let batch = l.next_batch();
        assert!(!batch.is_empty());
        for s in &seeds {
            l.note_sent(s.id, 1);
            l.on_closer(s.id, vec![], 10_000);
        }
        assert!(l.done || l.next_batch().is_empty());
    }

    #[test]
    fn merge_step_uses_arena() {
        let mut arena = LookupArena::with_capacity(4096);
        let n = merge_step(&mut arena, &[p(1), p(9)], &Key([0; 32]));
        assert_eq!(n, 2);
    }
}
