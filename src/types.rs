//! 256-bit IDs, XOR distance, and XOR-local shard selection.

use std::fmt;
use std::net::SocketAddr;

pub const ID_LEN: usize = 32;
pub const K_DEFAULT: usize = 20;
pub const K_MAX: usize = 32;
pub const ALPHA_DEFAULT: usize = 4;
pub const ALPHA_MIN: usize = 3;
pub const ALPHA_MAX: usize = 8;
pub const PROTOCOL_VERSION: u8 = 1;
pub const PMTU_FLOOR: usize = 1200;
pub const HEADER_LEN: usize = 12;
pub const MAX_FIND_NODE_PEERS: usize = 16;
pub const MAX_PROVIDERS_PER_CHUNK: usize = 32;
pub const MAX_CLOSER_PEERS: usize = 8;
pub const FEATURE_PRIVACY_BLINDING: u64 = 1 << 0;
pub const FEATURE_TWO_HOP_RELAY: u64 = 1 << 1;
pub const FEATURE_STREAMING_CHUNKS: u64 = 1 << 2;
pub const FEATURE_ERASURE_HINTS: u64 = 1 << 3;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub [u8; ID_LEN]);

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub [u8; ID_LEN]);

impl NodeId {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; ID_LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }
}

impl Key {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; ID_LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; ID_LEN] {
        &self.0
    }

    pub fn from_node(id: NodeId) -> Self {
        Self(id.0)
    }
}

impl From<NodeId> for Key {
    fn from(id: NodeId) -> Self {
        Self(id.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key({})", hex::encode(&self.0[..8]))
    }
}

/// `d(a, b) = a ⊕ b` as a 256-bit integer (big-endian).
pub fn xor_distance(a: &[u8; ID_LEN], b: &[u8; ID_LEN]) -> [u8; ID_LEN] {
    let mut out = [0u8; ID_LEN];
    for i in 0..ID_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Bucket index `⌊log2 d(self, contact)⌋` in a 256-bit space (0..=255).
pub fn bucket_index(self_id: &NodeId, other: &NodeId) -> usize {
    let d = xor_distance(&self_id.0, &other.0);
    let lz = leading_zeros_256(&d);
    if lz >= 256 {
        0
    } else {
        255 - lz
    }
}

fn leading_zeros_256(d: &[u8; ID_LEN]) -> usize {
    let mut n = 0usize;
    for b in d {
        if *b == 0 {
            n += 8;
        } else {
            n += b.leading_zeros() as usize;
            break;
        }
    }
    n.min(256)
}

/// `k = ceil(log2 S)` high bits of `self XOR key`.
pub fn shard_id(self_id: &NodeId, key: &Key, shard_count: u32) -> u32 {
    if shard_count <= 1 {
        return 0;
    }
    let k = 32 - (shard_count - 1).leading_zeros(); // ceil(log2 S)
    let d = xor_distance(&self_id.0, &key.0);
    let prefix = u32::from_be_bytes([d[0], d[1], d[2], d[3]]);
    let raw = if k == 0 { 0 } else { prefix >> (32 - k) };
    if shard_count.is_power_of_two() {
        raw
    } else {
        raw % shard_count
    }
}

#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub id: NodeId,
    pub addrs: arrayvec::ArrayVec<SocketAddr, 4>,
    pub rtt_ms: u32,
    pub x25519: Option<[u8; 32]>,
}

impl PeerInfo {
    pub fn new(id: NodeId, addr: SocketAddr) -> Self {
        let mut addrs = arrayvec::ArrayVec::new();
        let _ = addrs.try_push(addr);
        Self {
            id,
            addrs,
            rtt_ms: 0,
            x25519: None,
        }
    }

    pub fn primary_addr(&self) -> Option<SocketAddr> {
        self.addrs.first().copied()
    }

    pub fn push_addr(&mut self, addr: SocketAddr) {
        if !self.addrs.iter().any(|a| *a == addr) {
            let _ = self.addrs.try_push(addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_is_symmetric_and_self_inverse() {
        let a = NodeId([1; 32]);
        let b = NodeId([2; 32]);
        let d = xor_distance(&a.0, &b.0);
        assert_eq!(d, xor_distance(&b.0, &a.0));
        assert_eq!(xor_distance(&a.0, &a.0), [0u8; 32]);
    }

    #[test]
    fn shard_id_power_of_two() {
        let self_id = NodeId([0; 32]);
        let mut key = Key([0; 32]);
        key.0[0] = 0xC0; // top bits 11...
        assert_eq!(shard_id(&self_id, &key, 4), 3);
        key.0[0] = 0x00;
        assert_eq!(shard_id(&self_id, &key, 4), 0);
    }

    #[test]
    fn bucket_index_same_id_is_zero() {
        let id = NodeId([0x11; 32]);
        assert_eq!(bucket_index(&id, &id), 0);
    }
}
