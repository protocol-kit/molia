//! Per-shard userspace WireGuard (BoringTun, no TUN). `receiver_index` encodes shard id.

use crate::crypto::{verify_binding, verify_ephemeral_pow};
use crate::types::NodeId;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

pub const WG_TYPE_INITIATION: u32 = 1;
pub const WG_TYPE_RESPONSE: u32 = 2;
pub const WG_TYPE_COOKIE: u32 = 3;
pub const WG_TYPE_DATA: u32 = 4;
pub const KEEPALIVE_SECS: u16 = 20;
pub const PMTU_APP_CEILING: usize = 1200;

#[derive(Clone, Copy, Debug)]
pub struct WgHeader {
    pub ty: u32,
    pub receiver_index: u32,
}

pub fn parse_wg_header(buf: &[u8]) -> Option<WgHeader> {
    if buf.len() < 8 {
        return None;
    }
    let ty = u32::from_le_bytes(buf[0..4].try_into().ok()?);
    if !(1..=4).contains(&ty) {
        return None;
    }
    let receiver_index = u32::from_le_bytes(buf[4..8].try_into().ok()?);
    Some(WgHeader { ty, receiver_index })
}

pub fn looks_like_wg(buf: &[u8]) -> bool {
    parse_wg_header(buf).is_some()
}

/// BoringTun only yields `WriteToTunnelV4/V6` for inner IP packets.
pub fn wrap_rpc(rpc: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + rpc.len();
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&[10, 0, 0, 1]);
    ip[16..20].copy_from_slice(&[10, 0, 0, 2]);
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&1u16.to_be_bytes());
    udp[2..4].copy_from_slice(&1u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + rpc.len()) as u16).to_be_bytes());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&ip);
    out.extend_from_slice(&udp);
    out.extend_from_slice(rpc);
    out
}

pub fn unwrap_rpc(inner: &[u8]) -> &[u8] {
    if inner.len() >= 28 && inner[0] == 0x45 {
        &inner[28..]
    } else {
        inner
    }
}

/// High 8 bits of `receiver_index` are the shard id.
pub fn encode_receiver_index(shard_id: u8, local: u32) -> u32 {
    ((shard_id as u32) << 24) | (local & 0x00FF_FFFF)
}

pub fn shard_from_receiver_index(index: u32) -> u8 {
    (index >> 24) as u8
}

struct Session {
    tunn: Tunn,
    #[allow(dead_code)]
    peer_id: Option<NodeId>,
    endpoint: Option<SocketAddr>,
    #[allow(dead_code)]
    x25519: PublicKey,
}

pub struct WgEngine {
    secret: StaticSecret,
    public: PublicKey,
    shard_id: u8,
    next_local: u32,
    sessions: HashMap<u32, Session>,
    by_x25519: HashMap<[u8; 32], u32>,
    pub pow_nonce: [u8; 16],
    pub pow_bits: u8,
}

impl WgEngine {
    pub fn new(secret: StaticSecret, shard_id: u8) -> Self {
        let public = PublicKey::from(&secret);
        Self {
            secret,
            public,
            shard_id,
            next_local: 1,
            sessions: HashMap::new(),
            by_x25519: HashMap::new(),
            pow_nonce: [0x11; 16],
            pow_bits: 0,
        }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    pub fn add_peer(
        &mut self,
        peer_x25519: PublicKey,
        peer_id: Option<NodeId>,
        endpoint: Option<SocketAddr>,
    ) -> u32 {
        if let Some(idx) = self.by_x25519.get(peer_x25519.as_bytes()) {
            return *idx;
        }
        let index = encode_receiver_index(self.shard_id, self.next_local);
        self.next_local = self.next_local.wrapping_add(1);
        let tunn = Tunn::new(
            self.secret.clone(),
            peer_x25519,
            None,
            Some(KEEPALIVE_SECS),
            index,
            None,
        )
        .expect("Tunn::new");
        self.by_x25519.insert(*peer_x25519.as_bytes(), index);
        self.sessions.insert(
            index,
            Session {
                tunn,
                peer_id,
                endpoint,
                x25519: peer_x25519,
            },
        );
        index
    }

    pub fn verify_binding_once(&self, ed: &[u8], x: &[u8], sig: &[u8]) -> bool {
        verify_binding(ed, x, sig)
    }

    pub fn check_initiation_pow(&self, datagram: &[u8]) -> bool {
        if self.pow_bits == 0 {
            return true;
        }
        // Initiation: type(4) + sender_index(4) + ephemeral(32)
        if datagram.len() < 40 {
            return false;
        }
        let mut e = [0u8; 32];
        e.copy_from_slice(&datagram[8..40]);
        verify_ephemeral_pow(&e, &self.pow_nonce, self.pow_bits)
    }

    pub fn decapsulate(
        &mut self,
        src: SocketAddr,
        datagram: &[u8],
        scratch: &mut [u8],
    ) -> Decap {
        if datagram.is_empty() {
            return self.drain_session(src, scratch);
        }
        let Some(hdr) = parse_wg_header(datagram) else {
            return Decap::Drop;
        };
        if hdr.ty == WG_TYPE_INITIATION && !self.check_initiation_pow(datagram) {
            return Decap::Cookie(self.cookie_reply(hdr.receiver_index, scratch));
        }
        if hdr.ty == WG_TYPE_DATA || hdr.ty == WG_TYPE_RESPONSE || hdr.ty == WG_TYPE_COOKIE {
            if let Some(sess) = self.sessions.get_mut(&hdr.receiver_index) {
                sess.endpoint = Some(src);
                return drive_decap(&mut sess.tunn, src.ip(), datagram, scratch);
            }
        }
        // Try every session (small N) for initiation to a known peer.
        let keys: Vec<u32> = self.sessions.keys().copied().collect();
        for idx in keys {
            let sess = self.sessions.get_mut(&idx).unwrap();
            let r = drive_decap(&mut sess.tunn, src.ip(), datagram, scratch);
            if !matches!(r, Decap::Drop) {
                sess.endpoint = Some(src);
                return r;
            }
        }
        Decap::Drop
    }

    pub fn encapsulate(&mut self, peer_x25519: &PublicKey, plaintext: &[u8], out: &mut [u8]) -> Option<(usize, SocketAddr)> {
        let idx = *self.by_x25519.get(peer_x25519.as_bytes())?;
        let sess = self.sessions.get_mut(&idx)?;
        let dest = sess.endpoint?;
        match sess.tunn.encapsulate(plaintext, out) {
            TunnResult::WriteToNetwork(pkt) => {
                let n = pkt.len();
                Some((n, dest))
            }
            TunnResult::Done => None,
            _ => None,
        }
    }

    pub fn encapsulate_to(
        &mut self,
        dest: SocketAddr,
        peer_x25519: PublicKey,
        peer_id: Option<NodeId>,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> Option<usize> {
        self.add_peer(peer_x25519, peer_id, Some(dest));
        let idx = *self.by_x25519.get(peer_x25519.as_bytes())?;
        let sess = self.sessions.get_mut(&idx)?;
        sess.endpoint = Some(dest);
        match sess.tunn.encapsulate(plaintext, out) {
            TunnResult::WriteToNetwork(pkt) => Some(pkt.len()),
            _ => None,
        }
    }

    fn drain_session(&mut self, src: SocketAddr, scratch: &mut [u8]) -> Decap {
        let keys: Vec<u32> = self.sessions.keys().copied().collect();
        for idx in keys {
            let sess = self.sessions.get_mut(&idx).unwrap();
            if sess.endpoint != Some(src) {
                continue;
            }
            let r = drive_decap(&mut sess.tunn, src.ip(), &[], scratch);
            if !matches!(r, Decap::Drop) {
                return r;
            }
        }
        Decap::Drop
    }

    pub fn tick_keepalive(&mut self, out: &mut [u8]) -> Vec<(usize, SocketAddr)> {
        let mut pkts = Vec::new();
        for sess in self.sessions.values_mut() {
            let Some(dest) = sess.endpoint else { continue };
            if let TunnResult::WriteToNetwork(pkt) = sess.tunn.update_timers(out) {
                pkts.push((pkt.len(), dest));
            }
        }
        pkts
    }

    fn cookie_reply(&self, _rx: u32, scratch: &mut [u8]) -> Vec<u8> {
        // Lightweight stand-in: publish (Ns, d) so the client can solve PoW.
        scratch[..16].copy_from_slice(&self.pow_nonce);
        scratch[16] = self.pow_bits;
        scratch[..17].to_vec()
    }
}

#[derive(Debug)]
pub enum Decap {
    Plaintext { len: usize },
    Network { len: usize },
    Cookie(Vec<u8>),
    Drop,
}

fn drive_decap(tunn: &mut Tunn, src: IpAddr, datagram: &[u8], scratch: &mut [u8]) -> Decap {
    match tunn.decapsulate(Some(src), datagram, scratch) {
        TunnResult::WriteToNetwork(pkt) => Decap::Network { len: pkt.len() },
        TunnResult::WriteToTunnelV4(inner, _) | TunnResult::WriteToTunnelV6(inner, _) => {
            Decap::Plaintext { len: inner.len() }
        }
        TunnResult::Done | TunnResult::Err(_) => Decap::Drop,
    }
}

/// Userspace demux: Data → shard from `receiver_index`; handshake → hash of 5-tuple.
pub fn demux_shard(buf: &[u8], src: SocketAddr, shard_count: u32) -> u32 {
    if shard_count <= 1 {
        return 0;
    }
    if let Some(h) = parse_wg_header(buf) {
        if h.ty == WG_TYPE_DATA {
            return u32::from(shard_from_receiver_index(h.receiver_index)) % shard_count;
        }
    }
    let ip = match src.ip() {
        IpAddr::V4(v) => u32::from_be_bytes(v.octets()),
        IpAddr::V6(_) => src.port() as u32,
    };
    (ip ^ u32::from(src.port())) % shard_count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receiver_index_encodes_shard() {
        let idx = encode_receiver_index(3, 7);
        assert_eq!(shard_from_receiver_index(idx), 3);
        assert_eq!(idx & 0x00FF_FFFF, 7);
    }

    #[test]
    fn parse_data_header() {
        let mut buf = [0u8; 16];
        buf[0] = 4;
        buf[4..8].copy_from_slice(&7u32.to_le_bytes());
        let h = parse_wg_header(&buf).unwrap();
        assert_eq!(h.ty, 4);
        assert_eq!(h.receiver_index, 7);
    }

    #[test]
    fn wrap_rpc_roundtrip() {
        let rpc = [1u8, 7, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 9];
        let wrapped = wrap_rpc(&rpc);
        assert_eq!(wrapped[0], 0x45);
        assert_eq!(unwrap_rpc(&wrapped), &rpc);
        assert_eq!(unwrap_rpc(&rpc), &rpc[..]);
    }
}
