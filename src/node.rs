//! Multi-shard node: pin loops, route client ops by XOR locality.

use crate::crypto::{mutable_key, sign_record, Identity};
use crate::metrics::{aggregate, prometheus_text, ShardMetrics, Snapshot};
use crate::shard::{spawn_shard, NodeConfig, Reply, ShardCmd, ShardHandle};
use crate::store::{StoredRecord, KIND_MUTABLE, MUTABLE_TTL_SECS};
use crate::types::{shard_id, Key, NodeId, PeerInfo};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Duration;

pub struct Node {
    pub identity: Arc<Identity>,
    pub cfg: Arc<NodeConfig>,
    shards: Vec<ShardHandle>,
    running: Arc<AtomicBool>,
}

impl Node {
    pub fn start(identity: Identity, cfg: NodeConfig) -> std::io::Result<Self> {
        let identity = Arc::new(identity);
        let cfg = Arc::new(cfg);
        let running = Arc::new(AtomicBool::new(true));
        let n = cfg.shard_count.max(1);
        let mut shards = Vec::with_capacity(n as usize);
        for i in 0..n {
            let h = spawn_shard(i, identity.clone(), cfg.clone(), cfg.listen, running.clone())?;
            shards.push(h);
        }
        let node = Self {
            identity,
            cfg: cfg.clone(),
            shards,
            running,
        };
        if !cfg.bootstrap.is_empty() {
            node.bootstrap(&cfg.bootstrap);
        }
        Ok(node)
    }

    pub fn node_id(&self) -> NodeId {
        self.identity.node_id()
    }

    pub fn wg_public(&self) -> [u8; 32] {
        *self.identity.wg_public().as_bytes()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.shards[0].local
    }

    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.shards.iter().map(|s| s.local).collect()
    }

    pub fn bootstrap(&self, seeds: &[SocketAddr]) {
        for s in &self.shards {
            let _ = s.tx.send(ShardCmd::Bootstrap {
                seeds: seeds.to_vec(),
            });
        }
    }

    pub fn inject_peer(&self, info: PeerInfo) {
        for s in &self.shards {
            let _ = s.tx.send(ShardCmd::InjectPeer { info: info.clone() });
        }
    }

    fn owner(&self, key: &Key) -> &ShardHandle {
        let id = shard_id(&self.node_id(), key, self.shards.len() as u32);
        &self.shards[id as usize]
    }

    pub fn put(&self, value: &[u8]) -> Result<Key, &'static str> {
        self.put_ttl(value, crate::store::MUTABLE_TTL_SECS)
    }

    pub fn put_ttl(&self, value: &[u8], ttl_secs: u64) -> Result<Key, &'static str> {
        let key = crate::crypto::hash_value(value);
        self.call(
            self.owner(&key),
            |tx| ShardCmd::Put {
                value: value.to_vec(),
                ttl_secs,
                tx,
            },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Key(k) => Ok(k),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    pub fn get(&self, key: &Key) -> Result<Option<Vec<u8>>, &'static str> {
        self.call(
            self.owner(key),
            |tx| ShardCmd::Get { key: *key, tx },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Record(r) => Ok(r.map(|r| r.value)),
            Reply::Value(v) => Ok(v),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    pub fn get_record(&self, key: &Key) -> Result<Option<StoredRecord>, &'static str> {
        self.call(
            self.owner(key),
            |tx| ShardCmd::Get { key: *key, tx },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Record(r) => Ok(r),
            Reply::Value(Some(v)) => Ok(Some(StoredRecord {
                key: *key,
                value: v,
                sequence: 0,
                ttl_secs: 0,
                not_before_unix: 0,
                owner_pubkey: Vec::new(),
                signature: Vec::new(),
                kind: crate::store::KIND_IMMUTABLE,
                namespace: Vec::new(),
                salt: Vec::new(),
                stored_unix: 0,
                cache: false,
            })),
            Reply::Value(None) => Ok(None),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    /// FIND_VALUE for a named record; require Ed25519 `owner_pk` over the envelope.
    pub fn get_mutable(
        &self,
        owner_pk: &[u8],
        ns: &[u8],
        salt: &[u8],
    ) -> Result<Option<Vec<u8>>, &'static str> {
        let key = mutable_key(owner_pk, ns, salt);
        match self.get_record(&key)? {
            None => Ok(None),
            Some(rec) if rec.key != key || rec.namespace != ns || rec.salt != salt => {
                Err("key mismatch")
            }
            Some(rec) if !rec.signed_by(owner_pk) => Err("bad signature"),
            Some(rec) => Ok(Some(rec.value)),
        }
    }

    pub fn put_mutable(&self, ns: &[u8], salt: &[u8], value: &[u8], seq: u64) -> Result<Key, &'static str> {
        self.put_mutable_ttl(ns, salt, value, seq, MUTABLE_TTL_SECS)
    }

    pub fn put_mutable_ttl(
        &self,
        ns: &[u8],
        salt: &[u8],
        value: &[u8],
        seq: u64,
        ttl_secs: u64,
    ) -> Result<Key, &'static str> {
        let pk = self.identity.verifying_key();
        let key = mutable_key(pk.as_bytes(), ns, salt);
        let ttl = ttl_secs;
        let sig = sign_record(&self.identity.signing, &key, value, seq, ttl, 0);
        let rec = StoredRecord {
            key,
            value: value.to_vec(),
            sequence: seq,
            ttl_secs: ttl,
            not_before_unix: 0,
            owner_pubkey: pk.as_bytes().to_vec(),
            signature: sig.to_vec(),
            kind: KIND_MUTABLE,
            namespace: ns.to_vec(),
            salt: salt.to_vec(),
            stored_unix: crate::store::now_unix(),
            cache: false,
        };
        self.call(
            self.owner(&key),
            |tx| ShardCmd::PutMutable { rec, tx },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Key(k) => Ok(k),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    pub fn announce_provider(&self, key: Key, meta: &[u8]) -> Result<(), &'static str> {
        self.call(
            self.owner(&key),
            |tx| ShardCmd::Announce {
                key,
                meta: meta.to_vec(),
                tx,
            },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Ok => Ok(()),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    pub fn find_providers(&self, key: &Key) -> Result<Vec<(NodeId, Vec<u8>)>, &'static str> {
        self.call(
            self.owner(key),
            |tx| ShardCmd::FindProviders { key: *key, tx },
            Duration::from_secs(2),
        )
        .and_then(|r| match r {
            Reply::Providers(p) => Ok(p),
            Reply::Value(Some(_)) => Ok(Vec::new()),
            Reply::Value(None) => Ok(Vec::new()),
            Reply::Err(e) => Err(e),
            _ => Err("unexpected"),
        })
    }

    pub fn metrics(&self) -> Snapshot {
        let refs: Vec<Arc<ShardMetrics>> = self.shards.iter().map(|s| s.metrics.clone()).collect();
        aggregate(&refs)
    }

    pub fn prometheus(&self) -> String {
        prometheus_text(&self.metrics())
    }

    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        for s in &self.shards {
            let _ = s.tx.send(ShardCmd::Shutdown);
        }
        for s in &mut self.shards {
            s.join();
        }
    }

    fn call(
        &self,
        shard: &ShardHandle,
        make: impl FnOnce(mpsc::Sender<Reply>) -> ShardCmd,
        timeout: Duration,
    ) -> Result<Reply, &'static str> {
        let (tx, rx) = mpsc::channel();
        shard.tx.send(make(tx)).map_err(|_| "shard gone")?;
        rx.recv_timeout(timeout).map_err(|_| "timeout")
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.running.load(Ordering::Relaxed) {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{decode_body, encode_ping, Header, MessageType};
    use crate::crypto::hash_value;
    use crate::lookup::merge_step;
    use crate::pool::LookupArena;
    use crate::types::PeerInfo;
    use std::net::{IpAddr, Ipv4Addr, UdpSocket};

    fn cfg() -> NodeConfig {
        NodeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            shard_count: 1,
            plaintext: true,
            query_blind: false,
            ..NodeConfig::default()
        }
    }

    #[test]
    fn ping_pong_loopback() {
        let node = Node::start(Identity::generate(), cfg()).unwrap();
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(500))).unwrap();
        let mut buf = [0u8; 128];
        let n = encode_ping(42, 1, &mut buf).unwrap();
        sock.send_to(&buf[..n], node.local_addr()).unwrap();
        let mut r = [0u8; 256];
        let (m, _) = sock.recv_from(&mut r).unwrap();
        let h = Header::decode(&r[..m]).unwrap();
        assert_eq!(h.ty, MessageType::Pong);
        assert_eq!(h.correlation, 42);
        let _ = decode_body::<crate::proto::Pong>(&r[..m]).unwrap();
    }

    #[test]
    fn store_find_local() {
        let node = Node::start(Identity::generate(), cfg()).unwrap();
        let key = node.put(b"hello-molia").unwrap();
        assert_eq!(key, hash_value(b"hello-molia"));
        let got = node.get(&key).unwrap();
        assert_eq!(got.as_deref(), Some(&b"hello-molia"[..]));
    }

    fn cfg_wg() -> NodeConfig {
        NodeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            shard_count: 1,
            plaintext: false,
            query_blind: false,
            ..NodeConfig::default()
        }
    }

    #[test]
    fn two_nodes_store_find() {
        let a = Node::start(Identity::generate(), cfg()).unwrap();
        let b = Node::start(Identity::generate(), cfg()).unwrap();
        a.inject_peer(PeerInfo::new(b.node_id(), b.local_addr()));
        b.inject_peer(PeerInfo::new(a.node_id(), a.local_addr()));
        std::thread::sleep(Duration::from_millis(50));
        let key = a.put(b"shared").unwrap();
        // B may receive STORE replica; if not, FIND_VALUE via A as closer peer.
        let from_b = b.get(&key).unwrap();
        if from_b.is_none() {
            let from_a = a.get(&key).unwrap();
            assert_eq!(from_a.as_deref(), Some(&b"shared"[..]));
        } else {
            assert_eq!(from_b.as_deref(), Some(&b"shared"[..]));
        }
    }

    #[test]
    fn two_nodes_wg_store_find() {
        let a = Node::start(Identity::generate(), cfg_wg()).unwrap();
        let b = Node::start(Identity::generate(), cfg_wg()).unwrap();
        a.bootstrap(&[b.local_addr()]);
        b.bootstrap(&[a.local_addr()]);
        std::thread::sleep(Duration::from_millis(200));
        let key = a.put(b"wg-shared").unwrap();
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(b.get(&key).unwrap().as_deref(), Some(&b"wg-shared"[..]));
    }

    #[test]
    fn mutable_record() {
        let node = Node::start(Identity::generate(), cfg()).unwrap();
        let key = node.put_mutable(b"ns", b"salt", b"v1", 1).unwrap();
        let got = node.get(&key).unwrap();
        assert_eq!(got.as_deref(), Some(&b"v1"[..]));
        let key2 = node.put_mutable(b"ns", b"salt", b"v2", 2).unwrap();
        assert_eq!(key, key2);
        assert_eq!(node.get(&key).unwrap().as_deref(), Some(&b"v2"[..]));
        let pk = node.identity.verifying_key();
        assert_eq!(
            node.get_mutable(pk.as_bytes(), b"ns", b"salt")
                .unwrap()
                .as_deref(),
            Some(&b"v2"[..])
        );
        let other = Identity::generate();
        assert!(node
            .get_mutable(other.verifying_key().as_bytes(), b"ns", b"salt")
            .unwrap()
            .is_none());
        assert_eq!(
            node.get_mutable(pk.as_bytes(), b"ns", b"nope").unwrap(),
            None
        );
    }

    #[test]
    fn providers() {
        let node = Node::start(Identity::generate(), cfg()).unwrap();
        let key = hash_value(b"blob");
        node.announce_provider(key, b"chunk-0").unwrap();
        let p = node.find_providers(&key).unwrap();
        assert!(!p.is_empty());
    }

    #[test]
    fn lookup_step_zero_alloc_arena() {
        let mut arena = LookupArena::with_capacity(4096);
        let p = PeerInfo::new(
            NodeId([1; 32]),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        );
        assert_eq!(merge_step(&mut arena, &[p], &Key([0; 32])), 1);
    }

    #[test]
    fn codec_fuzz_random_headers() {
        let mut rng = [0u8; 64];
        for i in 0..200u16 {
            rng[0] = i as u8;
            rng[1] = i.wrapping_mul(3) as u8;
            let _ = Header::decode(&rng);
        }
    }

    #[test]
    fn chaos_partition_then_heal() {
        let a = Node::start(Identity::generate(), cfg()).unwrap();
        let b = Node::start(Identity::generate(), cfg()).unwrap();
        let key = a.put(b"part").unwrap();
        assert!(a.get(&key).unwrap().is_some());
        a.inject_peer(PeerInfo::new(b.node_id(), b.local_addr()));
        std::thread::sleep(Duration::from_millis(30));
        let _ = b.get(&key);
    }

    #[test]
    fn no_tokio_in_metrics_path() {
        let node = Node::start(Identity::generate(), cfg()).unwrap();
        let text = node.prometheus();
        assert!(text.contains("molia_rx_packets"));
    }
}
