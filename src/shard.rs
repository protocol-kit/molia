//! Shard-owned state and the packet/RPC event loop.

use crate::codec::{
    decode_body, default_capabilities, encode_message, Header, MessageType, Qos, FLAG_PROBE,
};
use crate::crypto::{hash_value, node_id_from_pubkey, verify_binding, Identity};
use crate::erasure;
use crate::event_loop::{drain_cmds, setup_poller, wait, TimerKind, TimingWheel, DRAIN_BATCH};
use crate::lookup::{Lookup, LookupKind, PrivacyMode};
use crate::metrics::ShardMetrics;
use crate::nat::{punch_deadlines, EndpointHint, KEEPALIVE};
use crate::peerstore::Peerstore;
use crate::pool::BufferPool;
use crate::proto;
use crate::relay::RelayState;
use crate::routing::RoutingTable;
use crate::store::{now_unix_ms, record_from_proto, Store, StoredRecord, KIND_IMMUTABLE};
use crate::sybil::Sybil;
use crate::types::{
    shard_id, Key, NodeId, PeerInfo, ALPHA_DEFAULT, HEADER_LEN, K_DEFAULT, MAX_CLOSER_PEERS,
    MAX_FIND_NODE_PEERS, MAX_PROVIDERS_PER_CHUNK, PMTU_FLOOR,
};
use crate::udp::UdpIo;
use crate::wg::{
    looks_like_wg, parse_wg_header, unwrap_rpc, wrap_rpc, Decap, WgEngine, WG_TYPE_INITIATION,
};
use boringtun::x25519::PublicKey;
use prost::Message;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub struct NodeConfig {
    pub listen: SocketAddr,
    pub shard_count: u32,
    pub bootstrap: Vec<SocketAddr>,
    pub plaintext: bool,
    pub query_blind: bool,
    pub two_hop_relay: bool,
    pub peerstore_dir: Option<PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            listen: "0.0.0.0:0".parse().unwrap(),
            shard_count: 1,
            bootstrap: Vec::new(),
            plaintext: true,
            query_blind: true,
            two_hop_relay: false,
            peerstore_dir: None,
        }
    }
}

pub enum Reply {
    Key(Key),
    Value(Option<Vec<u8>>),
    Record(Option<StoredRecord>),
    Providers(Vec<(NodeId, Vec<u8>)>),
    Peers(Vec<PeerInfo>),
    Ok,
    Err(&'static str),
}

pub enum ShardCmd {
    Bootstrap { seeds: Vec<SocketAddr> },
    Put {
        value: Vec<u8>,
        ttl_secs: u64,
        tx: Sender<Reply>,
    },
    Get { key: Key, tx: Sender<Reply> },
    PutMutable { rec: StoredRecord, tx: Sender<Reply> },
    Announce { key: Key, meta: Vec<u8>, tx: Sender<Reply> },
    FindProviders { key: Key, tx: Sender<Reply> },
    InjectPeer { info: PeerInfo },
    Shutdown,
}

pub struct ShardHandle {
    pub id: u32,
    pub local: SocketAddr,
    pub tx: Sender<ShardCmd>,
    pub metrics: Arc<ShardMetrics>,
    join: Option<JoinHandle<()>>,
}

impl ShardHandle {
    pub fn join(&mut self) {
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

pub fn spawn_shard(
    id: u32,
    identity: Arc<Identity>,
    cfg: Arc<NodeConfig>,
    bind: SocketAddr,
    running: Arc<AtomicBool>,
) -> std::io::Result<ShardHandle> {
    let io = UdpIo::bind(bind)?;
    let local = io.local;
    let (tx, rx) = mpsc::channel();
    let metrics = Arc::new(ShardMetrics::default());
    let m2 = metrics.clone();
    let join = thread::Builder::new()
        .name(format!("molia-shard-{id}"))
        .stack_size(8 * 1024 * 1024)
        .spawn(move || {
            if let Err(e) = run_shard(id, identity, cfg, io, rx, m2, running) {
                tracing::error!(shard = id, error = %e, "shard loop exited");
            }
        })?;
    Ok(ShardHandle {
        id,
        local,
        tx,
        metrics,
        join: Some(join),
    })
}

struct PendingLookup {
    lookup: Lookup,
    reply: Option<Sender<Reply>>,
}

struct ShardCtx {
    id: u32,
    identity: Arc<Identity>,
    cfg: Arc<NodeConfig>,
    io: UdpIo,
    pool: BufferPool,
    table: RoutingTable,
    store: Store,
    peers: Peerstore,
    wg: WgEngine,
    sybil: Sybil,
    relay: RelayState,
    metrics: Arc<ShardMetrics>,
    lookups: HashMap<u32, PendingLookup>,
    next_corr: u32,
    endpoints: HashMap<NodeId, EndpointHint>,
    timers: TimingWheel,
    keys_by_addr: HashMap<SocketAddr, [u8; 32]>,
    pending_wg: HashMap<SocketAddr, Vec<Vec<u8>>>,
}

fn run_shard(
    id: u32,
    identity: Arc<Identity>,
    cfg: Arc<NodeConfig>,
    io: UdpIo,
    rx: Receiver<ShardCmd>,
    metrics: Arc<ShardMetrics>,
    running: Arc<AtomicBool>,
) -> std::io::Result<()> {
    let self_id = identity.node_id();
    let mut wg = WgEngine::new(identity.wg_secret.clone(), id as u8);
    wg.pow_bits = 0;
    let peers = if let Some(dir) = &cfg.peerstore_dir {
        Peerstore::open(dir, id).unwrap_or_else(|_| Peerstore::memory())
    } else {
        Peerstore::memory()
    };
    let store = if let Some(dir) = &cfg.peerstore_dir {
        Store::open(dir, id).unwrap_or_else(|_| Store::new())
    } else {
        Store::new()
    };
    tracing::info!(shard = id, addr = %io.local, "shard loop");
    let mut ctx = ShardCtx {
        id,
        identity,
        cfg: cfg.clone(),
        io,
        pool: BufferPool::new(),
        table: RoutingTable::new(self_id),
        store,
        peers,
        wg,
        sybil: Sybil::new(),
        relay: RelayState::new(cfg.two_hop_relay),
        metrics,
        lookups: HashMap::new(),
        next_corr: 1,
        endpoints: HashMap::new(),
        timers: TimingWheel::new(),
        keys_by_addr: HashMap::new(),
        pending_wg: HashMap::new(),
    };
    let (poller, mut events) = setup_poller(&ctx.io)?;
    let now = Instant::now();
    ctx.timers.schedule(now + KEEPALIVE, TimerKind::Keepalive);
    ctx.timers.schedule(now + Duration::from_millis(100), TimerKind::PeerstoreFlush);
    ctx.timers.schedule(now + Duration::from_secs(30), TimerKind::Gc);
    ctx.timers.schedule(now + Duration::from_millis(50), TimerKind::LookupTick);

    let mut rx_bufs: Vec<Vec<u8>> = (0..32).map(|_| ctx.pool.take()).collect();

    while running.load(Ordering::Relaxed) {
        let timeout = ctx
            .timers
            .next_timeout(Instant::now())
            .or(Some(Duration::from_millis(50)));
        let readable = wait(&poller, &ctx.io, &mut events, timeout)?;
        if readable {
            match ctx.io.recv_batch(&mut rx_bufs) {
                Ok(batch) => {
                    for (i, (n, src)) in batch.into_iter().enumerate() {
                        ShardMetrics::incr(&ctx.metrics.rx_packets);
                        ShardMetrics::add(&ctx.metrics.rx_bytes, n as u64);
                        let pkt = rx_bufs[i][..n].to_vec();
                        handle_datagram(&mut ctx, src, &pkt);
                    }
                }
                Err(e) => tracing::debug!(?e, "recv"),
            }
        }
        for cmd in drain_cmds(&rx, DRAIN_BATCH) {
            if matches!(cmd, ShardCmd::Shutdown) {
                running.store(false, Ordering::Relaxed);
                break;
            }
            handle_cmd(&mut ctx, cmd);
        }
        for kind in ctx.timers.pop_due(Instant::now()) {
            on_timer(&mut ctx, kind);
        }
    }
    for b in rx_bufs {
        ctx.pool.recycle(b);
    }
    let _ = ctx.store.flush_wal(&mut ctx.peers);
    let _ = ctx.peers.flush();
    Ok(())
}

fn handle_cmd(ctx: &mut ShardCtx, cmd: ShardCmd) {
    match cmd {
        ShardCmd::Bootstrap { seeds } => {
            for addr in seeds {
                ping(ctx, addr, None);
            }
        }
        ShardCmd::InjectPeer { info } => {
            if let Some(x) = info.x25519 {
                ctx.wg
                    .add_peer(PublicKey::from(x), Some(info.id), info.primary_addr());
                if let Some(addr) = info.primary_addr() {
                    ctx.keys_by_addr.insert(addr, x);
                }
            }
            ctx.table.insert(info.clone());
            ctx.peers.upsert(info);
        }
        ShardCmd::Put {
            value,
            ttl_secs,
            tx,
        } => {
            if erasure::should_erasure(value.len()) {
                if let Ok(shards) = erasure::encode(&value) {
                    let key = hash_value(&value);
                    ctx.store.announce_provider(key, ctx.identity.node_id(), format!("rs-10-4:{}", value.len()).into_bytes());
                    let _ = tx.send(Reply::Key(key));
                    let _ = shards;
                    return;
                }
            }
            match ctx.store.put_immutable_ttl(&value, ttl_secs) {
                Ok(key) => {
                    ShardMetrics::incr(&ctx.metrics.store_ok);
                    replicate_store(ctx, &value, key, ttl_secs);
                    let _ = tx.send(Reply::Key(key));
                }
                Err(_) => {
                    ShardMetrics::incr(&ctx.metrics.store_reject);
                    let _ = tx.send(Reply::Err("store failed"));
                }
            }
        }
        ShardCmd::Get { key, tx } => {
            ShardMetrics::incr(&ctx.metrics.lookups);
            if let Some(r) = ctx.store.get(&key) {
                ShardMetrics::incr(&ctx.metrics.lookup_ok);
                let _ = tx.send(Reply::Record(Some(r.clone())));
                return;
            }
            start_lookup(ctx, LookupKind::FindValue, key, Some(tx));
        }
        ShardCmd::PutMutable { rec, tx } => match ctx.store.put_record(rec.clone(), false) {
            Ok(()) => {
                ShardMetrics::incr(&ctx.metrics.store_ok);
                send_store_rpc(ctx, &rec);
                let _ = tx.send(Reply::Key(rec.key));
            }
            Err(_) => {
                ShardMetrics::incr(&ctx.metrics.store_reject);
                let _ = tx.send(Reply::Err("mutable rejected"));
            }
        },
        ShardCmd::Announce { key, meta, tx } => {
            ctx.store.announce_provider(key, ctx.identity.node_id(), meta.clone());
            announce_rpc(ctx, key, meta);
            let _ = tx.send(Reply::Ok);
        }
        ShardCmd::FindProviders { key, tx } => {
            let local = ctx.store.providers(&key, MAX_PROVIDERS_PER_CHUNK);
            if !local.is_empty() {
                let _ = tx.send(Reply::Providers(
                    local.into_iter().map(|e| (e.peer_id, e.meta)).collect(),
                ));
            } else {
                start_lookup(ctx, LookupKind::FindValue, key, Some(tx));
            }
        }
        ShardCmd::Shutdown => {}
    }
}

fn start_lookup(ctx: &mut ShardCtx, kind: LookupKind, target: Key, reply: Option<Sender<Reply>>) {
    let privacy = if ctx.cfg.query_blind {
        PrivacyMode::Blind
    } else {
        PrivacyMode::None
    };
    let seeds = ctx.table.closest(&target, ALPHA_DEFAULT);
    let mut lookup = Lookup::new(kind, target, &seeds, privacy);
    dispatch_lookup_batch(ctx, &mut lookup);
    if lookup.done {
        finish_lookup(kind, &lookup, reply);
        return;
    }
    let id = ctx.next_corr;
    ctx.lookups.insert(id, PendingLookup { lookup, reply });
}

fn dispatch_lookup_batch(ctx: &mut ShardCtx, lookup: &mut Lookup) {
    let batch = lookup.next_batch();
    for p in batch {
        let corr = next_corr(ctx);
        let dest = match p.primary_addr() {
            Some(a) => a,
            None => continue,
        };
        let mut buf = ctx.pool.take();
        let n = match lookup.kind {
            LookupKind::FindNode => encode_message(
                &Header::request(MessageType::FindNodeReq, Qos::Coordination, corr),
                &proto::FindNodeReq {
                    target_id: lookup.target.0.to_vec().into(),
                    limit: K_DEFAULT as u32,
                },
                &mut buf,
            ),
            LookupKind::FindValue => encode_message(
                &Header::request(MessageType::FindValueReq, Qos::Coordination, corr),
                &proto::FindValueReq {
                    key: lookup.target.0.to_vec().into(),
                    provider_limit: 16,
                },
                &mut buf,
            ),
        };
        if let Some(n) = n {
            send_app(ctx, dest, p.x25519, &buf[..n]);
            lookup.note_sent(p.id, corr);
        }
        ctx.pool.recycle(buf);
        if lookup.privacy == PrivacyMode::Blind {
            for probe in &lookup.probe_targets.clone() {
                let mut h = Header::request(MessageType::FindValueReq, Qos::Hints, next_corr(ctx));
                h.flags |= FLAG_PROBE;
                let mut buf = ctx.pool.take();
                if let Some(n) = encode_message(
                    &h,
                    &proto::FindValueReq {
                        key: probe.0.to_vec().into(),
                        provider_limit: 1,
                    },
                    &mut buf,
                ) {
                    send_app(ctx, dest, p.x25519, &buf[..n]);
                }
                ctx.pool.recycle(buf);
            }
        }
    }
}

fn finish_lookup(kind: LookupKind, lookup: &Lookup, reply: Option<Sender<Reply>>) {
    let Some(tx) = reply else { return };
    match kind {
        LookupKind::FindNode => {
            let _ = tx.send(Reply::Peers(lookup.finish_peers()));
        }
        LookupKind::FindValue => {
            if let Some(r) = &lookup.found_record {
                let _ = tx.send(Reply::Record(Some(r.clone())));
            } else if !lookup.providers.is_empty() {
                let _ = tx.send(Reply::Providers(lookup.providers.clone()));
            } else {
                let _ = tx.send(Reply::Value(None));
            }
        }
    }
}

fn handle_datagram(ctx: &mut ShardCtx, src: SocketAddr, pkt: &[u8]) {
    if looks_like_wg(pkt) {
        if !ctx.sybil.allow_pre_handshake(src) {
            ShardMetrics::incr(&ctx.metrics.drops_rate);
            return;
        }
        let mut scratch = ctx.pool.take();
        match ctx.wg.decapsulate(src, pkt, &mut scratch) {
            Decap::Plaintext { len } => {
                ShardMetrics::incr(&ctx.metrics.wg_decap_ok);
                let inner = unwrap_rpc(&scratch[..len]).to_vec();
                ctx.pool.recycle(scratch);
                handle_app(ctx, src, &inner, true);
                drain_wg_session(ctx, src);
                flush_pending_wg(ctx, src);
                return;
            }
            Decap::Network { len } => {
                let _ = ctx.io.send_to(&scratch[..len], src);
                ctx.pool.recycle(scratch);
                drain_wg_session(ctx, src);
                flush_pending_wg(ctx, src);
                return;
            }
            Decap::Cookie(c) => {
                ShardMetrics::incr(&ctx.metrics.cookies);
                let _ = ctx.io.send_to(&c, src);
                ctx.pool.recycle(scratch);
                return;
            }
            Decap::Drop => {
                ShardMetrics::incr(&ctx.metrics.wg_decap_fail);
                ctx.pool.recycle(scratch);
                return;
            }
        }
    }
    handle_app(ctx, src, pkt, false);
}

fn handle_app(ctx: &mut ShardCtx, src: SocketAddr, pkt: &[u8], authenticated: bool) {
    let Some(h) = Header::decode(pkt) else {
        ShardMetrics::incr(&ctx.metrics.drops_malformed);
        return;
    };
    match h.ty {
        MessageType::Ping => on_ping(ctx, src, &h, pkt),
        MessageType::Pong => on_pong(ctx, src, &h, pkt),
        MessageType::NegotiateReq => on_negotiate(ctx, src, &h),
        MessageType::FindNodeReq => on_find_node(ctx, src, &h, pkt),
        MessageType::FindNodeResp => on_find_node_resp(ctx, src, &h, pkt),
        MessageType::FindValueReq => on_find_value(ctx, src, &h, pkt),
        MessageType::FindValueResp => on_find_value_resp(ctx, src, &h, pkt),
        MessageType::StoreReq => on_store(ctx, src, &h, pkt),
        MessageType::AnnounceProviderReq => on_announce(ctx, src, &h, pkt),
        MessageType::Error => {}
        _ => {
            if !h.is_response() && authenticated {
                send_error(ctx, src, h.correlation, proto::error::Code::Unsupported, "type");
            }
        }
    }
}

fn on_ping(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let id = decode_body::<proto::Ping>(pkt).and_then(|p| {
        note_peer_keys(ctx, src, &p.x25519_pubkey, &p.ed25519_pubkey, &p.binding_sig)
    });
    learn_addr(ctx, src, id);
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::Pong, Qos::Control, h.correlation),
        &intro_pong(ctx),
        &mut buf,
    ) {
        send_plain(ctx, src, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn on_pong(ctx: &mut ShardCtx, src: SocketAddr, _h: &Header, pkt: &[u8]) {
    let id = decode_body::<proto::Pong>(pkt).and_then(|p| {
        note_peer_keys(ctx, src, &p.x25519_pubkey, &p.ed25519_pubkey, &p.binding_sig)
    });
    learn_addr(ctx, src, id);
}

fn on_negotiate(ctx: &mut ShardCtx, src: SocketAddr, h: &Header) {
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::NegotiateResp, Qos::Control, h.correlation),
        &proto::NegotiateResp {
            agreed: Some(default_capabilities()),
        },
        &mut buf,
    ) {
        send_app(ctx, src, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn on_find_node(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(req) = decode_body::<proto::FindNodeReq>(pkt) else {
        return;
    };
    let target = Key::from_bytes(&req.target_id).unwrap_or(Key([0; 32]));
    let limit = (req.limit as usize).clamp(1, MAX_FIND_NODE_PEERS);
    let peers = ctx.table.closest(&target, limit);
    reply_peers(ctx, src, h.correlation, &peers);
}

fn on_find_node_resp(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(resp) = decode_body::<proto::FindNodeResp>(pkt) else {
        return;
    };
    let peers = peers_from_proto(&resp.peers);
    for p in &peers {
        ctx.table.insert(p.clone());
        ctx.peers.upsert(p.clone());
    }
    learn_addr(ctx, src, peers.first().map(|p| p.id));
    complete_closer(ctx, h.correlation, src, peers);
}

fn on_find_value(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(req) = decode_body::<proto::FindValueReq>(pkt) else {
        return;
    };
    let Some(key) = Key::from_bytes(&req.key) else {
        return;
    };
    let closer = ctx.table.closest(&key, MAX_CLOSER_PEERS);
    if let Some(rec) = ctx.store.get(&key) {
        if !h.is_probe() {
            let mut buf = ctx.pool.take();
            let body = proto::FindValueResp {
                result: Some(proto::find_value_resp::Result::Record(rec.encode().into())),
                closer_peers: peers_to_proto(&closer),
            };
            if let Some(n) = encode_message(
                &Header::response(MessageType::FindValueResp, Qos::Coordination, h.correlation),
                &body,
                &mut buf,
            ) {
                send_app(ctx, src, None, &buf[..n]);
            }
            ctx.pool.recycle(buf);
            return;
        }
    }
    let prov = ctx.store.providers(&key, (req.provider_limit as usize).min(MAX_PROVIDERS_PER_CHUNK));
    let mut buf = ctx.pool.take();
    let body = if prov.is_empty() {
        proto::FindValueResp {
            result: None,
            closer_peers: peers_to_proto(&closer),
        }
    } else {
        proto::FindValueResp {
            result: Some(proto::find_value_resp::Result::Providers(proto::Providers {
                providers: prov
                    .iter()
                    .map(|e| proto::Provider {
                        peer_id: e.peer_id.0.to_vec().into(),
                        meta: e.meta.clone().into(),
                    })
                    .collect(),
            })),
            closer_peers: peers_to_proto(&closer),
        }
    };
    if let Some(n) = encode_message(
        &Header::response(MessageType::FindValueResp, Qos::Coordination, h.correlation),
        &body,
        &mut buf,
    ) {
        send_app(ctx, src, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn on_find_value_resp(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(resp) = decode_body::<proto::FindValueResp>(pkt) else {
        return;
    };
    let closer = peers_from_proto(&resp.closer_peers);
    for p in &closer {
        ctx.table.insert(p.clone());
    }
    match resp.result {
        Some(proto::find_value_resp::Result::Record(bytes)) => {
            if let Ok(pr) = proto::Record::decode(&bytes[..]) {
                if let Some(rec) = record_from_proto(&pr) {
                    if rec.authentic() {
                        if !h.is_probe() {
                            ctx.store.cache_hit(rec.clone());
                        }
                        if let Some(pend) = find_lookup_mut(ctx, h.correlation) {
                            pend.lookup.on_record(NodeId([0; 32]), rec);
                        }
                    }
                }
            }
        }
        Some(proto::find_value_resp::Result::Providers(p)) => {
            let list = p
                .providers
                .iter()
                .filter_map(|x| NodeId::from_bytes(&x.peer_id).map(|id| (id, x.meta.to_vec())))
                .collect();
            if let Some(pend) = find_lookup_mut(ctx, h.correlation) {
                pend.lookup.on_providers(NodeId([0; 32]), list, closer);
            }
        }
        None => complete_closer(ctx, h.correlation, src, closer),
    }
    sweep_lookups(ctx);
}

fn on_store(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(req) = decode_body::<proto::StoreReq>(pkt) else {
        return;
    };
    if !ctx.sybil.allow_pre_handshake(src) {
        send_error(ctx, src, h.correlation, proto::error::Code::RateLimited, "rate");
        return;
    }
    let (code, reason) = match proto::Record::decode(&req.record[..]) {
        Ok(pr) => match record_from_proto(&pr) {
            Some(rec) => {
                if rec.kind != KIND_IMMUTABLE && !req.cost_stamp.is_empty() {
                    let _ = ctx.sybil.check_cost_stamp(&rec.key, b"store", &req.cost_stamp);
                }
                match ctx.store.put_record(rec, h.is_probe()) {
                    Ok(()) => {
                        ShardMetrics::incr(&ctx.metrics.store_ok);
                        (proto::store_resp::Code::Ok, "")
                    }
                    Err(e) => {
                        ShardMetrics::incr(&ctx.metrics.store_reject);
                        (proto::store_resp::Code::Invalid, e)
                    }
                }
            }
            None => (proto::store_resp::Code::Invalid, "record"),
        },
        Err(_) => (proto::store_resp::Code::Invalid, "decode"),
    };
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::StoreResp, Qos::Coordination, h.correlation),
        &proto::StoreResp {
            code: code as i32,
            reason: reason.into(),
        },
        &mut buf,
    ) {
        send_app(ctx, src, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn on_announce(ctx: &mut ShardCtx, src: SocketAddr, h: &Header, pkt: &[u8]) {
    let Some(req) = decode_body::<proto::AnnounceProviderReq>(pkt) else {
        return;
    };
    if !ctx.sybil.allow_pre_handshake(src) {
        return;
    }
    let Some(key) = Key::from_bytes(&req.key) else {
        return;
    };
    if let Some(p) = req.self_descriptor {
        if let Some(id) = NodeId::from_bytes(&p.peer_id) {
            ctx.store.announce_provider(key, id, p.meta.to_vec());
        }
    }
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::AnnounceProviderResp, Qos::Coordination, h.correlation),
        &proto::AnnounceProviderResp {
            code: proto::announce_provider_resp::Code::Ok as i32,
            reason: String::new(),
        },
        &mut buf,
    ) {
        send_app(ctx, src, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn complete_closer(ctx: &mut ShardCtx, corr: u32, src: SocketAddr, peers: Vec<PeerInfo>) {
    let from = ctx
        .table
        .all_peers()
        .find(|e| e.info.primary_addr() == Some(src))
        .map(|e| e.id())
        .unwrap_or(NodeId([0; 32]));
    if let Some(pend) = find_lookup_mut(ctx, corr) {
        pend.lookup.on_closer(from, peers, 50_000);
    }
    sweep_lookups(ctx);
}

fn find_lookup_mut(ctx: &mut ShardCtx, corr: u32) -> Option<&mut PendingLookup> {
    ctx.lookups.values_mut().find(|p| {
        p.lookup
            .in_flight
            .iter()
            .any(|(_, c, _)| *c == corr)
    })
}

fn sweep_lookups(ctx: &mut ShardCtx) {
    let ids: Vec<u32> = ctx.lookups.keys().copied().collect();
    for id in ids {
        let Some(mut pend) = ctx.lookups.remove(&id) else {
            continue;
        };
        dispatch_lookup_batch(ctx, &mut pend.lookup);
        if pend.lookup.done {
            if pend.lookup.found_record.is_some() {
                ShardMetrics::incr(&ctx.metrics.lookup_ok);
            }
            finish_lookup(pend.lookup.kind, &pend.lookup, pend.reply);
        } else {
            ctx.lookups.insert(id, pend);
        }
    }
}

fn on_timer(ctx: &mut ShardCtx, kind: TimerKind) {
    let now = Instant::now();
    match kind {
        TimerKind::Keepalive => {
            let peers: Vec<(SocketAddr, NodeId)> = ctx
                .table
                .all_peers()
                .filter_map(|p| p.info.primary_addr().map(|a| (a, p.info.id)))
                .collect();
            for (addr, id) in peers {
                ping(ctx, addr, Some(id));
            }
            if !ctx.cfg.plaintext {
                let mut out = ctx.pool.take();
                for (n, dest) in ctx.wg.tick_keepalive(&mut out) {
                    let _ = ctx.io.send_to(&out[..n], dest);
                }
                ctx.pool.recycle(out);
            }
            ctx.timers.schedule(now + KEEPALIVE, TimerKind::Keepalive);
        }
        TimerKind::PeerstoreFlush => {
            let _ = ctx.store.flush_wal(&mut ctx.peers);
            let _ = ctx.peers.flush();
            ctx.timers
                .schedule(now + Duration::from_millis(100), TimerKind::PeerstoreFlush);
        }
        TimerKind::Gc => {
            ctx.store.gc();
            ctx.timers.schedule(now + Duration::from_secs(30), TimerKind::Gc);
        }
        TimerKind::LookupTick => {
            let mut timed = Vec::new();
            for pend in ctx.lookups.values_mut() {
                timed.extend(pend.lookup.on_timeouts(now));
            }
            for id in timed {
                ctx.table.mark_fail(id);
                ctx.sybil.penalize(id);
            }
            sweep_lookups(ctx);
            ctx.timers
                .schedule(now + Duration::from_millis(50), TimerKind::LookupTick);
        }
        TimerKind::Punch => {
            let _ = punch_deadlines(now);
            ShardMetrics::incr(&ctx.metrics.punch_ok);
        }
    }
}

fn ping(ctx: &mut ShardCtx, dest: SocketAddr, _id: Option<NodeId>) {
    let corr = next_corr(ctx);
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::request(MessageType::Ping, Qos::Control, corr),
        &intro_ping(ctx),
        &mut buf,
    ) {
        send_plain(ctx, dest, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn replicate_store(ctx: &mut ShardCtx, value: &[u8], key: Key, ttl_secs: u64) {
    let rec = StoredRecord {
        key,
        value: value.to_vec(),
        sequence: 0,
        ttl_secs,
        not_before_unix: 0,
        owner_pubkey: Vec::new(),
        signature: Vec::new(),
        kind: KIND_IMMUTABLE,
        namespace: Vec::new(),
        salt: Vec::new(),
        stored_unix: crate::store::now_unix(),
        cache: false,
    };
    send_store_rpc(ctx, &rec);
}

fn send_store_rpc(ctx: &mut ShardCtx, rec: &StoredRecord) {
    let peers = ctx.table.closest(&rec.key, K_DEFAULT);
    let encoded = rec.encode();
    for p in peers {
        let Some(dest) = p.primary_addr() else { continue };
        let corr = next_corr(ctx);
        let mut buf = ctx.pool.take();
        if let Some(n) = encode_message(
            &Header::request(MessageType::StoreReq, Qos::Coordination, corr),
            &proto::StoreReq {
                record: encoded.clone().into(),
                admission_token: Default::default(),
                cost_stamp: Default::default(),
            },
            &mut buf,
        ) {
            send_app(ctx, dest, p.x25519, &buf[..n]);
        }
        ctx.pool.recycle(buf);
    }
}

fn announce_rpc(ctx: &mut ShardCtx, key: Key, meta: Vec<u8>) {
    let peers = ctx.table.closest(&key, K_DEFAULT);
    for p in peers {
        let Some(dest) = p.primary_addr() else { continue };
        let corr = next_corr(ctx);
        let mut buf = ctx.pool.take();
        if let Some(n) = encode_message(
            &Header::request(MessageType::AnnounceProviderReq, Qos::Coordination, corr),
            &proto::AnnounceProviderReq {
                key: key.0.to_vec().into(),
                self_descriptor: Some(proto::Provider {
                    peer_id: ctx.identity.node_id().0.to_vec().into(),
                    meta: meta.clone().into(),
                }),
                record: Default::default(),
                admission_token: Default::default(),
                cost_stamp: Default::default(),
            },
            &mut buf,
        ) {
            send_app(ctx, dest, p.x25519, &buf[..n]);
        }
        ctx.pool.recycle(buf);
    }
}

fn reply_peers(ctx: &mut ShardCtx, dest: SocketAddr, corr: u32, peers: &[PeerInfo]) {
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::FindNodeResp, Qos::Coordination, corr),
        &proto::FindNodeResp {
            peers: peers_to_proto(peers),
        },
        &mut buf,
    ) {
        send_app(ctx, dest, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn send_error(ctx: &mut ShardCtx, dest: SocketAddr, corr: u32, code: proto::error::Code, reason: &str) {
    let mut buf = ctx.pool.take();
    if let Some(n) = encode_message(
        &Header::response(MessageType::Error, Qos::Control, corr),
        &proto::Error {
            code: code as i32,
            reason: reason.into(),
            retry_after_ms: 50,
        },
        &mut buf,
    ) {
        send_app(ctx, dest, None, &buf[..n]);
    }
    ctx.pool.recycle(buf);
}

fn intro_ping(ctx: &ShardCtx) -> proto::Ping {
    proto::Ping {
        now_unix_ms: now_unix_ms(),
        x25519_pubkey: ctx.identity.wg_public().as_bytes().to_vec().into(),
        ed25519_pubkey: ctx.identity.verifying_key().as_bytes().to_vec().into(),
        binding_sig: ctx.identity.binding_signature().to_vec().into(),
    }
}

fn intro_pong(ctx: &ShardCtx) -> proto::Pong {
    proto::Pong {
        now_unix_ms: now_unix_ms(),
        x25519_pubkey: ctx.identity.wg_public().as_bytes().to_vec().into(),
        ed25519_pubkey: ctx.identity.verifying_key().as_bytes().to_vec().into(),
        binding_sig: ctx.identity.binding_signature().to_vec().into(),
    }
}

fn note_peer_keys(
    ctx: &mut ShardCtx,
    src: SocketAddr,
    x25519: &[u8],
    ed25519: &[u8],
    sig: &[u8],
) -> Option<NodeId> {
    if x25519.len() != 32 || ed25519.len() != 32 || sig.is_empty() {
        return None;
    }
    if !verify_binding(ed25519, x25519, sig) {
        return None;
    }
    let mut x = [0u8; 32];
    x.copy_from_slice(x25519);
    let id = node_id_from_pubkey(ed25519);
    ctx.keys_by_addr.insert(src, x);
    ctx.wg.add_peer(PublicKey::from(x), Some(id), Some(src));
    let mut info = PeerInfo::new(id, src);
    info.x25519 = Some(x);
    ctx.table.insert(info.clone());
    ctx.peers.upsert(info);
    Some(id)
}

fn send_plain(ctx: &mut ShardCtx, dest: SocketAddr, app: &[u8]) {
    if ctx.io.send_to(app, dest).is_ok() {
        ShardMetrics::incr(&ctx.metrics.tx_packets);
        ShardMetrics::add(&ctx.metrics.tx_bytes, app.len() as u64);
    }
}

fn send_app(ctx: &mut ShardCtx, dest: SocketAddr, x25519: Option<[u8; 32]>, app: &[u8]) {
    if app.len() > PMTU_FLOOR {
        return;
    }
    let _ = ctx.relay.budget.on_egress(app.len() as u64);
    let key = x25519.or_else(|| ctx.keys_by_addr.get(&dest).copied());
    if ctx.cfg.plaintext || key.is_none() {
        send_plain(ctx, dest, app);
        return;
    }
    let pk = PublicKey::from(key.unwrap());
    let inner = wrap_rpc(app);
    let mut out = ctx.pool.take();
    match ctx.wg.encapsulate_to(dest, pk, None, &inner, &mut out) {
        Some(n) => {
            if parse_wg_header(&out[..n]).is_some_and(|h| h.ty == WG_TYPE_INITIATION) {
                ctx.pending_wg.entry(dest).or_default().push(app.to_vec());
            }
            let _ = ctx.io.send_to(&out[..n], dest);
            ShardMetrics::incr(&ctx.metrics.tx_packets);
        }
        None => {
            ctx.pending_wg.entry(dest).or_default().push(app.to_vec());
            if let Some(n) = ctx.wg.encapsulate_to(dest, pk, None, &[], &mut out) {
                let _ = ctx.io.send_to(&out[..n], dest);
                ShardMetrics::incr(&ctx.metrics.tx_packets);
            }
        }
    }
    ctx.pool.recycle(out);
}

fn drain_wg_session(ctx: &mut ShardCtx, src: SocketAddr) {
    loop {
        let mut scratch = ctx.pool.take();
        match ctx.wg.decapsulate(src, &[], &mut scratch) {
            Decap::Network { len } => {
                let _ = ctx.io.send_to(&scratch[..len], src);
                ctx.pool.recycle(scratch);
            }
            Decap::Plaintext { len } => {
                ShardMetrics::incr(&ctx.metrics.wg_decap_ok);
                let inner = unwrap_rpc(&scratch[..len]).to_vec();
                ctx.pool.recycle(scratch);
                handle_app(ctx, src, &inner, true);
            }
            _ => {
                ctx.pool.recycle(scratch);
                break;
            }
        }
    }
}

fn flush_pending_wg(ctx: &mut ShardCtx, dest: SocketAddr) {
    let Some(queue) = ctx.pending_wg.remove(&dest) else {
        return;
    };
    let Some(key) = ctx.keys_by_addr.get(&dest).copied() else {
        for app in queue {
            send_plain(ctx, dest, &app);
        }
        return;
    };
    let pk = PublicKey::from(key);
    let mut leftover = Vec::new();
    let mut iter = queue.into_iter();
    for app in iter.by_ref() {
        let inner = wrap_rpc(&app);
        let mut out = ctx.pool.take();
        match ctx.wg.encapsulate_to(dest, pk, None, &inner, &mut out) {
            Some(n) => {
                if parse_wg_header(&out[..n]).is_some_and(|h| h.ty == WG_TYPE_INITIATION) {
                    leftover.push(app);
                    leftover.extend(iter);
                    let _ = ctx.io.send_to(&out[..n], dest);
                    ctx.pool.recycle(out);
                    break;
                }
                let _ = ctx.io.send_to(&out[..n], dest);
                ShardMetrics::incr(&ctx.metrics.tx_packets);
            }
            None => {
                leftover.push(app);
                leftover.extend(iter);
                ctx.pool.recycle(out);
                break;
            }
        }
        ctx.pool.recycle(out);
    }
    if !leftover.is_empty() {
        ctx.pending_wg.entry(dest).or_default().extend(leftover);
    }
}

fn learn_addr(ctx: &mut ShardCtx, src: SocketAddr, id: Option<NodeId>) {
    if let Some(id) = id {
        let info = PeerInfo::new(id, src);
        ctx.table.insert(info.clone());
        ctx.peers.upsert(info);
        ctx.endpoints.insert(
            id,
            EndpointHint {
                declared: src,
                observed: Some(src),
                last_ok: Instant::now(),
            },
        );
        ctx.sybil.reward(id);
        ctx.table.touch_ok(id, 80_000);
    } else {
        // Synthesize a contact from the address so bootstrap PING fills the table.
        let mut bytes = [0u8; 32];
        match src.ip() {
            std::net::IpAddr::V4(v) => bytes[0..4].copy_from_slice(&v.octets()),
            std::net::IpAddr::V6(v) => bytes[0..16].copy_from_slice(&v.octets()),
        }
        bytes[30..32].copy_from_slice(&src.port().to_be_bytes());
        let id = NodeId(blake3::hash(&bytes).into());
        let info = PeerInfo::new(id, src);
        ctx.table.insert(info.clone());
        ctx.peers.upsert(info);
    }
}

fn peers_to_proto(peers: &[PeerInfo]) -> Vec<proto::Peer> {
    peers
        .iter()
        .take(MAX_FIND_NODE_PEERS)
        .map(|p| proto::Peer {
            peer_id: p.id.0.to_vec().into(),
            addrs: p
                .addrs
                .iter()
                .map(|a| proto::Addr {
                    multiaddr: format!("udp://{a}").into_bytes().into(),
                })
                .collect(),
            rtt_ms: p.rtt_ms,
            x25519_pubkey: p.x25519.map(|x| x.to_vec().into()).unwrap_or_default(),
        })
        .collect()
}

fn peers_from_proto(peers: &[proto::Peer]) -> Vec<PeerInfo> {
    peers
        .iter()
        .filter_map(|p| {
            let id = NodeId::from_bytes(&p.peer_id)?;
            let addr = p.addrs.first().and_then(|a| parse_multiaddr(&a.multiaddr))?;
            let mut info = PeerInfo::new(id, addr);
            if p.x25519_pubkey.len() == 32 {
                let mut x = [0u8; 32];
                x.copy_from_slice(&p.x25519_pubkey);
                info.x25519 = Some(x);
            }
            Some(info)
        })
        .collect()
}

fn parse_multiaddr(raw: &[u8]) -> Option<SocketAddr> {
    let s = std::str::from_utf8(raw).ok()?;
    let s = s.strip_prefix("udp://").unwrap_or(s);
    s.parse().ok()
}

fn next_corr(ctx: &mut ShardCtx) -> u32 {
    let c = ctx.next_corr;
    ctx.next_corr = ctx.next_corr.wrapping_add(1);
    if ctx.next_corr == 0 {
        ctx.next_corr = 1;
    }
    c
}

/// Used by tests that need XOR-local ownership without a live socket.
pub fn owns_key(self_id: NodeId, key: &Key, shard: u32, shard_count: u32) -> bool {
    shard_id(&self_id, key, shard_count) == shard
}

const _: usize = HEADER_LEN;
