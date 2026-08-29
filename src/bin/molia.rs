use molia::store::MUTABLE_TTL_SECS;
use molia::webrtc::{spawn_gateway, DEFAULT_GATEWAY};
use molia::{Identity, Node, NodeConfig};
use std::collections::VecDeque;
use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

fn parse_key(hex: &str) -> molia::Key {
    let mut raw = hex::decode(hex.trim()).expect("hex key");
    raw.resize(32, 0);
    molia::Key::from_bytes(&raw).expect("key")
}

fn parse_pubkey(hex: &str) -> [u8; 32] {
    let raw = hex::decode(hex.trim()).expect("hex owner_pubkey");
    <[u8; 32]>::try_from(raw.as_slice()).expect("owner_pubkey must be 32 bytes")
}

fn print_value(v: &[u8]) {
    match String::from_utf8(v.to_vec()) {
        Ok(s) => println!("{s}"),
        Err(_) => println!("{}", hex::encode(v)),
    }
}

fn main() {
    let mut listen: SocketAddr = "0.0.0.0:4001".parse().unwrap();
    let mut bootstrap = Vec::new();
    let mut shards: u32 = thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    let mut put: Option<String> = None;
    let mut get: Option<String> = None;
    let mut plaintext = true;
    let mut webrtc_gateway: Option<SocketAddr> = None;
    let mut clear_peerstore = false;
    let mut new_identity = false;
    let mut data_dir = PathBuf::from(".");
    let mut relay = false;
    let mut put_mutable: Option<(String, String, String, u64)> = None;
    let mut announce: Option<(String, String)> = None;
    let mut providers: Option<String> = None;
    let mut get_mutable: Option<(String, String, String)> = None;
    let mut log_level: Option<String> = None;
    let mut ttl_secs: Option<u64> = None;
    let mut args: VecDeque<String> = env::args().skip(1).collect();
    while let Some(a) = args.pop_front() {
        match a.as_str() {
            "--listen" => {
                listen = args
                    .pop_front()
                    .expect("addr")
                    .parse()
                    .expect("listen addr");
            }
            "--bootstrap" => {
                let list = args.pop_front().expect("seed-addrs");
                for p in list.split(',') {
                    if !p.is_empty() {
                        bootstrap.push(p.parse::<SocketAddr>().expect("seed addr"));
                    }
                }
            }
            "--shards" => {
                shards = args.pop_front().expect("n").parse().expect("shards");
            }
            "--put" => put = Some(args.pop_front().expect("value")),
            "--get" => get = Some(args.pop_front().expect("hex key")),
            "--wg" => plaintext = false,
            "--clear-peerstore" => clear_peerstore = true,
            "--new-identity" => new_identity = true,
            "--data-dir" => {
                data_dir = PathBuf::from(args.pop_front().expect("path"));
            }
            "--relay" => relay = true,
            "--put-mutable" => {
                put_mutable = Some((
                    args.pop_front().expect("ns"),
                    args.pop_front().expect("salt"),
                    args.pop_front().expect("value"),
                    args.pop_front().expect("seq").parse().expect("seq"),
                ));
            }
            "--announce" => {
                announce = Some((
                    args.pop_front().expect("hex key"),
                    args.pop_front().expect("meta"),
                ));
            }
            "--providers" => providers = Some(args.pop_front().expect("hex key")),
            "--get-mutable" => {
                get_mutable = Some((
                    args.pop_front().expect("owner_pubkey"),
                    args.pop_front().expect("ns"),
                    args.pop_front().expect("salt"),
                ));
            }
            "--log-level" => log_level = Some(args.pop_front().expect("level")),
            "--ttl" => {
                ttl_secs = Some(args.pop_front().expect("secs").parse().expect("ttl"));
            }
            "--webrtc-gateway" => {
                webrtc_gateway = Some(match args.front() {
                    Some(s) if !s.starts_with('-') => args
                        .pop_front()
                        .unwrap()
                        .parse()
                        .expect("webrtc-gateway addr"),
                    _ => DEFAULT_GATEWAY.parse().unwrap(),
                });
            }
            "--help" => {
                eprintln!(
                    "molia --listen 0.0.0.0:4001 --bootstrap 127.0.0.1:4000 [--shards N] [--data-dir PATH] [--new-identity] [--clear-peerstore] [--wg] [--relay] [--log-level L] [--ttl SECS] [--put VAL] [--get HEX] [--put-mutable NS SALT VAL SEQ] [--get-mutable PUBKEY NS SALT] [--announce KEY META] [--providers KEY] [--webrtc-gateway [ADDR]]"
                );
                return;
            }
            other => {
                eprintln!("unknown arg {other}");
                std::process::exit(2);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(match log_level {
            Some(l) => tracing_subscriber::EnvFilter::new(l),
            None => tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        })
        .init();

    std::fs::create_dir_all(&data_dir).expect("data-dir");
    let identity_path = data_dir.join("identity.json");
    let peerstore_dir = data_dir.join("peerstore");
    if clear_peerstore && peerstore_dir.exists() {
        std::fs::remove_dir_all(&peerstore_dir).expect("clear peerstore");
        tracing::info!(path = %peerstore_dir.display(), "cleared peerstore");
    }

    let identity = if new_identity {
        let id = Identity::generate();
        id.save(&identity_path).expect("write identity");
        tracing::info!(path = %identity_path.display(), "wrote new identity");
        id
    } else {
        Identity::load_or_generate(&identity_path)
    };
    let cfg = NodeConfig {
        listen,
        shard_count: shards.max(1),
        bootstrap: bootstrap.clone(),
        plaintext,
        query_blind: true,
        two_hop_relay: relay,
        peerstore_dir: Some(peerstore_dir),
    };
    let node = Node::start(identity, cfg).expect("bind");
    tracing::info!(id = ?node.node_id(), addr = %node.local_addr(), "node started");

    let _gw = if let Some(addr) = webrtc_gateway {
        let gw = spawn_gateway(addr, Some(node.local_addr())).expect("webrtc-gateway bind");
        tracing::info!(addr = %gw.local, "webrtc gateway");
        println!("webrtc-gateway http://{}", gw.local);
        Some(gw)
    } else {
        None
    };

    let ttl = ttl_secs.unwrap_or(MUTABLE_TTL_SECS);
    let oneshot = put.is_some()
        || get.is_some()
        || put_mutable.is_some()
        || get_mutable.is_some()
        || announce.is_some()
        || providers.is_some();
    if oneshot {
        // Let bootstrap PINGs land before STORE / FIND_VALUE.
        thread::sleep(Duration::from_millis(if plaintext { 400 } else { 600 }));
    }

    if let Some(v) = put {
        let key = node.put_ttl(v.as_bytes(), ttl).expect("put");
        println!("{}", hex::encode(key.0));
        return;
    }
    if let Some(h) = get {
        match node.get(&parse_key(&h)).expect("get") {
            Some(v) => print_value(&v),
            None => {
                eprintln!("not found");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some((ns, salt, val, seq)) = put_mutable {
        let key = node
            .put_mutable_ttl(ns.as_bytes(), salt.as_bytes(), val.as_bytes(), seq, ttl)
            .expect("put-mutable");
        println!("{}", hex::encode(key.0));
        return;
    }
    if let Some((pk, ns, salt)) = get_mutable {
        match node.get_mutable(&parse_pubkey(&pk), ns.as_bytes(), salt.as_bytes()) {
            Ok(Some(v)) => print_value(&v),
            Ok(None) => {
                eprintln!("not found");
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        }
        return;
    }
    if let Some((key, meta)) = announce {
        node.announce_provider(parse_key(&key), meta.as_bytes())
            .expect("announce");
        println!("ok");
        return;
    }
    if let Some(h) = providers {
        let list = node.find_providers(&parse_key(&h)).expect("providers");
        if list.is_empty() {
            eprintln!("none");
            std::process::exit(1);
        }
        for (id, meta) in list {
            let m = match String::from_utf8(meta.clone()) {
                Ok(s) => s,
                Err(_) => hex::encode(meta),
            };
            println!("{} {m}", hex::encode(id.0));
        }
        return;
    }

    loop {
        thread::sleep(Duration::from_secs(30));
        let s = node.metrics();
        tracing::info!(rx = s.rx_packets, tx = s.tx_packets, lookups = s.lookups, "metrics");
    }
}
