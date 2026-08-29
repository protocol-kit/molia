//! Gateway shim: Molia RPC on a reliable DataChannel stand-in, forwarded to UDP.
//!
//! ```
//! [browser DC]  <->  [gateway]  <->  [UDP node]
//! ```
//!
//! ```bash
//! cargo run --example webrtc_dc
//! ```

use molia::codec::{decode_body, encode_message, encode_ping, Header, MessageType, Qos};
use molia::crypto::hash_value;
use molia::proto;
use molia::store::{now_unix, StoredRecord, KIND_IMMUTABLE};
use molia::webrtc::{accept_rpc, dc_pair, frame_rpc, multiaddr, DcEndpoint, WEBRTC_CHANNEL};
use molia::{Identity, Node, NodeConfig};
use std::net::UdpSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn main() {
    let node = Node::start(
        Identity::generate(),
        NodeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            shard_count: 1,
            plaintext: true,
            query_blind: false,
            ..NodeConfig::default()
        },
    )
    .expect("bind");

    let (browser, gateway) = dc_pair();
    let running = Arc::new(AtomicBool::new(true));
    let gw_thread = spawn_dc_gateway(gateway, node.local_addr(), running.clone());

    println!(
        "node {} @ {}  channel={}  {}",
        hex::encode(&node.node_id().0[..8]),
        node.local_addr(),
        WEBRTC_CHANNEL,
        multiaddr("local-dc")
    );

    let pong = rpc(&browser, &encode_local_ping(11));
    let h = frame_rpc(&pong).expect("pong frame").0;
    assert_eq!(h.ty, MessageType::Pong);
    assert_eq!(h.correlation, 11);
    let body = decode_body::<proto::Pong>(&pong).expect("pong body");
    println!("PING -> PONG corr={} ts={}", h.correlation, body.now_unix_ms);

    let value = b"hello-over-webrtc";
    let key = hash_value(value);
    let store = encode_store(21, value, key);
    let store_reply = rpc(&browser, &store);
    let sh = Header::decode(&store_reply).expect("store header");
    assert_eq!(sh.ty, MessageType::StoreResp);
    let sr = decode_body::<proto::StoreResp>(&store_reply).expect("store body");
    assert_eq!(sr.code, proto::store_resp::Code::Ok as i32);
    println!("STORE {} -> ok", hex::encode(key.0));

    let get = encode_find(22, key);
    let get_reply = rpc(&browser, &get);
    let gh = Header::decode(&get_reply).expect("find header");
    assert_eq!(gh.ty, MessageType::FindValueResp);
    let fv = decode_body::<proto::FindValueResp>(&get_reply).expect("find body");
    match fv.result {
        Some(proto::find_value_resp::Result::Record(bytes)) => {
            use prost::Message;
            let rec = proto::Record::decode(&bytes[..]).expect("record");
            println!("FIND_VALUE -> {}", String::from_utf8_lossy(&rec.value));
            assert_eq!(&rec.value[..], value);
        }
        other => panic!("expected record, got {other:?}"),
    }

    running.store(false, Ordering::Relaxed);
    let _ = gw_thread.join();
    println!("OK  WebRTC DataChannel shim delivered ping + put/get");
}

fn encode_local_ping(corr: u32) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let n = encode_ping(corr, 1, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

fn encode_store(corr: u32, value: &[u8], key: molia::Key) -> Vec<u8> {
    let rec = StoredRecord {
        key,
        value: value.to_vec(),
        sequence: 0,
        ttl_secs: 24 * 3600,
        not_before_unix: 0,
        owner_pubkey: Vec::new(),
        signature: Vec::new(),
        kind: KIND_IMMUTABLE,
        namespace: Vec::new(),
        salt: Vec::new(),
        stored_unix: now_unix(),
        cache: false,
    };
    let mut buf = vec![0u8; 512];
    let n = encode_message(
        &Header::request(MessageType::StoreReq, Qos::Coordination, corr),
        &proto::StoreReq {
            record: rec.encode().into(),
            admission_token: Default::default(),
            cost_stamp: Default::default(),
        },
        &mut buf,
    )
    .expect("store encode");
    buf.truncate(n);
    buf
}

fn encode_find(corr: u32, key: molia::Key) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let n = encode_message(
        &Header::request(MessageType::FindValueReq, Qos::Coordination, corr),
        &proto::FindValueReq {
            key: key.0.to_vec().into(),
            provider_limit: 16,
        },
        &mut buf,
    )
    .expect("find encode");
    buf.truncate(n);
    buf
}

fn rpc(browser: &DcEndpoint, datagram: &[u8]) -> Vec<u8> {
    assert!(accept_rpc(datagram));
    browser.send(datagram.to_vec()).expect("dc send");
    browser
        .recv_timeout(Duration::from_secs(2))
        .expect("dc reply")
}

fn spawn_dc_gateway(
    gw: DcEndpoint,
    node: std::net::SocketAddr,
    running: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("gateway udp");
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .expect("timeout");
        while running.load(Ordering::Relaxed) {
            if let Ok(msg) = gw.recv_timeout(Duration::from_millis(10)) {
                if accept_rpc(&msg) {
                    let _ = sock.send_to(&msg, node);
                }
            }
            let mut buf = [0u8; 2048];
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if accept_rpc(&buf[..n]) {
                    let _ = gw.send(buf[..n].to_vec());
                }
            }
        }
    })
}
