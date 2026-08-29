//! Raw UDP PING/PONG against a running node (wire-protocol header + Protobuf).
//!
//! ```bash
//! cargo run --example ping
//! ```

use molia::codec::{decode_body, encode_ping, Header, MessageType};
use molia::proto;
use molia::{Identity, Node, NodeConfig};
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    let sock = UdpSocket::bind("127.0.0.1:0").expect("client bind");
    sock.set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");

    let mut buf = [0u8; 128];
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let n = encode_ping(7, now, &mut buf).expect("encode");
    sock.send_to(&buf[..n], node.local_addr()).expect("send");

    let mut reply = [0u8; 256];
    let (m, src) = sock.recv_from(&mut reply).expect("recv");
    let header = Header::decode(&reply[..m]).expect("header");
    let pong = decode_body::<proto::Pong>(&reply[..m]).expect("pong");

    println!("PING {} -> {}", sock.local_addr().unwrap(), node.local_addr());
    println!(
        "PONG from {} type={:?} corr={} ts={}",
        src, header.ty, header.correlation, pong.now_unix_ms
    );
    assert_eq!(header.ty, MessageType::Pong);
    assert_eq!(header.correlation, 7);
}
