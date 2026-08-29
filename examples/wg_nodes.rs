//! Two Molia nodes with `plaintext: false` and X25519 keys in peer records.
//!
//! WireGuard sessions are created on `inject_peer`. RPC put/get still needs a
//! completed handshake; this example prints identities and WG publics, then
//! stores locally (owner path) and shows metrics.
//!
//! ```bash
//! cargo run --example wg_nodes
//! ```

use molia::types::PeerInfo;
use molia::{Identity, Node, NodeConfig};

fn start() -> Node {
    Node::start(
        Identity::generate(),
        NodeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            shard_count: 1,
            plaintext: false,
            query_blind: false,
            ..NodeConfig::default()
        },
    )
    .expect("bind")
}

fn peer(node: &Node) -> PeerInfo {
    let mut info = PeerInfo::new(node.node_id(), node.local_addr());
    info.x25519 = Some(node.wg_public());
    info
}

fn main() {
    let a = start();
    let b = start();
    a.inject_peer(peer(&b));
    b.inject_peer(peer(&a));

    println!(
        "A id={} wg={} @ {}",
        hex::encode(&a.node_id().0[..8]),
        hex::encode(&a.wg_public()[..8]),
        a.local_addr()
    );
    println!(
        "B id={} wg={} @ {}",
        hex::encode(&b.node_id().0[..8]),
        hex::encode(&b.wg_public()[..8]),
        b.local_addr()
    );

    let key = a.put(b"wg-local").expect("put");
    let got = a.get(&key).expect("get");
    println!("A local STORE/FIND_VALUE -> {:?}", got.as_ref().map(|v| String::from_utf8_lossy(v).into_owned()));

    let m = a.metrics();
    println!(
        "A metrics rx={} tx={} wg_decap_ok={} wg_decap_fail={}",
        m.rx_packets, m.tx_packets, m.wg_decap_ok, m.wg_decap_fail
    );
}
