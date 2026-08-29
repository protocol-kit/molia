//! Two local nodes: inject peers, put on A, look up from both.
//!
//! ```bash
//! cargo run --example two_nodes
//! ```

use molia::types::PeerInfo;
use molia::{Identity, Node, NodeConfig};
use std::thread;
use std::time::Duration;

fn start() -> Node {
    Node::start(
        Identity::generate(),
        NodeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            shard_count: 1,
            plaintext: true,
            query_blind: false,
            ..NodeConfig::default()
        },
    )
    .expect("bind")
}

fn main() {
    let a = start();
    let b = start();

    a.inject_peer(PeerInfo::new(b.node_id(), b.local_addr()));
    b.inject_peer(PeerInfo::new(a.node_id(), a.local_addr()));
    thread::sleep(Duration::from_millis(50));

    println!("A {} @ {}", hex::encode(&a.node_id().0[..8]), a.local_addr());
    println!("B {} @ {}", hex::encode(&b.node_id().0[..8]), b.local_addr());

    let key = a.put(b"shared-record").expect("put on A");
    println!("A stored {}", hex::encode(key.0));

    let from_a = a.get(&key).expect("get A");
    let from_b = b.get(&key).expect("get B");
    println!("A -> {:?}", from_a.as_ref().map(|v| String::from_utf8_lossy(v).into_owned()));
    println!("B -> {:?}", from_b.as_ref().map(|v| String::from_utf8_lossy(v).into_owned()));
}
