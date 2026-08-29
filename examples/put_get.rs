//! Single-node immutable put/get.
//!
//! ```bash
//! cargo run --example put_get
//! ```

use molia::{Identity, Node, NodeConfig};

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

    println!("node {} on {}", hex::encode(&node.node_id().0[..8]), node.local_addr());

    let key = node.put(b"hello from molia").expect("put");
    println!("stored key {}", hex::encode(key.0));

    let value = node.get(&key).expect("get").expect("found");
    println!("fetched {}", String::from_utf8_lossy(&value));
}
