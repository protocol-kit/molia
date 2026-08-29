//! Signed mutable (named) records with a monotonic sequence.
//!
//! ```bash
//! cargo run --example mutable
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

    let key = node
        .put_mutable(b"profile", b"v1", b"alice", 1)
        .expect("seq 1");
    println!("mutable key {}", hex::encode(key.0));
    println!(
        "seq 1 -> {:?}",
        node.get(&key)
            .unwrap()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    );

    let key2 = node
        .put_mutable(b"profile", b"v1", b"alice-updated", 2)
        .expect("seq 2");
    assert_eq!(key, key2);
    println!(
        "seq 2 -> {:?}",
        node.get(&key)
            .unwrap()
            .map(|v| String::from_utf8_lossy(&v).into_owned())
    );
}
