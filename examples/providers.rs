//! Announce and look up provider records (who has the content, not the bytes).
//!
//! ```bash
//! cargo run --example providers
//! ```

use molia::crypto::hash_value;
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

    let key = hash_value(b"large-blob-not-stored-in-dht");
    node.announce_provider(key, b"chunk-0+size=1048576")
        .expect("announce");

    let found = node.find_providers(&key).expect("find");
    println!("content key {}", hex::encode(key.0));
    println!("providers: {}", found.len());
    for (id, meta) in found {
        println!(
            "  {} meta={}",
            hex::encode(&id.0[..8]),
            String::from_utf8_lossy(&meta)
        );
    }
}
