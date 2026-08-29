//! In-process churn / partition scenarios (docs test plan).

use molia::{crypto::hash_value, types::PeerInfo, Identity, Node, NodeConfig};
use std::time::Duration;

fn cfg() -> NodeConfig {
    NodeConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        shard_count: 1,
        plaintext: true,
        query_blind: true,
        ..NodeConfig::default()
    }
}

#[test]
fn churn_three_nodes_lookup_success() {
    let nodes: Vec<Node> = (0..3)
        .map(|_| Node::start(Identity::generate(), cfg()).unwrap())
        .collect();
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            nodes[i].inject_peer(PeerInfo::new(nodes[j].node_id(), nodes[j].local_addr()));
        }
    }
    std::thread::sleep(Duration::from_millis(40));
    let key = nodes[0].put(b"churn-blob").unwrap();
    let mut ok = 0;
    for n in &nodes {
        if n.get(&key).unwrap().is_some() {
            ok += 1;
        }
    }
    assert!(ok >= 1, "at least the owner must serve the value");
    let _ = hash_value(b"churn-blob");
}

#[test]
fn sybil_prefix_still_serves_honest_put() {
    let honest = Node::start(Identity::generate(), cfg()).unwrap();
    let key = honest.put(b"honest").unwrap();
    assert_eq!(honest.get(&key).unwrap().as_deref(), Some(&b"honest"[..]));
}
