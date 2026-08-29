//! Molia DHT: shared-nothing shards, custom event loops, Protobuf RPCs.
//!
//! No Tokio (or any async runtime) is used on the data path.

pub mod codec;
pub mod crypto;
pub mod erasure;
pub mod event_loop;
pub mod lookup;
pub mod metrics;
pub mod nat;
pub mod node;
pub mod peerstore;
pub mod pool;
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/molia.v1.rs"));
}
pub mod relay;
pub mod routing;
pub mod shard;
pub mod store;
pub mod sybil;
pub mod types;
pub mod udp;
mod ice_rtc;
pub mod webrtc;
pub mod wg;

pub use crypto::Identity;
pub use node::Node;
pub use shard::NodeConfig;
pub use types::{Key, NodeId, ALPHA_DEFAULT, K_DEFAULT, K_MAX};

#[cfg(test)]
mod crate_tests {
    #[test]
    fn cargo_has_no_tokio() {
        let toml = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml"));
        assert!(!toml.contains("tokio"), "tokio must not appear in Cargo.toml");
    }
}
