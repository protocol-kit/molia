//! Signaling + static page for the WebRTC playground.
//!
//! Prefer `--webrtc-gateway` on a node: that path runs ICE/DTLS/SCTP.
//! This example is HTTP signaling only (no DHT, no ICE answerer).
//!
//! Prefer the node flag:
//! ```bash
//! cargo run --bin molia -- --listen 127.0.0.1:4001 --shards 1 --webrtc-gateway
//! ```
//!
//! Standalone (no DHT node):
//! ```bash
//! cargo run --example webrtc_play
//! # open http://127.0.0.1:9080 in two tabs
//! ```

use molia::webrtc::{serve_gateway, DEFAULT_GATEWAY};

fn main() {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| DEFAULT_GATEWAY.into())
        .parse()
        .expect("bind addr");
    println!("Molia WebRTC playground  http://{addr}");
    println!("Open that URL in two tabs: Offerer in one, Answerer in the other.");
    serve_gateway(addr, None).expect("bind");
}
