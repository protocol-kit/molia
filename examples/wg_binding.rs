//! Ed25519 identity binds the published X25519 WireGuard key (self-certifying NodeID).
//!
//! ```bash
//! cargo run --example wg_binding
//! ```

use molia::crypto::{verify_binding, Identity};

fn main() {
    let id = Identity::generate();
    let ed = id.verifying_key();
    let x = id.wg_public();
    let sig = id.binding_signature();

    println!("NodeID     {}", hex::encode(id.node_id().0));
    println!("Ed25519    {}", hex::encode(ed.as_bytes()));
    println!("X25519     {}", hex::encode(x.as_bytes()));
    println!("binding    {} bytes", sig.len());

    assert!(verify_binding(ed.as_bytes(), x.as_bytes(), &sig));
    assert!(!verify_binding(ed.as_bytes(), x.as_bytes(), &[0u8; 64]));
    println!("OK  Ed25519→X25519 binding verifies");
}
