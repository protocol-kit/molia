//! Per-shard `WgEngine`: add peers, encode `receiver_index`, encapsulate/decapsulate.
//!
//! ```bash
//! cargo run --example wg_engine
//! ```

use molia::codec::encode_ping;
use molia::wg::{
    encode_receiver_index, parse_wg_header, shard_from_receiver_index, Decap, WgEngine,
};
use molia::Identity;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let a_id = Identity::generate();
    let b_id = Identity::generate();
    let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
    let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4002);

    let mut a = WgEngine::new(a_id.wg_secret.clone(), 0);
    let mut b = WgEngine::new(b_id.wg_secret.clone(), 3);
    let a_rx = a.add_peer(b.public(), Some(b_id.node_id()), Some(b_addr));
    let b_rx = b.add_peer(a.public(), Some(a_id.node_id()), Some(a_addr));

    println!(
        "A session index={a_rx:#010x} (shard {})",
        shard_from_receiver_index(a_rx)
    );
    println!(
        "B session index={b_rx:#010x} (shard {})",
        shard_from_receiver_index(b_rx)
    );
    assert_eq!(a_rx, encode_receiver_index(0, 1));
    assert_eq!(shard_from_receiver_index(b_rx), 3);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut rpc = [0u8; 64];
    let n = encode_ping(1, now, &mut rpc).unwrap();
    let inner = wrap_ipv4(&rpc[..n]);

    let mut out = vec![0u8; 2048];
    let mut scratch = vec![0u8; 65536];

    // First encapsulate emits handshake initiation (type 1).
    let hs_n = a
        .encapsulate_to(b_addr, b.public(), Some(b_id.node_id()), &inner, &mut out)
        .expect("initiation");
    let hs = parse_wg_header(&out[..hs_n]).unwrap();
    println!("A→B {} bytes WG type={}", hs_n, hs.ty);

    match b.decapsulate(a_addr, &out[..hs_n], &mut scratch) {
        Decap::Network { len } => {
            let resp = parse_wg_header(&scratch[..len]).unwrap();
            println!("B→A handshake response type={}", resp.ty);
            let resp_buf = scratch[..len].to_vec();
            let _ = a.decapsulate(b_addr, &resp_buf, &mut scratch);
        }
        other => panic!("expected handshake response, got {other:?}"),
    }

    // Session is up; encapsulate the RPC-bearing inner packet.
    let data_n = a
        .encapsulate_to(b_addr, b.public(), Some(b_id.node_id()), &inner, &mut out)
        .expect("data");
    let data = parse_wg_header(&out[..data_n]).unwrap();
    println!(
        "A→B data type={} receiver_index={:#010x} shard={}",
        data.ty,
        data.receiver_index,
        shard_from_receiver_index(data.receiver_index)
    );

    match b.decapsulate(a_addr, &out[..data_n], &mut scratch) {
        Decap::Plaintext { len } => {
            println!("B decapsulated {len} inner bytes");
            assert!(len >= 28);
            println!("OK  WgEngine handshake + data");
        }
        Decap::Network { len } => {
            // Cookie or leftover handshake — feed back and retry once.
            let extra = scratch[..len].to_vec();
            let _ = a.decapsulate(b_addr, &extra, &mut scratch);
            let data_n = a
                .encapsulate_to(b_addr, b.public(), Some(b_id.node_id()), &inner, &mut out)
                .expect("data retry");
            match b.decapsulate(a_addr, &out[..data_n], &mut scratch) {
                Decap::Plaintext { len } => {
                    println!("B decapsulated {len} inner bytes (after extra handshake)");
                    println!("OK  WgEngine handshake + data");
                }
                other => panic!("still no plaintext: {other:?}"),
            }
        }
        other => panic!("expected plaintext, got {other:?}"),
    }
}

fn wrap_ipv4(payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    ip[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    let mut udp = [0u8; 8];
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp);
    pkt.extend_from_slice(payload);
    pkt
}
