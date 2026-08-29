//! BoringTun handshake + data, no OS TUN. Inner payload is a Molia PING.
//! Session indexes use Molia's `receiver_index` layout (high 8 bits = shard).
//!
//! ```bash
//! cargo run --example wg_handshake
//! ```

use boringtun::noise::{Tunn, TunnResult};
use molia::codec::{decode_body, encode_ping, Header};
use molia::proto;
use molia::wg::{encode_receiver_index, parse_wg_header, shard_from_receiver_index};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let a_id = molia::Identity::generate();
    let b_id = molia::Identity::generate();
    let a_idx = encode_receiver_index(0, 1);
    let b_idx = encode_receiver_index(1, 1);

    let mut a = Tunn::new(
        a_id.wg_secret.clone(),
        b_id.wg_public(),
        None,
        Some(20),
        a_idx,
        None,
    )
    .expect("A");
    let mut b = Tunn::new(
        b_id.wg_secret.clone(),
        a_id.wg_public(),
        None,
        Some(20),
        b_idx,
        None,
    )
    .expect("B");

    println!(
        "A receiver_index={a_idx:#010x} shard={}",
        shard_from_receiver_index(a_idx)
    );
    println!(
        "B receiver_index={b_idx:#010x} shard={}",
        shard_from_receiver_index(b_idx)
    );

    let mut a2b = VecDeque::new();
    let mut b2a = VecDeque::new();
    let mut a_inner = VecDeque::new();
    let mut b_inner = VecDeque::new();

    let mut out = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(pkt) = a.format_handshake_initiation(&mut out, false) {
        print_wg("A→B handshake", pkt);
        a2b.push_back(pkt.to_vec());
    }
    pump(&mut a, &mut b, &mut a2b, &mut b2a, &mut a_inner, &mut b_inner);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut rpc = [0u8; 128];
    let rpc_n = encode_ping(7, now, &mut rpc).unwrap();
    let inner = wrap_ipv4(&rpc[..rpc_n]);

    let mut enc = vec![0u8; inner.len() + 256];
    match a.encapsulate(&inner, &mut enc) {
        TunnResult::WriteToNetwork(wg) => {
            print_wg("A→B data", wg);
            a2b.push_back(wg.to_vec());
        }
        other => panic!("encapsulate: {other:?}"),
    }
    pump(&mut a, &mut b, &mut a2b, &mut b2a, &mut a_inner, &mut b_inner);

    let got = b_inner.pop_front().expect("B should receive inner IPv4");
    let payload = &got[28..];
    let h = Header::decode(payload).expect("rpc header");
    let pongish = decode_body::<proto::Ping>(payload).expect("ping body");
    println!(
        "B inner RPC type={:?} corr={} ts={}",
        h.ty, h.correlation, pongish.now_unix_ms
    );
    println!("OK  PING survived WG ({} inner bytes)", got.len());
}

fn print_wg(label: &str, pkt: &[u8]) {
    let h = parse_wg_header(pkt).expect("wg header");
    println!(
        "{label}: {} bytes type={} receiver_index={:#010x} shard={}",
        pkt.len(),
        h.ty,
        h.receiver_index,
        shard_from_receiver_index(h.receiver_index)
    );
}

fn pump(
    a: &mut Tunn,
    b: &mut Tunn,
    a2b: &mut VecDeque<Vec<u8>>,
    b2a: &mut VecDeque<Vec<u8>>,
    a_inner: &mut VecDeque<Vec<u8>>,
    b_inner: &mut VecDeque<Vec<u8>>,
) {
    loop {
        let p1 = ingest(a, b2a, a2b, a_inner);
        let p2 = ingest(b, a2b, b2a, b_inner);
        if !(p1 || p2) {
            break;
        }
    }
}

fn ingest(
    me: &mut Tunn,
    incoming: &mut VecDeque<Vec<u8>>,
    outgoing: &mut VecDeque<Vec<u8>>,
    inner: &mut VecDeque<Vec<u8>>,
) -> bool {
    let mut any = false;
    while let Some(datagram) = incoming.pop_front() {
        any = true;
        let mut scratch = vec![0u8; 65536];
        let mut res = me.decapsulate(None::<IpAddr>, &datagram, &mut scratch);
        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    outgoing.push_back(packet.to_vec());
                    res = me.decapsulate(None::<IpAddr>, &[], &mut scratch);
                }
                TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                    inner.push_back(p.to_vec());
                    break;
                }
                TunnResult::Done | TunnResult::Err(_) => break,
            }
        }
    }
    any
}

/// BoringTun classifies inner packets by IP version nibble; wrap RPC so decap succeeds.
fn wrap_ipv4(payload: &[u8]) -> Vec<u8> {
    let total = 20 + 8 + payload.len();
    let mut ip = [0u8; 20];
    ip[0] = 0x45;
    ip[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = 17;
    ip[12..16].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 1).octets());
    ip[16..20].copy_from_slice(&Ipv4Addr::new(10, 0, 0, 2).octets());
    let mut sum = 0u32;
    for i in (0..20).step_by(2) {
        if i != 10 {
            sum += u16::from_be_bytes([ip[i], ip[i + 1]]) as u32;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    ip[10..12].copy_from_slice(&(!sum as u16).to_be_bytes());
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    udp[2..4].copy_from_slice(&54321u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp);
    pkt.extend_from_slice(payload);
    pkt
}
