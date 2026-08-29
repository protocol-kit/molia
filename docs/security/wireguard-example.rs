//! Illustrative BoringTun `Tunn` usage for handshake + encapsulate/decapsulate.
//! Production Molia feeds DHT RPC bytes into the same APIs (no OS TUN device).
//! See `wireguard-integration.md`.

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rand_core::OsRng;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr};

fn main() {
    // ---- Generate static keys for two peers: A (initiator) and B (responder)
    let a_sk = StaticSecret::random_from_rng(OsRng);
    let b_sk = StaticSecret::random_from_rng(OsRng);
    let a_pk = PublicKey::from(&a_sk);
    let b_pk = PublicKey::from(&b_sk);

    // ---- Build Tunn state machines (no PSK, keepalive 25s, no rate limiter)
    // index is an arbitrary u32 you choose per peer.
    let mut a = Tunn::new(a_sk, b_pk, None, Some(25), 0, None).expect("A Tunn::new");
    let mut b = Tunn::new(b_sk, a_pk, None, Some(25), 1, None).expect("B Tunn::new");

    // ---- In-memory "network" channels and "tun" queues
    // a2b_net/b2a_net simulate UDP between the peers.
    // a_tun/b_tun simulate the OS TUN interfaces (IP packets in/out).
    let mut a2b_net: VecDeque<Vec<u8>> = VecDeque::new();
    let mut b2a_net: VecDeque<Vec<u8>> = VecDeque::new();
    let mut a_tun: VecDeque<Vec<u8>> = VecDeque::new();
    let mut b_tun: VecDeque<Vec<u8>> = VecDeque::new();

    // ---- Kick off a handshake from A
    let mut out = vec![0u8; 2048];
    if let TunnResult::WriteToNetwork(pkt) = a.format_handshake_initiation(&mut out, false) {
        a2b_net.push_back(pkt.to_vec());
    }

    // ---- Pump the in-memory network until the handshake completes
    pump(&mut a, &mut b, &mut a2b_net, &mut b2a_net, &mut a_tun, &mut b_tun);

    // ---- Build a small dummy IPv4/UDP packet to send over the tunnel
    let inner = build_ipv4_udp(
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(10, 0, 0, 2),
        12345,
        54321,
        b"hello over boringtun".as_ref(),
    );

    // ---- Encapsulate on A (like writing to /dev/net/tun), producing a WG datagram
    let mut enc_buf = vec![0u8; inner.len() + 256]; // >= inner + 32 bytes headroom
    match a.encapsulate(&inner, &mut enc_buf) {
        TunnResult::WriteToNetwork(wg) => a2b_net.push_back(wg.to_vec()),
        other => panic!("unexpected encapsulate result: {:?}", other),
    }

    // ---- Pump again so B receives and decapsulates to its TUN queue
    pump(&mut a, &mut b, &mut a2b_net, &mut b2a_net, &mut a_tun, &mut b_tun);

    // ---- Verify the inner packet arrived at B
    let received = b_tun.pop_front().expect("B should receive inner packet");
    assert_eq!(inner, received);
    println!("OK ✅  B received {} bytes over the tunnel", received.len());
}

/// Move datagrams across the "wire" until there’s nothing left to do.
/// This processes handshake retries, keepalives, and data.
/// It follows the docs for `decapsulate`: if we get `WriteToNetwork`,
/// call again with an empty datagram until `Done`.
fn pump(
    a: &mut Tunn,
    b: &mut Tunn,
    a2b_net: &mut VecDeque<Vec<u8>>,
    b2a_net: &mut VecDeque<Vec<u8>>,
    a_tun: &mut VecDeque<Vec<u8>>,
    b_tun: &mut VecDeque<Vec<u8>>,
) {
    loop {
        let p1 = process_incoming(a, b2a_net, a2b_net, a_tun, "A");
        let p2 = process_incoming(b, a2b_net, b2a_net, b_tun, "B");
        if !(p1 || p2) {
            break;
        }
    }
}

fn process_incoming(
    me: &mut Tunn,
    incoming_net: &mut VecDeque<Vec<u8>>,
    outgoing_net: &mut VecDeque<Vec<u8>>,
    out_tun: &mut VecDeque<Vec<u8>>,
    who: &str,
) -> bool {
    let mut did_any = false;

    while let Some(datagram) = incoming_net.pop_front() {
        did_any = true;
        let mut scratch = vec![0u8; 65536];

        // parse the received WG/UDP datagram
        let mut res = me.decapsulate(None::<IpAddr>, &datagram, &mut scratch);

        loop {
            match res {
                TunnResult::WriteToNetwork(packet) => {
                    // handshake response, cookie, keepalive, or data that must be forwarded
                    outgoing_net.push_back(packet.to_vec());
                    // IMPORTANT: call again with empty datagram until Done (per docs)
                    res = me.decapsulate(None::<IpAddr>, &[], &mut scratch);
                }
                TunnResult::WriteToTunnelV4(inner, _src) => {
                    out_tun.push_back(inner.to_vec());
                    break;
                }
                TunnResult::WriteToTunnelV6(inner, _src) => {
                    out_tun.push_back(inner.to_vec());
                    break;
                }
                TunnResult::Done => break,
                TunnResult::Err(e) => {
                    eprintln!("{who} decap error: {e:?}");
                    break;
                }
            }
        }
    }

    did_any
}

/// Minimal IPv4/UDP packet builder (valid header & checksum, UDP checksum=0).
fn build_ipv4_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = 20 + 8 + payload.len();
    let mut ip = [0u8; 20];
    ip[0] = 0x45; // ver=4, ihl=5
    ip[1] = 0; // dscp/ecn
    ip[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // flags=DF
    ip[8] = 64; // ttl
    ip[9] = 17; // proto=UDP
    ip[10..12].copy_from_slice(&[0, 0]); // checksum zeroed for calc
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let cksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&cksum.to_be_bytes());

    let udp_len = 8 + payload.len();
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    udp[6..8].copy_from_slice(&0u16.to_be_bytes()); // checksum 0 (optional on IPv4)

    let mut pkt = Vec::with_capacity(total_len);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp);
    pkt.extend_from_slice(payload);
    pkt
}

fn ipv4_checksum(hdr: &[u8; 20]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        if i == 10 {
            continue; // checksum field itself
        }
        let word = u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        sum = sum.wrapping_add(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
