//! Two `WgEngine`s over real UDP sockets (userspace WG, no TUN).
//!
//! ```bash
//! cargo run --example wg_udp
//! ```

use molia::wg::{parse_wg_header, Decap, WgEngine};
use molia::Identity;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

fn main() {
    let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    a_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    b_sock
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let a_id = Identity::generate();
    let b_id = Identity::generate();
    let mut a = WgEngine::new(a_id.wg_secret.clone(), 0);
    let mut b = WgEngine::new(b_id.wg_secret.clone(), 1);
    a.add_peer(b.public(), Some(b_id.node_id()), Some(b_addr));
    b.add_peer(a.public(), Some(a_id.node_id()), Some(a_addr));

    println!("A UDP {a_addr}  B UDP {b_addr}");

    let inner = wrap_ipv4(b"hello-over-wg");
    let mut out = vec![0u8; 2048];
    let mut scratch = vec![0u8; 65536];

    let n = a
        .encapsulate_to(b_addr, b.public(), Some(b_id.node_id()), &inner, &mut out)
        .expect("A encapsulate");
    a_sock.send_to(&out[..n], b_addr).unwrap();
    println!("A sent {} bytes ({})", n, wg_label(&out[..n]));

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got_plain = false;
    while Instant::now() < deadline && !got_plain {
        drain(&b_sock, &mut b, b_addr, a_addr, &mut scratch, &mut got_plain);
        drain(&a_sock, &mut a, a_addr, b_addr, &mut scratch, &mut got_plain);
        if !got_plain {
            if let Some(n) =
                a.encapsulate_to(b_addr, b.public(), Some(b_id.node_id()), &inner, &mut out)
            {
                a_sock.send_to(&out[..n], b_addr).unwrap();
            }
        }
    }
    assert!(got_plain, "handshake did not deliver inner packet");
    println!("OK  UDP WireGuard path delivered inner packet");
}

fn drain(
    sock: &UdpSocket,
    engine: &mut WgEngine,
    _self_addr: SocketAddr,
    peer: SocketAddr,
    scratch: &mut [u8],
    got_plain: &mut bool,
) {
    let mut buf = [0u8; 2048];
    while let Ok((n, src)) = sock.recv_from(&mut buf) {
        println!("  recv {} bytes {} ({})", n, src, wg_label(&buf[..n]));
        match engine.decapsulate(src, &buf[..n], scratch) {
            Decap::Network { len } => {
                let _ = sock.send_to(&scratch[..len], peer);
            }
            Decap::Plaintext { len } => {
                println!("  decapsulated {len} inner bytes");
                *got_plain = true;
            }
            Decap::Cookie(c) => {
                let _ = sock.send_to(&c, peer);
            }
            Decap::Drop => {}
        }
    }
}

fn wg_label(pkt: &[u8]) -> String {
    parse_wg_header(pkt)
        .map(|h| format!("WG type={} rx={:#x}", h.ty, h.receiver_index))
        .unwrap_or_else(|| "not WG".into())
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
    udp[0..2].copy_from_slice(&12345u16.to_be_bytes());
    udp[2..4].copy_from_slice(&54321u16.to_be_bytes());
    udp[4..6].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&ip);
    pkt.extend_from_slice(&udp);
    pkt.extend_from_slice(payload);
    pkt
}
