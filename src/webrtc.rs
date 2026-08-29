//! Browser fallback: ICE/DTLS/SCTP (str0m) plus HTTP signaling.
//!
//! `--webrtc-gateway` accepts a browser SDP offer on `POST /rtc/offer`, runs
//! ICE/DTLS/SCTP, and maps DataChannel `molia` messages to the local UDP node
//! (same 12-byte header + Protobuf). `POST /rpc` remains an HTTP fallback.
//! Two-tab room signaling is unchanged.

use crate::codec::Header;
use crate::types::HEADER_LEN;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

pub const WEBRTC_KIND: &str = "webrtc";
pub const WEBRTC_CHANNEL: &str = "molia";
pub const DEFAULT_GATEWAY: &str = "127.0.0.1:9080";

const HTML: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/playgroud/webrtc/index.html"
));

/// Address-record tag: `/webrtc/<hint>`.
pub fn multiaddr(hint: &str) -> String {
    format!("/{WEBRTC_KIND}/{hint}")
}

/// One RPC datagram as it would ride a WebRTC DataChannel.
pub fn frame_rpc(datagram: &[u8]) -> Option<(Header, &[u8])> {
    let h = Header::decode(datagram)?;
    Some((h, &datagram[HEADER_LEN..]))
}

pub fn accept_rpc(datagram: &[u8]) -> bool {
    Header::decode(datagram).is_some()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignalKind {
    Offer,
    Answer,
    Ice,
}

/// Out-of-band signaling blob (SDP or an ICE candidate line).
#[derive(Clone, Debug)]
pub struct Signal {
    pub room: String,
    pub from: String,
    pub kind: SignalKind,
    pub body: String,
}

/// In-process reliable DataChannel stand-in (SCTP-like, ordered messages).
pub struct DcEndpoint {
    tx: Sender<Vec<u8>>,
    rx: Receiver<Vec<u8>>,
}

impl DcEndpoint {
    pub fn send(&self, msg: Vec<u8>) -> Result<(), mpsc::SendError<Vec<u8>>> {
        self.tx.send(msg)
    }

    pub fn recv_timeout(&self, d: Duration) -> Result<Vec<u8>, RecvTimeoutError> {
        self.rx.recv_timeout(d)
    }
}

/// Paired endpoints: browser shim ↔ gateway.
pub fn dc_pair() -> (DcEndpoint, DcEndpoint) {
    let (a_tx, b_rx) = mpsc::channel();
    let (b_tx, a_rx) = mpsc::channel();
    (
        DcEndpoint { tx: a_tx, rx: a_rx },
        DcEndpoint { tx: b_tx, rx: b_rx },
    )
}

/// HTTP signaling + playground page for browser DataChannels.
pub struct GatewayHandle {
    pub local: SocketAddr,
    join: Option<std::thread::JoinHandle<()>>,
}

impl GatewayHandle {
    pub fn join(&mut self) {
        if let Some(h) = self.join.take() {
            let _ = h.join();
        }
    }
}

/// Bind `listen` and serve the playground in a background thread.
///
/// When `node` is set, `POST /rtc/offer` runs ICE/DTLS/SCTP and `POST /rpc`
/// forwards a DataChannel-shaped RPC frame to the local UDP node.
pub fn spawn_gateway(listen: SocketAddr, node: Option<SocketAddr>) -> std::io::Result<GatewayHandle> {
    let listener = std::net::TcpListener::bind(listen)?;
    let local = listener.local_addr()?;
    let join = std::thread::Builder::new()
        .name("molia-webrtc-gw".into())
        .spawn(move || serve_listener(listener, node))?;
    Ok(GatewayHandle {
        local,
        join: Some(join),
    })
}

/// Block on the playground (used by `webrtc_play`).
pub fn serve_gateway(listen: SocketAddr, node: Option<SocketAddr>) -> std::io::Result<SocketAddr> {
    let listener = std::net::TcpListener::bind(listen)?;
    let local = listener.local_addr()?;
    serve_listener(listener, node);
    Ok(local)
}

fn serve_listener(listener: std::net::TcpListener, node: Option<SocketAddr>) {
    let rooms: Rooms = std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let rooms = rooms.clone();
                let _ = std::thread::spawn(move || {
                    if let Err(e) = handle_http(s, &rooms, node) {
                        tracing::debug!(error = %e, "webrtc gateway conn");
                    }
                });
            }
            Err(e) => tracing::warn!(error = %e, "webrtc gateway accept"),
        }
    }
}

#[derive(Default)]
struct Room {
    offer: String,
    answer: String,
    ice_offerer: Vec<String>,
    ice_answerer: Vec<String>,
}

type Rooms = std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Room>>>;

fn handle_http(
    mut stream: std::net::TcpStream,
    rooms: &Rooms,
    node: Option<SocketAddr>,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let (method, path, body) = read_request(&mut stream)?;
    if method == "OPTIONS" {
        return write_resp(&mut stream, 204, "text/plain", b"");
    }
    let (status, ctype, payload) = route(&method, &path, &body, rooms, node);
    write_resp(&mut stream, status, ctype, &payload)
}

/// Accept one DataChannel RPC datagram and wait for the matching UDP reply.
pub fn accept_rpc_to_node(node: SocketAddr, datagram: &[u8]) -> Option<Vec<u8>> {
    if !accept_rpc(datagram) {
        return None;
    }
    let want = Header::decode(datagram)?.correlation;
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(1500))).ok()?;
    sock.send_to(datagram, node).ok()?;
    let mut buf = [0u8; 2048];
    let deadline = std::time::Instant::now() + Duration::from_millis(1500);
    while std::time::Instant::now() < deadline {
        match sock.recv_from(&mut buf) {
            Ok((n, _)) => {
                if Header::decode(&buf[..n]).is_some_and(|h| h.correlation == want) {
                    return Some(buf[..n].to_vec());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => break,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => break,
        }
    }
    None
}

fn route(
    method: &str,
    path: &str,
    body: &[u8],
    rooms: &Rooms,
    node: Option<SocketAddr>,
) -> (u16, &'static str, Vec<u8>) {
    if method == "GET" && (path == "/" || path == "/index.html") {
        return (200, "text/html; charset=utf-8", HTML.as_bytes().to_vec());
    }
    if method == "POST" && path == "/rpc" {
        let Some(dest) = node else {
            return (503, "text/plain", b"no node".to_vec());
        };
        if !accept_rpc(body) {
            return (400, "text/plain", b"bad rpc".to_vec());
        }
        return match accept_rpc_to_node(dest, body) {
            Some(reply) => (200, "application/octet-stream", reply),
            None => (204, "text/plain", Vec::new()),
        };
    }
    if method == "POST" && path == "/rtc/offer" {
        let Some(dest) = node else {
            return (503, "text/plain", b"no node".to_vec());
        };
        let raw = match std::str::from_utf8(body) {
            Ok(s) => s,
            Err(_) => return (400, "text/plain", b"sdp must be utf-8".to_vec()),
        };
        return match crate::ice_rtc::accept_offer(&offer_sdp(raw), dest) {
            Ok(answer) => (200, "application/sdp", answer.into_bytes()),
            Err(e) => (400, "text/plain", e.into_bytes()),
        };
    }
    let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if parts.first() != Some(&"room") || parts.len() < 2 {
        return (404, "text/plain", b"not found".to_vec());
    }
    let name = parts[1].to_string();
    match (method, parts.get(2).copied(), parts.get(3).copied()) {
        ("DELETE", None, None) => {
            rooms.lock().unwrap().remove(&name);
            (204, "text/plain", Vec::new())
        }
        ("PUT", Some("offer"), None) => {
            let mut g = rooms.lock().unwrap();
            let r = g.entry(name).or_default();
            r.offer = String::from_utf8_lossy(body).into_owned();
            r.answer.clear();
            r.ice_offerer.clear();
            r.ice_answerer.clear();
            (204, "text/plain", Vec::new())
        }
        ("PUT", Some("answer"), None) => {
            let mut g = rooms.lock().unwrap();
            g.entry(name).or_default().answer = String::from_utf8_lossy(body).into_owned();
            (204, "text/plain", Vec::new())
        }
        ("GET", Some("offer"), None) => take_text(rooms, &name, |r| r.offer.clone()),
        ("GET", Some("answer"), None) => take_text(rooms, &name, |r| r.answer.clone()),
        ("POST", Some("ice"), Some(side)) => {
            let mut g = rooms.lock().unwrap();
            let r = g.entry(name).or_default();
            let line = String::from_utf8_lossy(body).into_owned();
            match side {
                "offerer" => r.ice_offerer.push(line),
                "answerer" => r.ice_answerer.push(line),
                _ => return (404, "text/plain", b"ice side".to_vec()),
            }
            (204, "text/plain", Vec::new())
        }
        ("GET", Some("ice"), Some(side)) => {
            let g = rooms.lock().unwrap();
            let Some(r) = g.get(&name) else {
                return (204, "text/plain", Vec::new());
            };
            let lines = match side {
                "offerer" => &r.ice_offerer,
                "answerer" => &r.ice_answerer,
                _ => return (404, "text/plain", b"ice side".to_vec()),
            };
            (200, "text/plain; charset=utf-8", lines.join("\n").into_bytes())
        }
        _ => (404, "text/plain", b"not found".to_vec()),
    }
}

fn offer_sdp(body: &str) -> String {
    let t = body.trim();
    if t.starts_with("v=") {
        return t.to_string();
    }
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(t) {
        if let Some(s) = v.get("sdp").and_then(|x| x.as_str()) {
            return s.to_string();
        }
    }
    t.to_string()
}

fn take_text(rooms: &Rooms, name: &str, f: impl Fn(&Room) -> String) -> (u16, &'static str, Vec<u8>) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        {
            let g = rooms.lock().unwrap();
            if let Some(r) = g.get(name) {
                let s = f(r);
                if !s.is_empty() {
                    return (200, "text/plain; charset=utf-8", s.into_bytes());
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return (204, "text/plain", Vec::new());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> std::io::Result<(String, String, Vec<u8>)> {
    use std::io::Read;
    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 512];
    loop {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
        if find_double_crlf(&buf).is_some() {
            break;
        }
        if buf.len() > 64 * 1024 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "headers too large",
            ));
        }
    }
    let header_end = find_double_crlf(&buf).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "bad request")
    })?;
    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.split("\r\n");
    let req = lines.next().unwrap_or("");
    let mut req_parts = req.split_whitespace();
    let method = req_parts.next().unwrap_or("").to_string();
    let path = req_parts.next().unwrap_or("/").to_string();
    let mut len = 0usize;
    for line in lines {
        let (k, v) = line.split_once(':').unwrap_or(("", ""));
        if k.eq_ignore_ascii_case("content-length") {
            len = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = buf[header_end + 4..].to_vec();
    while body.len() < len {
        let n = stream.read(&mut tmp)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&tmp[..n]);
    }
    body.truncate(len);
    Ok((method, path, body))
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn write_resp(
    stream: &mut std::net::TcpStream,
    status: u16,
    ctype: &str,
    body: &[u8],
) -> std::io::Result<()> {
    use std::io::Write;
    let reason = match status {
        200 => "OK",
        204 => "No Content",
        _ => "Error",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\nAccess-Control-Allow-Headers: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::encode_ping;

    #[test]
    fn maps_same_rpc_header() {
        let mut buf = [0u8; 64];
        let n = encode_ping(1, 9, &mut buf).unwrap();
        assert!(accept_rpc(&buf[..n]));
        let (h, _) = frame_rpc(&buf[..n]).unwrap();
        assert_eq!(h.correlation, 1);
    }

    #[test]
    fn dc_pair_delivers_rpc() {
        let (a, b) = dc_pair();
        let mut buf = [0u8; 64];
        let n = encode_ping(3, 1, &mut buf).unwrap();
        a.send(buf[..n].to_vec()).unwrap();
        let got = b.recv_timeout(Duration::from_millis(50)).unwrap();
        assert!(accept_rpc(&got));
        assert_eq!(multiaddr("tab-1"), "/webrtc/tab-1");
    }

    #[test]
    fn gateway_serves_playground() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let gw = spawn_gateway("127.0.0.1:0".parse().unwrap(), None).unwrap();
        let mut s = TcpStream::connect(gw.local).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        assert!(body.contains("Molia WebRTC playground"));
    }

    #[test]
    fn gateway_accepts_rpc_to_node() {
        use crate::codec::{encode_ping, Header, MessageType};
        use crate::crypto::Identity;
        use crate::node::Node;
        use crate::shard::NodeConfig;
        use std::io::{Read, Write};
        use std::net::TcpStream;

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
        .unwrap();
        let gw = spawn_gateway("127.0.0.1:0".parse().unwrap(), Some(node.local_addr())).unwrap();

        let mut ping = [0u8; 64];
        let n = encode_ping(99, 1, &mut ping).unwrap();
        let req = format!(
            "POST /rpc HTTP/1.1\r\nHost: localhost\r\nContent-Length: {n}\r\nConnection: close\r\n\r\n"
        );
        let mut s = TcpStream::connect(gw.local).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(&ping[..n]).unwrap();
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let split = raw.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let body = &raw[split + 4..];
        let h = Header::decode(body).expect("pong header");
        assert_eq!(h.ty, MessageType::Pong);
        assert_eq!(h.correlation, 99);
    }

    #[test]
    fn rtc_offer_rejects_bad_sdp() {
        use std::io::{Read, Write};
        use std::net::TcpStream;
        let gw = spawn_gateway(
            "127.0.0.1:0".parse().unwrap(),
            Some("127.0.0.1:1".parse().unwrap()),
        )
        .unwrap();
        let body = b"not-an-sdp-offer";
        let req = format!(
            "POST /rtc/offer HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let mut s = TcpStream::connect(gw.local).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        s.write_all(req.as_bytes()).unwrap();
        s.write_all(body).unwrap();
        let mut raw = String::new();
        s.read_to_string(&mut raw).unwrap();
        assert!(raw.starts_with("HTTP/1.1 400"), "{raw}");
    }
}
