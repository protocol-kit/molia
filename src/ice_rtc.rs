//! ICE / DTLS / SCTP via str0m (Sans-I/O). One thread per accepted offer.

use crate::webrtc::accept_rpc_to_node;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};
use str0m::change::SdpOffer;
use str0m::crypto::from_feature_flags;
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, RtcConfig};

static CRYPTO: Once = Once::new();

fn install_crypto() {
    CRYPTO.call_once(|| {
        from_feature_flags().install_process_default();
    });
}

fn advertise_hosts(port: u16) -> Vec<SocketAddr> {
    let mut out = vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)];
    if let Ok(probe) = UdpSocket::bind("0.0.0.0:0") {
        if probe.connect("8.8.8.8:80").is_ok() {
            if let Ok(a) = probe.local_addr() {
                let host = SocketAddr::new(a.ip(), port);
                if !out.contains(&host) {
                    out.push(host);
                }
            }
        }
    }
    out
}

/// Accept a browser SDP offer, start ICE/DTLS/SCTP, return the SDP answer.
pub fn accept_offer(offer_sdp: &str, node: SocketAddr) -> Result<String, String> {
    install_crypto();
    let offer = SdpOffer::from_sdp_string(offer_sdp.trim())
        .map_err(|e| format!("sdp offer: {e}"))?;

    let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let bound = sock.local_addr().map_err(|e| e.to_string())?;
    let mut rtc = RtcConfig::new()
        .set_ice_lite(true)
        .build(Instant::now());
    for addr in advertise_hosts(bound.port()) {
        let c = Candidate::host(addr, "udp").map_err(|e| e.to_string())?;
        rtc.add_local_candidate(c);
    }

    let answer = rtc
        .sdp_api()
        .accept_offer(offer)
        .map_err(|e| format!("accept offer: {e}"))?;

    thread::Builder::new()
        .name("molia-webrtc-ice".into())
        .spawn(move || {
            if let Err(e) = drive(rtc, sock, node) {
                tracing::warn!(error = %e, "webrtc ice session ended");
            }
        })
        .map_err(|e| e.to_string())?;

    Ok(answer.to_sdp_string())
}

fn drive(mut rtc: str0m::Rtc, sock: UdpSocket, node: SocketAddr) -> Result<(), str0m::RtcError> {
    let mut buf = vec![0u8; 2000];
    let mut dc_id = None;
    loop {
        let timeout = loop {
            match rtc.poll_output()? {
                Output::Timeout(t) => break t,
                Output::Transmit(t) => {
                    let _ = sock.send_to(&t.contents, t.destination);
                }
                Output::Event(Event::IceConnectionStateChange(IceConnectionState::Disconnected))
                | Output::Event(Event::Closed) => return Ok(()),
                Output::Event(Event::ChannelOpen(id, label)) => {
                    tracing::info!(%label, "webrtc datachannel open");
                    dc_id = Some(id);
                }
                Output::Event(Event::ChannelClose(id)) => {
                    if dc_id == Some(id) {
                        dc_id = None;
                    }
                }
                Output::Event(Event::ChannelData(d)) => {
                    if let Some(reply) = accept_rpc_to_node(node, &d.data) {
                        if let Some(mut ch) = rtc.channel(d.id) {
                            let _ = ch.write(true, &reply);
                        }
                    }
                }
                Output::Event(Event::Connected) => {
                    tracing::info!("webrtc ice+dtls connected");
                }
                Output::Event(_) => {}
            }
        };

        let wait = timeout.saturating_duration_since(Instant::now());
        if wait.is_zero() {
            rtc.handle_input(Input::Timeout(Instant::now()))?;
            continue;
        }
        sock.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
        buf.resize(2000, 0);
        let input = match sock.recv_from(&mut buf) {
            Ok((n, source)) => {
                buf.truncate(n);
                Input::Receive(
                    Instant::now(),
                    Receive {
                        proto: Protocol::Udp,
                        source,
                        destination: sock.local_addr()?,
                        contents: buf.as_slice().try_into()?,
                    },
                )
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Input::Timeout(Instant::now())
            }
            Err(e) => return Err(e.into()),
        };
        rtc.handle_input(input)?;
    }
}
