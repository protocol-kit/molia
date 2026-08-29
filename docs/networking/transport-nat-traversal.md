# Transport & NAT Traversal

This document details the transport stack and NAT traversal strategy for Molia DHT. It complements [I/O Design](io-design.md) (I/O paths), [WireGuard Integration](../security/wireguard-integration.md) (per-shard crypto/sessioning), and [Architecture Overview](../overview.md) §2 (Transport & NAT Traversal).

---

## 0) Scope & Goals

- UDP transport with userspace WireGuard for confidentiality/integrity.
- Fast, portable NAT traversal: direct first, hole‑punch if needed, relay as last resort.
- Maintain shared‑nothing sharding and zero‑alloc hot paths.
- Clear defaults and operability: tunable budgets, metrics, and safe fallbacks.

---

## 1) Transport Stack

- Base: UDP sockets per shard (`SO_REUSEPORT`).
- Security: userspace WireGuard per shard; see [WireGuard Integration](../security/wireguard-integration.md) (e.g., [BoringTun](https://github.com/cloudflare/boringtun)).
- RPC: [Wire Protocol](wire-protocol.md) header + Protobuf body over plaintext payloads after WG decapsulation. UDP provides framing (no extra length prefix).
- Multiplexing: logical streams by request correlation IDs; no kernel stream abstraction.
- Pacing: token buckets per peer and per `/24`; optional NIC pacing.

---

## 2) Session & Endpoint Management (WG)

- Pin sessions to shards by `receiver_index` or peer X25519 public key.
- NAT rebinding: update endpoint in place without moving shards.
- Keepalives 15–25 s; rekey ~2 min (configurable). Cookie reply gating under load.

---

## 3) Packet Framing & Limits

- Frame: fixed Wire Protocol header (`version`, `type`, `flags`, `qos`, `correlation`, `stream_id`) followed by a Protobuf body inside the WG payload; strict size checks. See [Wire Protocol](wire-protocol.md).
- Max wire payload: `min(local_mtu, path_mtu) − (IP+UDP+WG_overhead)`; clamp to avoid fragmentation.
- Vectored I/O for composing headers + payload; zero‑copy decode over borrowed slices.

---

## 4) NAT Classification & Discovery

- Techniques: endpoint reflection via rendezvous servers; compare observed external address.
- Heuristics to classify: full‑cone, restricted, port‑restricted, symmetric.
- Cache NAT type per node; use to select traversal path and keepalive cadence.

---

## 5) Hole Punching (UDP)

- Rendezvous: lightweight coordinators exchange encrypted endpoint hints and timing windows.
- Simultaneous open: both sides send timed SYN‑like bursts (WG initiation) to each other’s candidates.
- Consent tokens: short‑lived, signed tokens to throttle abuse and validate intent.
- Retry windows with jitter; abort early on verified direct path success.

---

## 6) Relays (TURN‑like) – Last Resort

- Minimal relay API: forward WG datagrams between two peers; no application visibility.
- Budgeting: cap relay egress per peer and globally; prioritize control traffic.
- Placement: region‑diverse set; select by latency and health; rotate periodically.

---

## 7) WebRTC DataChannels (Browser Fallback)

**Crate:** `--webrtc-gateway` is an HTTP thread plus one Sans-I/O ICE/DTLS/SCTP session (str0m) per accepted offer. No Tokio. DTLS uses vendored OpenSSL (`str0m` rust-crypto conflicts with BoringTun’s pinned `x25519-dalek`).

- Browser: role **Gateway (ICE)** → `createDataChannel("molia")` → wait for host candidates → `POST /rtc/offer` (raw SDP or JSON `{sdp}`) → set remote answer.
- Node: ICE-lite, host candidates on `0.0.0.0:0` (advertise `127.0.0.1` and a LAN IP; Firefox often rejects loopback-only).
- One DataChannel message = one RPC datagram (same 12-byte header + Protobuf as UDP). Replies write back on the channel.
- `POST /rpc` is an HTTP fallback with the same frame shape.
- Two-tab room signaling (`/room/…`) stays in-browser P2P; `webrtc_play` is that page without a DHT node; `webrtc_dc` is an in-process `dc_pair()` shim.

Page: [playgroud/webrtc/](../../playgroud/webrtc/). CLI: [cli.md](../cli.md).

---

## 8) Address Records & Reachability

- Records include: declared addresses, observed external addresses (by peers/relays), and proofs.
- Proof of reachability: recent successful handshake/echo timestamps, signed by reporter.
- Multiaddr format with tags for transport kind (udp+wg, webrtc) and priority hints.

---

## 9) Consent, Keepalives, and Freshness

- Keep NAT bindings fresh with periodic keepalives tuned to NAT type.
- Consent freshness: tokens expire ≤ 30 minutes; renew on successful authenticated traffic.
- Drop unauthenticated floods; cookie replies before expensive operations.

---

## 10) MTU & Path Discovery

- Black‑hole detection: retransmit with smaller sizes when ICMP is filtered.
- Opportunistic PMTU discovery on stable paths; cache per peer and decay on errors.
- Never fragment: encoder enforces hard ceiling derived from current PMTU.

---

## 11) Abuse Resistance (Transport Layer)

- Pre‑handshake: per‑IP and per `/24` token buckets; fixed CPU budget per tick.
- Post‑handshake: per‑peer rate limits; challenge on anomalies; quarantine misbehaving endpoints.
- Relay throttling: strict egress caps; shed low‑priority traffic when budget tight.

---

## 12) Observability & Alarms

- NAT: type distribution, keepalive success, punch success rate, relay utilization.
- Transport: RX/TX rates, batch sizes, drops by reason, PMTU changes.
- Security: cookie replies, handshake failures, suspected floods.
- Alarms: relay budget > 80%, punch success < target, handshake failure spike.

---

## 13) Defaults (Initial)

- Keepalive: 20 s; rekey: 2 min; consent token TTL: 30 min.
- Punch attempts: 2 windows × 250 ms jitter; relay budget ≤ 10% of egress.
- PMTU floor: 1200 bytes (safe for the wider Internet); cap payload accordingly.

---

## 14) Rollout & Compatibility

1. Direct UDP (plaintext or `--wg`); verify PMTU and keepalives.
2. Enable rendezvous hole punching; measure success matrix across NAT types.
3. Introduce relays with strict budgets; wire telemetry and alerts.
4. WebRTC: `--webrtc-gateway` ICE/DTLS/SCTP is in this crate; STUN/TURN for remote NATs is still browser-side / future.

---

## 15) Checklist (PR Gate)

- Direct paths established; no IP fragmentation; PMTU logic proven.
- Hole punching succeeds at target rate; fallbacks work; budgets enforced.
- Observability dashboards and alerts configured; load tests pass.

---

[← Back to Networking](README.md)
