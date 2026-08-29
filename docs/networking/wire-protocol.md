# Wire Protocol

This document defines the Molia DHT wire protocol carried over UDP and protected by the WireGuard protocol (userspace, no TUN). It complements [I/O Design](io-design.md) and [WireGuard Integration](../security/wireguard-integration.md).

---

## 0) Layering & Scope

- Transport: UDP datagrams. One application message per datagram. Default is plaintext; `--wg` wraps after intro PING/PONG (see [WireGuard Integration](../security/wireguard-integration.md)).
- Browsers: same header + body on DataChannel `molia` or `POST /rpc` ([transport §7](transport-nat-traversal.md#7-webrtc-datachannels-browser-fallback)).
- Encoding: Protobuf for message bodies; strict size limits. No length prefix (UDP / SCTP message provides framing).
- Canonical schema: `proto/molia.proto` (built with `prost` + `protox`).

---

## 1) Framing & Header

Each datagram contains a fixed header followed by a Protobuf body.

Header (network byte order):
```text
u8  version      // start at 1
u8  type         // MessageType enum
u8  flags        // bit 0: is_response, bit 1: more_chunks, bit 2: probe, others reserved=0
u8  qos          // 0=control, 1=coordination, 2=hints
u32 correlation  // request/response correlation id
u32 stream_id    // 0 if unused; for long ops/streams
```

- No length field; total size = UDP datagram length.
- Max datagram size (application bytes) = `min(local_mtu, path_mtu) − (IP+UDP+WireGuard)`; encoder enforces ceiling.
- Unknown `version` or `type` → reply with ERROR UNSUPPORTED if authenticated, else drop.

---

## 2) Message Types (ids)

- 1 PING, 2 PONG
- 3 NEGOTIATE_REQ, 4 NEGOTIATE_RESP
- 5 FIND_NODE_REQ, 6 FIND_NODE_RESP
- 7 FIND_VALUE_REQ, 8 FIND_VALUE_RESP
- 9 STORE_REQ, 10 STORE_RESP
- 11 ANNOUNCE_PROVIDER_REQ, 12 ANNOUNCE_PROVIDER_RESP
- 250 TRACE_HINT (best‑effort), 251 CACHE_HINT (best‑effort)
- 255 ERROR

---

## 3) Protobuf Schemas (excerpt)

```proto
syntax = "proto3";
package molia.v1;

message Key32 { bytes v = 1; }           // 32 bytes
message PeerId { bytes v = 1; }          // 32 bytes (BLAKE3(pubkey))
message Addr   { bytes multiaddr = 1; }  // multiaddr bytes

message Capabilities {
  uint32 version = 1;                 // app version
  uint64 bitmap  = 2;                 // feature bits
  uint32 max_msg_bytes = 3;           // receiver’s hard ceiling
}

message Ping {
  uint64 now_unix_ms = 1;
  bytes x25519_pubkey = 2;   // --wg intro
  bytes ed25519_pubkey = 3;
  bytes binding_sig = 4;     // Ed25519 over molia-wg-bind-v1 ‖ ed ‖ x25519
}
message Pong {
  uint64 now_unix_ms = 1;
  bytes x25519_pubkey = 2;
  bytes ed25519_pubkey = 3;
  bytes binding_sig = 4;
}

message FindNodeReq { bytes target_id = 1; uint32 limit = 2; }
message FindNodeResp { repeated Peer peers = 1; }

message Peer {
  bytes peer_id = 1;                  // PeerId
  repeated Addr addrs = 2;            // reachable addresses (scoped)
  uint32 rtt_ms = 3;                  // optional hint
  bytes x25519_pubkey = 4;            // for --wg after FIND_NODE
}

message FindValueReq { bytes key = 1; uint32 provider_limit = 2; }
message FindValueResp {
  oneof result {
    bytes record = 1;                  // validated immutable/mutable record
    Providers providers = 2;           // when value not present
  }
  repeated Peer closer_peers = 3;      // k-closest hints
}

message Providers { repeated Provider providers = 1; }
message Provider  { bytes peer_id = 1; bytes meta = 2; }

message StoreReq {
  bytes record = 1;
  bytes admission_token = 2;
  bytes cost_stamp = 3;
}
message StoreResp { enum Code { OK=0; REJECTED=1; TOO_LARGE=2; INVALID=3; } Code code = 1; string reason = 2; }

message NegotiateReq { Capabilities want = 1; }
message NegotiateResp { Capabilities agreed = 1; }

message Error { enum Code {
  UNSPECIFIED=0; NOT_FOUND=1; BUSY=2; RATE_LIMITED=3; INVALID=4; TOO_LARGE=5; UNSUPPORTED=6; UNAUTHORIZED=7; INTERNAL=8;
} Code code = 1; string reason = 2; }
```

Notes:
- Records carry their own signatures; receivers validate before accept or relay.
- Admission tokens (if used) are included inside operation bodies that require them.

---

## 4) Negotiation & Feature Bits

- After `--wg` keys are known (intro PING/PONG), later RPCs are dummy-IPv4 + BoringTun. Mixed plaintext/`--wg` still accepts plaintext RPC.
- First app exchange after WG: NEGOTIATE (Req/Resp) to agree capabilities and max message size.
- Feature bits examples: 0=privacy_blinding, 1=two_hop_relay, 2=streaming_chunks, 3=erasure_hints.
- Nodes maintain multiple handlers to allow rolling upgrades.

---

## 5) Timeouts & Retries

- Request timeout per peer: `T = clamp(2×SRTT, 50–600 ms)` with jitter.
- One retry per peer per lookup after cooldown; demote on repeated failures.
- Overall lookup budget 1–2 s; stop when no closer peers or budget exhausted.

---

## 6) Chunking & Streaming

- Use `flags.more_chunks` to indicate additional chunks for large responses (providers, etc.).
- Bodies include optional `chunk_index`/`total_chunks` when applicable.
- No IP fragmentation; chunks respect negotiated `max_msg_bytes`.

---

## 7) Privacy & Blinding

- `flags.probe` marks decoy or neighbor‑probe requests for privacy blinding.
- Probes must be well‑formed and rate‑limited; receivers treat equally but may not cache results.

---

## 8) Rate Limiting & QoS

- `qos` guides scheduling: 0 control, 1 coordination, 2 hints.
- Enforced by token buckets per peer and per `/24` (see [I/O Design](io-design.md)).
- On RATE_LIMITED, send ERROR with optional retry_after_ms.

---

## 9) Errors & Backoff

- ERROR responses carry `Error.Code` and human‑readable reason (truncated to fit).
- For UNSUPPORTED, include the offending `type` or missing feature bit in the reason where feasible.

---

## 10) Validation & Safety

- Without `--wg`, accept plaintext RPC. With `--wg`, intro PING/PONG stay plaintext; later datagrams that are not WG or plaintext RPC are dropped.
- Enforce strict maximums on message sizes and repeated fields; reject oversize with TOO_LARGE.
- Decode Protobuf over borrowed slices; fail fast on malformed inputs.

---

## 11) Compatibility & Versioning

- `version` in header controls top‑level dispatch; NEGOTIATE agrees finer‑grained features.
- Nodes should support at least N−1 versions during rolling upgrades.

---

## 12) Limits (initial)

- Max datagram after WG: 1200 bytes safe floor (tunable by PMTU).
- Max peers per FindNodeResp: 16. Max providers per chunk: 32.
- Max closer_peers attached to FindValueResp: 8.

---

## 13) Observability

- Per‑type counters, failure codes, and per‑type latency histograms.
- Drop reasons: malformed, too_large, unsupported, rate_limited, budget_exhausted.

---

[← Back to Networking](README.md)

