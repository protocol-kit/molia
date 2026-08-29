# WireGuard Per‑Shard Integration

This document specifies how to integrate a userspace WireGuard engine per shard, aligned with [Shared-Nothing Architecture](../architecture/shared-nothing-architecture.md), [I/O Design](../networking/io-design.md), and [Architecture Overview](../overview.md) §6 (transport security).

---

## 0) Goals & Constraints

- One WireGuard instance per shard; no cross-shard locks or shared mutable state.

**Crate:** `--wg` sets `NodeConfig.plaintext = false`. Bootstrap PING/PONG stay plaintext and carry `x25519_pubkey`, `ed25519_pubkey`, and `binding_sig`. After keys, RPCs are dummy IPv4 + BoringTun; handshake-only UDP is queued and flushed. Mixed plaintext/`--wg` still accepts plaintext RPC. No OS TUN.
- Maintain XOR locality and per-core affinity; avoid cross-core handoffs on crypto.
- Zero-alloc hot path preserved; bounded batching for crypto without hurting tail latency.

---

## 1) Topology Per Shard

- Single WG engine instance pinned to the shard’s core.
- Shard-local maps for active sessions, handshake state, and timers.
- Shared read-only cookie secret across shards (generated at boot) for DoS cookies.

---

## 2) Identity & Key Binding

- Node identity remains Ed25519; NodeID = BLAKE3(pubkey).
- Publish an X25519 WireGuard public key in peer records, signed by the Ed25519 identity.
- On first packet/handshake from a peer, verify Ed25519→X25519 binding once and cache the result.

---

## 3) Data Path

- RX: UDP `recvmsg/recvmmsg` → WG `decapsulate()` → plaintext RPC decoder.
- TX: RPC encoder → WG `encapsulate(peerId, payload)` → UDP `sendmmsg`.
- Handle cookie reply requests immediately in RX before heavy work.
- Batch encrypt/decrypt in bursts of 8–32 packets to leverage SIMD without harming tail.

---

## 4) Sockets & Sharding

- `SO_REUSEPORT` UDP socket per shard on the same port; RSS keeps flows on a shard.
- Demux and shard selection (state-aware):
  - Pre-handshake (Initiation/Cookie): hash(sender_index || first bytes of ephemeral_pubkey) to select a “handshake shard” and apply rate limits.
  - Post-handshake/Data: route by WireGuard `receiver_index` to the owning shard.
  - Receiver index strategy: encode `shardId` in the high bits to enable payload-only demux without a userspace map.
  - Linux advanced path: with `SO_REUSEPORT`, attach a reuseport eBPF that peeks the UDP payload to steer packets:
    - Initiation/Cookie → handshake shard (hash src IP:port).
    - Data/Response → shard derived from `receiver_index` (via bit encoding or BPF map).
  - Portable path: single UDP socket; userspace parses WG header and forwards buffers to shard queues using the same rules.
- Application demux uses `shard_id = msb_k(selfId XOR key)` for RPC-level ownership; WG engines remain per-shard to avoid contention.

---

## 5) Timers, Keepalives, Rekey

- Per-peer keepalive (e.g., 15–25 s) driven by shard timer wheel.
- Rekey cadence (e.g., 2 min) per WireGuard recommendations; backoff on failures.
- Quarantine abusive sources based on repeated handshake failures or invalid packets.

---

## 6) MTU & Overhead

- Effective MTU = `path_mtu − (IP + UDP + WireGuard_overhead)`.
- Clamp message sizes to avoid IP fragmentation; recompute on path change.
- Propagate new ceilings to encoders and lookup planners.

---

## 7) Persistence & Restart

- Sessions are ephemeral; re-handshake on process restart.
- Persist only the Ed25519→X25519 binding in the peerstore.
- Cookie secret is regenerated at boot (optionally persisted and rotated by policy).

---

## 8) Observability

- Metrics per shard: decaps/encaps counts, handshake success/fail, cookie replies, encrypt/decrypt latency histograms, MTU changes.
- Alerts: handshake failure spikes, cookie flood conditions, sustained decrypt failures.

---

## 9) Backpressure & DoS Handling

- Token buckets per source and per /24 on pre-handshake traffic.
- Reply-with-cookie under load; drop unauthenticated floods early.
- Bound crypto work per tick; never block shard loop on expensive operations.

---

## 10) Library Choice

- Use a userspace WireGuard implementation (e.g., Cloudflare’s BoringTun) and integrate its core without TUN; we provide UDP I/O and timers.
- Reference: [BoringTun (userspace WireGuard in Rust)](https://github.com/cloudflare/boringtun).

---

## 11) Bring‑Up Checklist

1. WG engine wrapper API per shard: add/remove peer, decapsulate, encapsulate.
2. Publish and verify Ed25519→X25519 binding in peer records.
3. Wire RX/TX to batch encrypt/decrypt; implement cookie replies.
4. Add keepalives and rekeys via shard timer wheel.
5. Clamp MTU; enforce no IP fragmentation; adjust encoders.
6. Add metrics, alerts; soak under churn and NAT scenarios.

---

## 12) Testing & Validation

- Handshake flood tests (cookie defense), NAT traversal mixes, churn under load.
- PMTU shifts; confirm clamping and behavior without fragmentation.
- Crash/restart: ensure re-handshake works and bindings persist.

---

[← Back to Security](README.md)
