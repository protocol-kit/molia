# Security

This directory contains documentation on Molia's security mechanisms, including transport security and abuse resistance.

## Documents

### [WireGuard Integration](wireguard-integration.md)
Specifies per-shard WireGuard integration for transport security. Covers:
- One WireGuard instance per shard (no shared state)
- Identity binding: Ed25519 identity → X25519 WireGuard key
- Data path: UDP → WireGuard decapsulate → RPC decoder
- Socket sharding with `SO_REUSEPORT` and RSS
- Demux strategies:
  - Pre-handshake: hash to handshake shard
  - Post-handshake: route by `receiver_index` (shard encoded)
  - Optional eBPF steering (Linux; see [../advanced/](../advanced/))
- Timers: keepalives, rekey cadence
- MTU clamping to avoid fragmentation
- DoS handling: cookie replies, token buckets

**Library**: [BoringTun](https://github.com/cloudflare/boringtun) (userspace WireGuard in Rust)

**Crate**: `--wg` intro PING/PONG stay plaintext (X25519 + binding sig); later RPCs encapsulate. Without `--wg`, RPC is plaintext UDP.

**Design target**: Silent by default; no response before valid handshake.

### [Sybil Resistance](sybil-resistance.md)
Mechanisms to resist Sybil attacks and general abuse. Covers:
- **Pre-handshake PoW**: Leverage WireGuard ephemeral public key as hashcash puzzle input
  - Server publishes `(nonce, difficulty)`; client solves before sending Initiation
  - Dynamic difficulty based on load, /24, ASN
- **Admission tokens**: Post-handshake tokens for rate budget and PoW relaxation
- **Operation-level cost stamps**: Hashcash for spam-sensitive ops (STORE, ANNOUNCE_PROVIDER)
- **Behavioral scoring**: Per-peer EWMA of responsiveness, correctness, equivocation
- **Rate limiting**: Pre- and post-handshake buckets per IP, /24, and peer
- **Integration**: Handshake shard performs PoW verify with zero alloc; cheap hash only

**Threat Model**: Adversary can spawn many identities, spoof metadata, attempt DoS.

**Defense-in-Depth**: PoW + cookies + tokens + rate limits + behavioral scoring.

### [WireGuard Example](wireguard-example.rs)
Illustrative BoringTun `Tunn` sketch for handshake and encapsulate/decapsulate. Production Molia feeds DHT RPC bytes into the same APIs — no OS TUN device.

---

## Defense Layers

1. **Pre-handshake**: Silent by default, PoW on ephemeral key, cookie challenges
2. **Handshake**: WireGuard mutual authentication, IP/ASN rate limits
3. **Post-handshake**: Admission tokens, per-peer quotas, cost stamps for ops
4. **Behavioral**: EWMA scoring, quarantine tiers, circuit breakers
5. **Network**: Per-/24 and per-ASN aggregation, relay budget caps

Each layer is stateless or low-state on the fast path to avoid DoS amplification.

---

## Related

- **[Transport](../networking/transport-nat-traversal.md)**: Abuse resistance at transport layer
- **[Wire Protocol](../networking/wire-protocol.md)**: Rate limiting and QoS enforcement
- **[Advanced/eBPF](../advanced/linux-reuseport-ebpf.md)**: Kernel-space packet steering for efficiency

---

[← Back to Documentation](../README.md)

