# Molia DHT

A high-performance, production-ready Distributed Hash Table (DHT) implementation designed for Internet-scale deployment with security, privacy, and operability as first-class concerns.

IMPORTANT: Project in research and design phase. Drafts only.

---

## Overview

Molia is a modern DHT built on Kademlia's XOR metric with significant enhancements for production use:

- **Sub-second lookups** at Internet scale (median ≤300ms, P95 ≤1s)
- **Zero-allocation hot paths** for predictable performance
- **Shared-nothing architecture** for maximum scalability
- **WireGuard-based transport security** with built-in Sybil resistance
- **First-class NAT traversal** and browser support
- **Privacy-preserving lookups** with query blinding

### Key Features

- **Security**: Ed25519 identity, WireGuard encryption, proof-of-work admission control
- **Performance**: Lock-free per-core sharding, zero-allocation design, batched I/O
- **Reliability**: Erasure coding, adaptive replication, graceful degradation
- **Operability**: Prometheus metrics, structured logging, rolling upgrades
- **Privacy**: Query blinding, two-hop relays, minimal metadata exposure

---

## Quick Links

- **[Architecture Overview](docs/overview.md)** - Start here for the big picture
- **[Implementation Roadmap](docs/overview.md#13-implementation-roadmap-12-weeks)** - 12-week development plan
- **[API Reference](docs/overview.md#11-api-sketch-client-library)** - Client library interface

---

## Documentation Structure

### Core Concepts
- **[Kademlia Algorithm](docs/core/kademlia.md)** - DHT fundamentals, XOR metric, k-buckets, iterative lookups

### Architecture
- **[Shared-Nothing Architecture](docs/architecture/shared-nothing-architecture.md)** - Per-core sharding, message passing, isolation
- **[Zero-Allocation Design](docs/architecture/zero-allocation-design.md)** - Hot-path optimization, buffer pools, bounded containers

### Networking
- **[I/O Design](docs/networking/io-design.md)** - Event loops, batch I/O, buffer management, peerstore persistence
- **[Transport & NAT Traversal](docs/networking/transport-nat-traversal.md)** - UDP stack, hole punching, relay strategies, WebRTC fallback
- **[Wire Protocol](docs/networking/wire-protocol.md)** - RPC messages, encoding, versioning, negotiation

### Security
- **[WireGuard Integration](docs/security/wireguard-integration.md)** - Per-shard crypto, session management, MTU handling
- **[Sybil Resistance](docs/security/sybil-resistance.md)** - Proof-of-work, admission tokens, rate limiting, behavioral scoring

### Advanced
- **[Linux eBPF Optimization](docs/advanced/linux-reuseport-ebpf.md)** - SO_REUSEPORT with eBPF steering for WireGuard packet demux

---

## Design Principles

1. **Security by Default**: Silent before handshake, authenticated all traffic, proof-of-work gated
2. **Zero-Trust Networking**: Every peer is untrusted; validate everything
3. **Fail Gracefully**: Degrade performance under attack, never fail open
4. **Observable**: Rich metrics, structured logs, distributed tracing
5. **Upgradeable**: Rolling protocol upgrades, feature negotiation
6. **Privacy-Aware**: Minimize metadata leakage, support query blinding

---

## Technology Stack

- **Language**: Rust (recommended)
- **Crypto**: 
  - Identity: Ed25519 (ed25519-dalek)
  - Hashing: BLAKE3 (blake3)
  - Transport: WireGuard (boringtun)
- **Encoding**: Protocol Buffers (prost)
- **I/O**: tokio (per-shard single-threaded runtimes)
- **Storage**: Per-shard WAL with periodic compaction

---

## Getting Started

### Prerequisites
- Rust 1.70+ (recommended)
- Linux 5.3+ for eBPF features (optional)
- UDP connectivity (NAT traversal support included)

### Building
```bash
cargo build --release
```

### Running Tests
```bash
cargo test
cargo test --features allocation-tracking  # Verify zero-alloc paths
```

### Running a Node
```bash
./target/release/molia --bootstrap <seed-addrs>
```

---

## Performance Targets

- **Lookup Latency**: P50 ≤300ms, P95 ≤1s, P99 ≤2s
- **Throughput**: 100K+ lookups/sec per 8-core node
- **Hot Path**: Zero allocations in steady state
- **Per-Packet CPU**: ≤5μs median at 3.5 GHz
- **Churn Resilience**: 95%+ success rate at 30% nodes joining/leaving per minute

---

## Testing & Validation

### Test Scenarios
- **Churn Soak**: 30% join/leave rate, maintain ≥95% lookup success
- **Partition Heal**: Regional isolation recovery
- **Adversarial**: 20% Sybils near target prefix
- **NAT Matrix**: Full-cone, symmetric, restricted NAT types
- **Data Durability**: Random node failures with erasure-coded recovery

### Verification
- Zero-allocation tests with custom allocator tracking
- Fuzz testing of wire protocol and codecs
- Chaos engineering (network partitions, node crashes)
- Security audits of crypto and admission control

---

## Deployment Considerations

### Recommended Configuration
- **Shard Count**: Number of physical cores (default)
- **Bucket Size (K)**: 20 peers per bucket
- **Parallelism (α)**: 4 concurrent lookups
- **TTL**: 24h for mutable records, 5-30min for cached content
- **Erasure Coding**: 10:4 (data:parity) for blobs ≥1MB

### Observability
- Prometheus metrics endpoint
- Structured JSON logs with privacy scrubbers
- Optional distributed tracing (opt-in per request)
- Grafana dashboards for SLOs and regional heatmaps

### Security Hardening
- Enable proof-of-work with adaptive difficulty
- Configure per-/24 and per-ASN rate limits
- Set relay budget caps (≤10% egress recommended)
- Enable query blinding for privacy-sensitive deployments

---

## Contributing

Contributions are welcome! Please see our contribution guidelines (coming soon).

### Key Areas
- Protocol implementation and testing
- Security review and hardening
- Performance optimization
- Documentation improvements
- Platform support (Windows, mobile)

---

## References

- **Kademlia Paper**: Maymounkov & Mazières. "Kademlia: A Peer-to-Peer Information System Based on the XOR Metric." IPTPS 2002.
- **WireGuard**: [BoringTun userspace implementation](https://github.com/cloudflare/boringtun)
- **BLAKE3**: [Fast cryptographic hashing](https://github.com/BLAKE3-team/BLAKE3)

---

## License

This project is MIT-0 licensed for code and CC0-1.0 licensed for non-code content.

---

## Contact

- **Issues**: GitHub Issues (link TBD)
- **Discussions**: GitHub Discussions (link TBD)
- **Security**: security@example.com (update with actual contact)

---

*Built with a focus on security, performance, and operability for the modern Internet.*

