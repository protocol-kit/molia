# Networking

This directory contains documentation on Molia's networking stack, transport protocols, and I/O design.

## Documents

### [I/O Design](io-design.md)
Specifies the I/O model aligned with shared-nothing and zero-allocation principles. Covers:
- Per-shard event loops and UDP sockets (`SO_REUSEPORT`)
- Batch receive/send (`recvmmsg`/`sendmmsg` on Linux)
- WireGuard integration for userspace crypto
- Buffer management: pools, alignment, recycling
- MTU handling and fragmentation avoidance
- QoS rings (Control, Coordination, Hints) with backpressure
- Peerstore persistence (per-shard WAL, compaction, crash recovery)

**Performance**: Zero allocations, batched syscalls, DMA-friendly buffers.

### [Transport & NAT Traversal](transport-nat-traversal.md)
Details the transport stack and NAT traversal strategies. Covers:
- UDP; optional userspace WireGuard (BoringTun, `--wg`)
- Session management and endpoint rebinding
- NAT classification (full-cone, restricted, symmetric)
- UDP hole punching with rendezvous coordination
- TURN-like relays as last resort (strict budgets)
- WebRTC ICE/DTLS/SCTP (`--webrtc-gateway`, str0m) for browsers
- MTU discovery and path MTU clamping
- Abuse resistance at transport layer

**Goal**: Direct connectivity first, hole-punch if needed, relay as last resort.

### [Wire Protocol](wire-protocol.md)
Defines the application-layer protocol (UDP, `--wg`, or WebRTC DataChannel). Covers:
- Fixed header: version, type, flags, QoS, correlation ID
- Message types: PING/PONG, NEGOTIATE, FIND_NODE, FIND_VALUE, STORE, ANNOUNCE_PROVIDER
- Protobuf schemas for all RPCs
- Negotiation and feature bits for rolling upgrades
- Timeouts, retries, and adaptive SRTT
- Chunking and streaming for large responses
- Privacy flags (probes for blinding)
- Error codes and backoff strategies

**Design**: Compact, extensible, transport-agnostic (UDP-first, adaptable to WebRTC).

---

## Integration

These three documents work together:
1. **I/O Design** describes *how* packets flow through the system (event loops, buffers, batching)
2. **Transport** describes *how* connectivity is established (NAT, sessions, keepalives)
3. **Wire Protocol** describes *what* messages are exchanged (RPCs, encoding, semantics)

All three are designed for zero-allocation hot paths and shared-nothing architecture.

---

[← Back to Documentation](../README.md)

