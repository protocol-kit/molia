# Advanced Features

This directory contains documentation on advanced, platform-specific optimizations and optional features.

## Documents

### [Linux eBPF Optimization](linux-reuseport-ebpf.md)
Linux-specific fast path using `SO_REUSEPORT` with reuseport eBPF for WireGuard packet steering. Covers:

**Problem**: With multiple shard sockets, kernel RSS may not route WireGuard Data messages to the correct shard (the one owning the session).

**Solution**: Attach an eBPF program to the reuseport group that:
- Peeks into UDP payload to read WireGuard header
- For **Data** messages (type 4): extracts `receiver_index` and steers to owning shard
- For **Initiation/Cookie** (type 1/3): hashes 5-tuple to a handshake shard
- Fallback: kernel RSS if parsing fails

**Prerequisites**:
- Linux 5.3+ kernel
- `BPF_PROG_TYPE_SK_REUSEPORT` support
- `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` and hash map
- CAP_BPF or bpffs + loader privileges

**Implementation**:
- eBPF program: `wg_select()` with bounds-checked header parsing
- Maps: `socks` (sockarray), `rx_index_to_slot` (receiver_index → shard mapping)
- Userspace: populate maps on session creation, update on handshake completion
- Observability: counters for selections, fallbacks, map misses

**Benefits**:
- Near-zero userspace demux cost
- Direct kernel steering to the correct shard socket
- Preserves XOR locality and shared-nothing isolation
- No cross-core handoffs for WireGuard crypto

**Portability**:
- Linux-only; other platforms use userspace demux (see [I/O Design](../networking/io-design.md))
- Graceful fallback if eBPF not available or verifier rejects

---

## When to Use

- **Production Linux deployments** where maximum performance is required
- **High packet rates** (>100K pps) where userspace demux becomes a bottleneck
- **Multi-core servers** with many shards

## When to Skip

- **Non-Linux platforms** (macOS, Windows)
- **Development/testing** environments (userspace demux is simpler to debug)
- **Low traffic** scenarios (<10K pps) where overhead is negligible

---

## Related

- **[WireGuard Integration](../security/wireguard-integration.md)**: General per-shard WireGuard design
- **[I/O Design](../networking/io-design.md)**: Portable demux fallback strategy
- **[Shared-Nothing Architecture](../architecture/shared-nothing-architecture.md)**: Shard selection and ownership

---

[← Back to Documentation](../README.md)

