# I/O Design

This document specifies the I/O model for the Molia DHT implementation. It aligns with [Zero-Allocation Design](../architecture/zero-allocation-design.md) and [Shared-Nothing Architecture](../architecture/shared-nothing-architecture.md).

---

## 0) Objectives & Constraints

- Minimize syscalls and context switches via batching and per-core sharding.
- Zero-allocation on hot paths; fixed-capacity buffers from shard-local pools.
- Preserve XOR locality end-to-end; shard selection uses `msb_k(selfId XOR key)`.
- Transport security via optional userspace WireGuard (`--wg`, [BoringTun](https://github.com/cloudflare/boringtun)). Browser path is a separate HTTP + ICE thread, not the shard loop.
- Cross-platform: Linux (first-class), macOS (kqueue), Windows (future).

---

## 1) Architecture Overview

- One event loop per shard pinned to a core (shared-nothing).
- One UDP socket per shard using `SO_REUSEPORT`. Kernel RSS steers flows.
- Demultiplex within node by `shard_id = msb_k(selfId XOR key)` to preserve XOR locality.
- Userspace WireGuard processes packets at the shard, avoiding cross-core handoffs.

---

## 2) Receive Path (RX)

- Batch receive: prefer `recvmmsg()` on Linux, kqueue readiness + manual batching on macOS.
- Buffers: MTU-aligned, fixed-size slices from shard-local pool; DMA-friendly alignment.
- WireGuard: decrypt in-place (userspace), validate, then pass decrypted payload to decoder.
- Decode: zero-copy over borrowed slices; preflight length checks before accessing payload.
- Queueing: classify to control/coordination/hints rings; avoid cross-shard forwarding on hot path.

---

## 3) Transmit Path (TX)

- Encode responses into preallocated output buffers; use vectored I/O to avoid concatenation.
- WireGuard: encrypt in-place; account for WG overhead when sizing payloads.
- Batch send: prefer `sendmmsg()`; set packet pacing where supported; otherwise timer-based pacing.
- Recycling: return buffers to pool immediately after send completion.

---

## 4) Batching & Syscall Strategy

- Target batch size: 16–64 packets per drain cycle (adaptive by load and latency).
- Use `recvmmsg/sendmmsg` on Linux. Evaluate UDP GSO/GRO if available for improved throughput.
- On macOS, use kqueue with readiness batching; coalesce up to the batch target per loop.
- Optional: io_uring for RX/TX if it measurably reduces syscall overhead without complicating zero-alloc.

---

## 5) Buffer Management

- Per-shard buffer pools (fixed-size and a small set of large buffers) with lock-free freelists.
- Align to cache lines; pad ring entries to avoid false sharing.
- Typical sizes: network MTU-class buffers for messages; jumbo buffers reserved for exceptional payloads.
- Lifetimes: RX buffers valid during handler; copy only when retention is necessary.

---

## 6) MTU & Fragmentation

- Compute allowed payload: `min(local_mtu, path_mtu_estimate) - (IP + UDP + WireGuard_overhead)`.
- Avoid IP fragmentation; clamp application payload accordingly.
- Periodically validate PMTU; backoff on ICMP “frag needed” or inferred loss patterns.

---

## 7) WireGuard Integration

- Library: userspace WireGuard (e.g., [BoringTun](https://github.com/cloudflare/boringtun)).
- Placement: one WG worker per shard; pin threads to the same core where possible.
- Batching: feed decrypt/encrypt in small batches to leverage SIMD; avoid large latency spikes.
- Keys/Identity: bind WireGuard keys to NodeID; rotate per operational policy outside the hot path.

---

## 8) Pacing, Shaping, and Backpressure

- Token buckets per peer and per `/24` for outbound sends; reserve headroom for control traffic.
- Separate rings by QoS: Control (highest), Coordination (normal), Hints (best-effort).
- Non-blocking enqueue: `Enqueued | Coalesced | Dropped{Full|TTLExpired}`; never block shard loop.
- Inbound overload: drop hints first; outbound overload: defer low-priority sends.

---

## 9) NAT Traversal I/O

- Keepalives to maintain NAT mappings; cadence adaptive to NAT type.
- Hole punching: coordinate timing with rendezvous; exploit simultaneous open when possible.
- Relay fallback: bounded budget; monitor relay egress and shed under pressure.

---

## 10) Loss, Latency, and Timeouts

- Adaptive per-peer SRTT/RTTVAR; timeouts `T = clamp(2×SRTT, 50–600 ms)` with jitter.
- Retries: single retry per peer per lookup with cooldown; demote noisy peers.
- ECN/DSCP (optional) to prioritize control traffic where networks honor markings.

---

## 11) Observability

- Per-shard metrics: RX/TX packets, bytes, batch size histograms, syscall counts, queue depths, drops by reason.
- WireGuard: decrypt/encrypt ops, failures, and per-batch timing.
- Alarms: sustained control-queue > 50% capacity; any control drops; coordination drops > 5% over 1 min.
- Tracing: minimal hot-path annotations; sample at low rate under load.

---

## 12) Portability

- Linux: `SO_REUSEPORT`, `recvmmsg/sendmmsg`, optional GSO/GRO, optional io_uring.
- macOS: kqueue readiness loops; `SO_REUSEPORT` equivalent; no GSO/GRO.
- Windows (future): I/O completion ports; map batching semantics to posted recv/send lists.

---

## 13) Testing & Verification

- Synthetic load: generate RX/TX at line-rate; assert 0 allocations in steady state.
- Failure injection: drop/delay batches; verify timeouts and backpressure responses.
- NAT matrix: emulate full-cone/symmetric; measure keepalive efficacy and punch success.
- PMTU scenarios: validate clamping and recovery after MTU changes.

---

## 14) Rollout Plan

1. Implement per-shard sockets with `SO_REUSEPORT` and batch RX/TX.
2. Integrate userspace WireGuard per shard; validate MTU and overhead handling.
3. Add pacing and QoS rings; enforce drop/coalescing policies.
4. Wire observability; establish alert thresholds.
5. Validate on Linux; add macOS kqueue path; benchmark; tune batch sizes.

---

## 15) Checklist (PR Gate)

- Per-shard sockets and batch I/O in place.
- Zero-alloc buffers on hot paths; pool recycling verified.
- WireGuard integrated; MTU clamping correct; no IP fragmentation under normal ops.
- Pacing/backpressure policies enforced; no shard-loop blocking.
- Metrics/alerts in place; tests cover loss/NAT/PMTU.

---

## 16) Persistent Peerstore I/O

- **Per-shard layout**
  - Directory per shard: `peerstore/shard-<id>/`.
  - Files: `snapshot.bin` (compact state), `wal.log` (append-only peers + DHT records), `compaction.tmp` (atomic replace).
  - Frames: `len:u32 | type:u8 | payload | crc32:u32`. type 1 peer upsert, 2 peer tombstone, 3 protobuf `Record`.

- **Write path (non-blocking)**
  - Mutations (insert/update/evict/score) enqueue a small POD record to a shard-local bounded SPSC ring.
  - A shard-local writer task batches records (e.g., up to 4 MiB or 50 ms) and writes with `writev`.
  - Durability levels (configurable):
    - `async` (no fsync): fastest, crash may lose last batch.
    - `group` (default): `fdatasync` every Δt (e.g., 100 ms) or after N MiB.
    - `strict`: `fdatasync` after each batch when latency budget allows.
  - Preallocate with `fallocate` in large chunks to avoid fragmentation; track file offset atomically.

- **Compaction & snapshots**
  - Trigger when `wal.log` exceeds `X` MiB or `dead/live` ratio > threshold.
  - Build `compaction.tmp` from in-memory state; fsync file, then atomic rename to `snapshot.bin`.
  - Truncate or rotate `wal.log` after ensuring snapshot is durable; write WAL header with epoch.

- **Crash recovery**
  - Load `snapshot.bin` if present; then replay `wal.log` tail, verifying checksums.
  - Ignore trailing partial records; on checksum failure, stop at last valid offset and raise an alert.
  - If neither snapshot nor valid WAL exists, start empty and mark peerstore as cold.

- **Backpressure & isolation**
  - If writer falls behind, drop least-important mutation kinds first (e.g., soft score updates) while preserving critical events (new peers, tombstones).
  - Never block shard network loop on disk; the writer is a cooperative low-priority drain on the same shard event loop (no separate async runtime).

- **Portability notes**
  - Linux: prefer `fdatasync`; macOS: `F_FULLFSYNC` when `strict` is requested; Windows (future): `FlushFileBuffers`.
  - Use buffered I/O; avoid `O_DIRECT` unless benchmarks prove net wins for our sizes.

- **Telemetry**
  - Bytes written, batches/sec, batch size histogram, fsync latency histogram, compaction duration, WAL size, last valid offset.
  - Recovery metrics: records replayed, tail bytes discarded, checksum errors.

- **Testing**
  - Power-failure simulation: kill during write/flush/rename; verify recovery.
  - Corruption injection: flip bits in WAL; confirm detection and clean stop.
  - High-churn soak: ensure writer keeps up without impacting shard latency.

---

[← Back to Networking](README.md)

