# Zero-Allocation Design

This document specifies a zero-allocation (or strictly bounded-allocation) strategy for the Molia DHT implementation, defining concrete budgets, structures, APIs, and verification methods to keep the hot paths allocation-free in steady state.

---

## 0) Objectives & Definitions

- **Primary Objective**: Zero heap allocations on hot-path operations in steady state.
  - RX/TX network fast path (UDP packet → decode → route decision → encode → send).
  - Routing table lookups and updates (k-bucket maintenance, PNS selection, LRU touch).
  - Lookup loop step (merge/sort of candidates, stop condition checks).
- **Cold Path**: Initialization, table growth, occasional rebalancing, and error/slow-path handling may allocate, but are amortized and outside the latency-critical loop.
- **Bounded**: Where zero is not achievable, enforce strict, predeclared allocation bounds with capacity planning and compile-time checks.

---

## 1) Performance Budgets (Targets)

- **Per-packet (RX/TX)**: 0 allocations; ≤ 3 copies of small slices; ≤ 5 microseconds median CPU at 3.5 GHz core for typical packets.
- **Per lookup step**: 0 allocations; candidate heap within stack or fixed-capacity small buffer.
- **Per routing table touch**: 0 allocations for hit/move; amortized O(1) for rare evictions.
- **Buffers**: All network and codec buffers sourced from pools/arenas created at startup.

---

## 2) Hot-Path Map & Zero-Alloc Tactics

### 2.1 RX Path (UDP → Decode)
- Preallocate a ring of packet buffers sized to the PMTU ceiling (safe floor 1200 bytes; typical 1232–1400) and a few jumbo buffers for edge cases.
- Batch receive when platform supports it (Linux `recvmmsg`/`sendmmsg`; fall back to single I/O on other OSes) while reusing buffers.
- Decode directly from borrowed byte slices using a zero-copy codec.

### 2.2 Routing Decision
- Compute XOR distance and perform table lookups without allocation.
- Use fixed-capacity containers (stack-backed) for peer candidate sets.
- Maintain LRU indices within fixed-capacity bucket arrays (index swaps, no heap moves).

### 2.3 TX Path (Encode → UDP)
- Serialize into preallocated `BytesMut` or raw `&mut [u8]` from a buffer pool; return slices for immediate send.
- Vectored I/O (gather) to avoid concatenation; recycle buffers to pool after send completes.

---

## 3) Memory Management Strategies

- **Buffer Pools**: Central pool for RX/TX message buffers (fixed-size and a small set of large buffers). Simple lock-free freelist per core when possible.
- **Arenas (bump allocators)**: Short-lived arenas for per-lookup scratch (candidate sets, temporary maps). Entire arena reset after lookup completes; zero frees.
- **Borrowed Views**: Prefer `&[u8]`, `&str`, and `bytes::Bytes` for references over owned `Vec`/`String` in hot paths.
- **Small/Fixed Containers**: Use `arrayvec::ArrayVec`, `smallvec::SmallVec`, or `heapless` types for bounded collections on stack.
- **Slab Allocation for Long-Lived Objects**: `slab`/`slotmap` for peers and sessions to avoid frequent alloc/free churn; indices instead of pointers.

---

## 4) Data Structures (Hot Path)

- **K-Buckets**: `ArrayVec<PeerEntry, K_MAX>` with `K_MAX = 32` (default **K = 20**). LRU via index dance (swap-with-end or small ring of indices). No heap on touch/move.
- **Candidate Sets (Lookups)**: `SmallVec<[Candidate; 64]>` sized to expected frontier; switch to fixed-capacity binary heap if needed.
- **Bloom Filters / Hints**: Use `arrayvec`-backed bitsets or fixed-size bit arrays for path caching hints.
- **Peerstore**: Backed by `slab` for stable indices; buckets store indices, not owned structs.

---

## 5) Wire Encoding & Framing

- **Encoding**: Protocol Buffers (`prost`), matching the [Wire Protocol](../networking/wire-protocol.md).
- Zero-copy constraints on the hot path:
  - Restrict hot RPCs to `bytes` fields; decode into borrowed views using pooled `Bytes`.
  - Avoid `string` allocations on the hot path.
  - Encoder writes directly into a preallocated output buffer.
- Framing: fixed header + Protobuf body; no extra length prefix (UDP datagram size is the frame). Decoder operates over borrowed slices of the datagram after the header.
- Strict size limits to prevent oversized allocations; preflight length checks before building responses.

---

## 6) Networking (UDP)

- **Sockets**: Configure `SO_RCVBUF`/`SO_SNDBUF` generously; pin per-core sockets if applicable.
- **Batch I/O**: Use `recvmmsg`/`sendmmsg` on Linux; emulate batching with readiness loops elsewhere.
- **Buffers**: MTU-aligned fixed-size buffers from pool; recycle immediately after processing.
- **Timers**: Wheel or hierarchical timing wheels backed by fixed arrays to avoid heap per timer.

---

## 7) Routing Table & Lookup Algorithm

- **Bucket Maintenance**: LRU ping of oldest peer without allocation; evict on repeated failure.
- **PNS**: Store RTT and quality metrics inline; update using EWMA in-place.
- **Iterative Lookup**: Maintain frontier and visited sets in stack-bounded containers; no dynamic growth in steady state.
- **Concurrency (α)**: Preallocate request contexts (streams, buffers) up to α; reuse across steps.

---

## 8) Crypto & Hashing

- **BLAKE3**: Reuse hasher states or thread-local contexts; avoid allocating temporary buffers.
- **Ed25519**: Use libraries that do not allocate on sign/verify; reuse key material.
- **MAC/AEAD**: Select constructions with in-place seal/open APIs over borrowed slices.

---

## 9) Logging, Metrics, Tracing

- **Hot Path**: Avoid string formatting; use `tracing` with predeclared fields; sampling when under load.
- **Buffers**: Telemetry exporters use their own pooled buffers; offload to background tasks.
- **Counters**: Track allocations via a global allocator wrapper in test builds (see below) but keep disabled in prod.

---

## 10) Verification & Tests (Enforcing Zero Alloc)

- **Allocation Counters**: In test/profile builds, wrap the global allocator to count allocations; assert 0 on:
  - N packet RX→process→TX iterations.
  - M lookup steps over populated tables.
- **Benches**: Criterion benches with allocation counting; fail CI if regressions appear.
- **Fuzzing**: Structure-aware fuzzing of codec over pooled buffers to ensure no hidden allocs.

Suggested crates/tools:
- `bytes` (pool-friendly buffers), `arrayvec`/`smallvec`/`heapless`, `slab`, `bumpalo`.
- `count-alloc` or a custom `GlobalAlloc` wrapper for tests.

---

## 11) Rollout Plan

1. Introduce buffer pool and bump arena modules; switch RX/TX paths to pooled buffers.
2. Replace buckets with fixed-capacity `ArrayVec` + index-based LRU.
3. Convert lookup frontier/visited to `SmallVec`/fixed heaps; preallocate α request contexts.
4. Move hot RPCs to borrowed `prost` decode over pooled buffers; enforce size limits.
5. Add allocation-count tests/benches; wire into CI thresholds.
6. Gradually expand coverage (provider announcements, erasure coding, privacy features) while keeping hot paths allocation-free.

---

## 12) Risks & Trade-offs

- **Complexity**: Fixed-capacity structures and arenas increase code complexity and require careful lifetimes.
- **Flexibility**: Strict bounds may reject rare jumbo messages; handle via slow-path with explicit backpressure.
- **Platform Variance**: Batch I/O differs across OSes; ensure fallbacks maintain zero-allocation guarantees.

---

## 13) Checklist (PR Gate)

- RX/TX handlers: 0 allocations in steady state (proof via test).
- Routing bucket touch/evict: 0 allocations in steady state.
- Lookup step (merge/sort): 0 allocations in steady state.
- Codec: zero-copy reads; pooled buffer writes; size limits enforced.
- Bench + CI: allocation counters and latency budgets met.

---

[← Back to Architecture](README.md)

