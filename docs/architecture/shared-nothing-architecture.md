# Shared-Nothing Architecture

This document specifies a shared-nothing architecture for the Molia DHT implementation. It complements [Zero-Allocation Design](zero-allocation-design.md) by defining how we partition state, schedule work, and communicate without shared mutable memory, maximizing cache locality, scalability, and failure isolation.

---

## 0) Objectives & Principles

- **Primary Objective**: No shared mutable state across worker shards; communicate via message passing.
- **Per-Core Shards**: Each shard is pinned to a CPU core and owns its state (routing, peerstore, timers, in-flight ops).
- **Isolation**: A shard can stall or be restarted without halting others.
- **Locality**: Keep data and hot loops on the same core; avoid cross-core cache traffic.
- **Determinism**: Prefer single-threaded event loops per shard; bounded, explicit cross-shard messages.

---

## 1) Partitioning Strategy (Keys to Shards)

- **Shard Count**: `S` shards per node (default: number of physical cores, configurable).
- **Assignment**: XOR-local selector by high bits of `d = selfId XOR key`.
  - Let `k = ceil(log2 S)`. Compute `shard_id = msb_k(d)`.
  - If `S` is not a power of two, map `2^k` prefix buckets to `S` shards via a small static remap table.
  - Inputs: 256-bit key (XOR space). With uniform keys, `d` is uniform; whitening not required.
  - Preserves XOR locality: nearby keys map to the same shard with high probability.
  - When `S` changes, update the remap table to minimize movement; only affected prefix buckets migrate.
- **Ownership**:
  - The owning shard handles lookups, stores, provider announcements, refresh, and caching decisions for its keys.
  - Network packets are demultiplexed to the shard by the same selector `msb_k(selfId XOR key)` to preserve XOR locality.

---

## 2) Threading & Runtimes

- **One Event Loop per Shard**: Custom single-threaded reactor per shard (no Tokio). Drive UDP, timers, and cross-shard rings directly; do not introduce an async runtime.
- **Core Affinity**: Pin shard threads to dedicated cores where the OS permits.
- **No Cross-Shard Locks**: No `Mutex`/`RwLock` across shards. Use lock-free SPSC rings or bounded MPSC channels.
- **I/O**: Each shard owns its UDP socket (see §3) and timers. Background tasks (erasure coding, GC) run within the shard.

---

## 3) Networking (UDP, SO_REUSEPORT, RSS)

- **UDP Sockets**: `S` sockets bound with `SO_REUSEPORT`, one per shard. The kernel steers flows to shards (RSS).
- **Fallback Demux**: If RSS not available, a thin acceptor hashes `(src_ip, src_port, dst_port, msg_key)` and forwards buffers to shards via SPSC rings.
- **Buffers**: Per-shard buffer pools (see zero-allocation design). No sharing of buffers across shards.
- **Batch I/O**: Use `recvmmsg/sendmmsg` per shard where supported; otherwise per-packet with readiness batching.

---

## 4) Per-Shard State (Shared-Nothing)

- **Routing Table**: K-buckets stored as fixed-capacity arrays. LRU and PNS maintained in-place.
- **Peerstore**: Slab-backed structures with shard-local indices. Buckets store indices, not pointers.
- **In-Flight Ops**: Lookup frontiers, visited sets, retry state in shard-local arenas.
- **Timers**: Hierarchical timing wheel per shard for pings, TTL refresh, backoff.
- **Metrics & Logs**: Shard-local counters and ring buffers; aggregated asynchronously (see §8).

---

## 5) Cross-Shard Messaging

- **Topology**: SPSC rings for common paths (per neighbor pair), or a sharded MPSC bus with per-shard receive queues.
- **Message Types**:
  - Lookup coordination (forward/redirect), provider announce fanout, cache hints, control plane signals.
- **Semantics**:
  - Bounded capacity; backpressure by dropping low-priority hints first, then delaying.
  - Messages are plain POD structs with borrowed slices to avoid allocation; buffers remain shard-owned.
- **Order**: Best-effort ordering within a channel; idempotent handlers to tolerate reorder/drop.

- **Envelope (POD, cache-friendly)**
  - Fields: `msgType(u8)`, `srcShard(u8)`, `dstShard(u8)`, `priority(u8)`, `correlationId(u64)`, `keyHashPrefix(u64)`, `epoch(u16)`, `ttl(u8)`, `payloadLen(u16)`.
  - Size target ≤ 32 bytes (without payload), 8-byte aligned. Payload is a borrowed `&[u8]` or inline small struct.
  - `keyHashPrefix` accelerates routing/coalescing without full keys.

- **Classes & QoS**
  - Control (highest): config changes, shard lifecycle, admission decisions. Capacity small; loss unacceptable → escalate when full.
  - Coordination (normal): lookup redirects, provider fanout control. Capacity moderate; drop only when duplicate/coalescible.
  - Hints (best-effort): cache hints, soft reputation gossip. Capacity large; lossy by design.
  - Each class has a distinct ring per shard; drain using weighted round-robin (e.g., 8:4:1 for Control:Coord:Hints).

- **Backpressure & Drop Policy**
  - Never block producers. Enqueue returns `Enqueued | Coalesced | Dropped{Full|TTLExpired|NoRoute}`.
  - Hints: drop-oldest or coalesce by `keyHashPrefix` to keep freshest hints.
  - Coordination: drop-newest only if duplicate in-flight exists; otherwise accept until cap, then log and drop.
  - Control: do not drop; if full, trigger rate-cut signals and shed lower classes until control ring is healthy.

- **Reliability & Idempotency**
  - At-most-once delivery semantics. Handlers must be idempotent (use `correlationId` and message kind).
  - Optional ack for rare control ops: bounded retries with `ttl` decrement; never block shard main loop.
  - No cross-shard consensus. On repeated failure, local fallback or operator alert.

- **Buffer Ownership & Zero-Copy**
  - Payload buffers are owned by sender shard's pool; receiver must process synchronously.
  - If retention is needed, receiver copies into its own pool (explicit, counted); otherwise zero-copy borrow.
  - Lifetimes: payload considered valid only for the handling call; no sharing beyond handler scope.

- **Scheduling & Fairness**
  - Per tick: drain up to `quota[class]` messages, then rotate class. Within class, round-robin across producers.
  - Batch size 16–64 per drain to maximize cache locality and reduce per-message overhead.
  - Starvation guards: minimum quota per lower class to prevent indefinite suppression.

- **Routing & Rebalancing Awareness**
  - Envelope carries `epoch`. If `dstShard` ownership changed, forward once to new owner and decrement `ttl`.
  - If `ttl == 0` or route unknown, drop with `NoRoute` and increment metric; do not loop.
  - During shard-count transitions, a compatibility map is consulted for forwarding targets.

- **Limits & Budgets**
  - Max payload per message ≤ 512 bytes. Larger data must use network paths or be reduced to keys/indices.
  - Per-class ring capacities (typical): Control=64, Coordination=1024, Hints=4096 (tunable per deployment).
  - Per-producer rate caps to isolate misbehaving components; excess becomes drops in the producer's class.

- **Telemetry & Alarms**
  - Per class: queue depth, high-water mark, enqueue rate, drain rate, latency p50/p95, drops by reason.
  - Top-N noisy producers and hot message kinds by rate and drop impact.
  - Alerts on sustained control queue > 50% capacity, or any control drop; coordination drops > 5% over 1 min.

---

## 6) Lookup Execution (Iterative, Sharded)

- **Entry & Ownership**
  - The shard selected by `msb_k(selfId XOR targetKey)` owns the lookup lifecycle.
  - Requests carry a correlation ID, privacy flags (none/blind/relay), and budgets (timeouts, α limits).

- **State Machine (per lookup)**
  - Initialize: seed frontier with α closest known peers from the shard's routing table.
  - Dispatch: send requests to up to α peers in parallel, respecting per-peer tokens and rate limits.
  - Collect: on response/timeout, update candidate ordering and bookkeeping.
  - Iterate: continue rounds while closer peers are discovered and budgets remain.
  - Finalize: return record/providers or NotFound, perform opportunistic caching and metric updates.

- **Data Structures (zero-alloc)**
  - Frontier: fixed-capacity binary heap or `ArrayVec<[Candidate; N]>` ordered by XOR distance, then RTT.
  - Visited: fixed-size bitset/Bloom filter to avoid re-querying peers in the same lookup.
  - In-Flight: `ArrayVec<OutstandingRequest, ALPHA_MAX>` with timestamps and peer indices.
  - Results: small fixed buffers for found records, provider lists, and closer peers.

- **Concurrency & Scheduling**
  - α parallelism: start at α_min; increase toward α_max on loss/slow paths; decrease on healthy paths.
  - Per-peer concurrency tokens to avoid overloading a single peer; global outstanding cap per lookup.
  - Selection: choose next peers by best distance with latency bias; skip peers lacking tokens or recently failed.

- **Timeouts & Retries**
  - Adaptive timeout: `T = clamp(2×SRTT(peer), 50ms..600ms)` with jitter. Record SRTT per peer.
  - One retry per peer per lookup after cooldown; demote peer score on repeated timeouts or malformed replies.
  - Overall lookup budget: `T_max` (e.g., 1–2 s); hard stop when exceeded.

- **Query Shaping & Privacy (optional)**
  - Blinding: include a small number of neighbor probes around the target prefix to mask intent.
  - Two-hop relay: if enabled, route initial leg via a disjoint-bucket relay; fall back to direct on failure.
  - Rate limits and privacy choices are enforced locally within the shard; no cross-shard dependency.

- **Response Handling**
  - Record: verify integrity (hash for immutable, signature/sequence for mutable). On success, early-return value.
  - Providers: merge unique providers up to caller limit; continue querying until quorum or budget reached.
  - Closer peers: merge into frontier, maintaining ordering and visited filters.
  - Invalid/malformed: drop and penalize peer; do not poison the frontier.

- **Termination Conditions**
  - No closer peers found in the last round, or the k-closest set has been fully queried.
  - Record found and validated (may still schedule background cache updates without blocking return).
  - Budgets exhausted: `T_max`, attempt caps, or α cannot be advanced further.

- **Side Effects (post-lookup)**
  - Opportunistic caching: store successful immutable fetches with short TTL; respect zero-alloc by using shard pools.
  - Routing maintenance: LRU touch successful responders; evict/penalize chronic offenders.
  - Metrics: record hop count, latency, success/failure reason, and α trajectory.

- **Cancellation & Cleanup**
  - On termination, cancel outstanding requests; recycle buffers to shard-local pools immediately.
  - Reset per-lookup arena/bump allocator to reclaim temporary structures in O(1).

- **Cross-Shard Notes**
  - Lookups are shard-contained; cross-shard messages are not required for correctness and are avoided in hot paths.
  - If coordination is needed (e.g., policy signals), use best-effort messages that do not block the lookup state machine.

---

## 7) Provider Records & Announcements

- Provider records are partitioned by content key to the owning shard.
- Announce and refresh tasks are scheduled on that shard's timer wheel.
- Dandelion-like stem/flare (if enabled) uses local randomness; fanout to other shards only via network, not local memory sharing.

---

## 8) Observability (No Shared Locks)

- **Metrics**: Per-shard counters/gauges/histograms updated without contention.
- **Aggregation**: A low-priority aggregator thread periodically reads snapshots via lock-free atomic loads or message pull. No shard waits on the aggregator.
- **Tracing**: Per-shard trace buffers with sampling; flush via messages to an I/O worker.

---

## 9) Persistence & WAL

- **Peerstore**: One WAL file per shard to avoid cross-thread coordination. Periodic compaction per shard.
- **Crash Safety**: Each shard recovers independently from its WAL on restart.

---

## 10) Resilience & Isolation

- **Crash-Only**: Shards are supervised. On failure, restart shard with state rebuilt from WAL and bootstrap.
- **Rate Limiting**: Enforced per shard (per peer/IP buckets) to avoid shared global limiters.
- **Backpressure**: Channel capacity + timer-based retries; never blocking across shards.

---

## 11) Configuration & Rebalancing

- **Changing Shard Count**:
  - Update the `msb_k(selfId XOR key)` mapping when `S` changes by adjusting the prefix remap table. Drain-and-close a shard by migrating only affected prefix buckets.
  - During transition, a compatibility map forwards messages to new owners.
- **Hotspot Relief**:
  - Temporarily split a shard's keyspace (virtual shards) and assign to helper threads; merge back post-incident.

---

## 12) Integration with Zero-Allocation

- Per-shard arenas for lookup scratch; buffer pools owned by shard; no cross-shard buffer reuse.
- Channel payloads avoid allocation and copy minimal slices; large payloads are referenced via shard-owned buffers until send completes.
- Timers and data structures use fixed-capacity containers, aligned with zero-alloc budgets.

---

## 13) Security & Privacy Considerations

- **Auth & MAC**: In-place verification within the receiving shard; no cross-shard handoff for validation.
- **Privacy**: Query blinding and relay strategies executed locally; randomness sourced per shard to avoid correlation.
- **Abuse Controls**: EWMA scoring and quarantine lists held per shard; optional periodic gossip via messages to converge decisions.

---

## 14) Testing & Verification

- **Deterministic Shard Tests**: Single-shard simulations with scripted timers and channels.
- **Cross-Shard Stress**: Saturate message buses, verify backpressure policy and no deadlocks.
- **Allocation Counters**: Assert zero allocations on hot paths per shard (see zero-alloc tests).
- **Chaos**: Kill/restart a shard; verify continued service and recovery from WAL.

---

## 15) Rollout Plan

1. Introduce shard event loop skeleton with per-shard state and sockets (SO_REUSEPORT).
2. Route incoming packets to shards by kernel RSS; implement fallback demux if needed.
3. Partition routing table and peerstore; migrate handlers into shard loops.
4. Add cross-shard messaging bus for optional coordination paths.
5. Wire observability: per-shard metrics, aggregator reader.
6. Enable rebalancing hooks for changing shard counts; add migration tests.

---

## 16) Checklist (PR Gate)

- No cross-shard locks; message passing only.
- Per-shard sockets, timers, buffer pools in place.
- Routing, lookups, provider ops owned by shards.
- Backpressure policies enforced on channels.
- Tests: zero-alloc on hot paths; chaos restart; rebalancing.

---

[← Back to Architecture](README.md)
