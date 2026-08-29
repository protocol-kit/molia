# Linux Advanced Path: SO_REUSEPORT + eBPF Steering

This document describes a Linux‑specific fast path that uses `SO_REUSEPORT` with a reuseport eBPF program to peek UDP payloads and steer WireGuard packets directly to per‑shard sockets.

---

## 0) Goals & Prereqs

- Steer WG Data messages by `receiver_index` to the shard that owns the session.
- Steer WG Initiation/Cookie to a dedicated "handshake shard" without waking others.
- Keep per‑shard isolation (shared‑nothing) and minimize cross‑core handoffs.
- Kernel: Linux 5.3+ recommended; features: `BPF_PROG_TYPE_SK_REUSEPORT`, `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY`.
- Privileges: load/attach eBPF (CAP_BPF or bpffs + loader), set `SO_REUSEPORT` on per‑shard sockets.

---

## 1) High‑Level Design

- Create `S` UDP sockets bound to the same port with `SO_REUSEPORT`, one per shard.
- Attach a reuseport eBPF program to the reuseport group.
- The program peeks into UDP payload (WireGuard) and selects a socket:
  - WG Data (type=4): read `receiver_index` and pick owning shard.
  - WG Initiation/Cookie (type=1/3): hash `src_ip:src_port` to a designated handshake shard.
- Fallback: if parsing fails, use kernel hash (consistent RSS‑like behavior).

---

## 2) WireGuard Header Summary (for parsing)

- First 4 bytes (little‑endian) indicate WG message type:
  - 1 Initiation, 2 Response, 3 Cookie, 4 Data.
- For Data (type 4), the next 4 bytes are `receiver_index` (little‑endian) identifying the recipient session.
- The eBPF program only reads the first 8 bytes of UDP payload (plus IPv4/IPv6 + UDP headers) with strict bounds checks.

---

## 3) eBPF Maps

- `socks`: `BPF_MAP_TYPE_REUSEPORT_SOCKARRAY` length S (one entry per shard socket).
- `rx_index_to_slot`: `BPF_MAP_TYPE_HASH` key=`u32 receiver_index`, value=`u32 slot` (index into `socks`).
- Optional `handshake_seed`: `BPF_MAP_TYPE_ARRAY` with a per‑node salt for hashing (updated by userspace).

---

## 4) eBPF Program Logic (pseudo‑C)

```c
SEC("sk_reuseport")
int wg_select(struct bpf_sk_reuseport_md *md) {
  void *data     = (void *)(long)md->data;
  void *data_end = (void *)(long)md->data_end;

  // Parse IPv4/IPv6 + UDP headers to find payload start
  struct hdrs h = {0};
  if (parse_l3l4_udp(md, &h, &data, data_end) < 0) {
    return SK_PASS; // let kernel choose
  }

  // Need first 8 bytes of payload (type + receiver_index)
  if (data + 8 > data_end) {
    return SK_PASS;
  }

  __u32 wg_type_le = *(__u32 *)data;       // little‑endian
  __u32 wg_type = __le32_to_cpu(wg_type_le);

  if (wg_type == 4) { // Data
    __u32 rx_idx = __le32_to_cpu(*(__u32 *)(data + 4));
    __u32 *slotp = bpf_map_lookup_elem(&rx_index_to_slot, &rx_idx);
    if (slotp) {
      return bpf_sk_select_reuseport(md, &socks, NULL, *slotp, 0);
    }
    return SK_PASS;
  }

  // Initiation or Cookie → handshake shard selection
  // Hash src ip:port (and optional salt) to a stable slot for handshake
  __u32 slot = hash_5tuple_to_slot(&h, S_HANDSHAKE_SLOTS);
  return bpf_sk_select_reuseport(md, &socks, NULL, slot, 0);
}
```

Notes:
- `parse_l3l4_udp` must bounds‑check every read and support both IPv4 and IPv6.
- Do not parse beyond a small fixed window to satisfy the verifier.
- For kernels without `bpf_sk_select_reuseport`, the program can set `md->hash` (if supported) and return `SK_PASS` to let the kernel pick, but direct selection is preferred.

---

## 5) Userspace Control‑Plane

- Socket setup:
  - Create `S` UDP sockets with `SO_REUSEPORT`, bind to the same address/port.
  - Load/attach the reuseport program to the group; populate `socks` with socket FDs.
- Session pinning:
  - On successful WG handshake, compute owning shard for the peer and assign a `receiver_index` from that shard’s range.
  - Update `rx_index_to_slot[receiver_index] = shard_slot` (atomic; idempotent) so Data messages steer correctly.
- Handshake sharding:
  - Optional: update a salt in `handshake_seed` to mix into the 5‑tuple hash for better distribution.
- Rotation & cleanup:
  - On session teardown/rekey that changes `receiver_index`, update the map accordingly.
  - On shard changes (rebalance), update affected entries; keep TTLs to prune stale indices.

---

## 6) Failure & Fallback

- If map lookup fails or parsing errors, the kernel’s default selection applies (consistent hashing).
- If the eBPF verifier rejects the program on older kernels, fall back to userspace demux parsing and queueing.
- On map pressure, cap `rx_index_to_slot` size and evict LRU (userspace maintenance) while retaining active sessions.

---

## 7) Observability & Debugging

- Counters (userspace): selections by path (Data vs Handshake), `SK_PASS` fallbacks, map misses.
- Kernel tracepoints: `sock:inet_sock_set_state`, `bpf:bpf_sk_reuseport_select` (if available).
- bpftool: dump maps (`bpftool map dump`), program stats, verifier logs during load.

---

## 8) Security Considerations

- Bounds‑check all accesses; never trust packet lengths.
- Treat pre‑handshake traffic as untrusted; do minimal work in BPF (hash + steer only).
- Keep socket array and index map writable only by the daemon; avoid external mutation.

---

## 9) Integration Steps

1. Implement userspace sockets and sharding; verify baseline without eBPF.
2. Add eBPF loader with libbpf; create `socks` and `rx_index_to_slot` maps; attach program.
3. Wire WG handshake completion to update `rx_index_to_slot`.
4. Benchmark selection accuracy and CPU cost; verify no regressions under churn.
5. Add metrics and fallbacks; test on multiple kernel versions.

---

[← Back to Advanced](README.md)
