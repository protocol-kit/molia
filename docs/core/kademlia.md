# Kademlia — Notes & Implementation Guide

This note covers the original Kademlia algorithm (typically 160-bit IDs, **α** ≈ 2–4). Molia keeps XOR routing and k-buckets, with **256-bit IDs** (`BLAKE3` of Ed25519), default **k = 20**, and adaptive **α = 4** (range 3–8). See [Architecture Overview](../overview.md) and [Molia enhancements](README.md#molia-enhancements).

---

## 1) What is Kademlia (in one line)
Give every node and piece of content a large random ID; define “closeness” with XOR over IDs; route queries toward nodes whose IDs are XOR-closer to the target until you converge on the best matches.

---

## 2) Core concepts
- **Keyspace & IDs:** Nodes and content keys live in the same b-bit space (original paper: 160; Molia: 256).  
- **Distance:** \(d(x,y) = x \oplus y\) (bitwise XOR). Smaller integers are closer.  
- **k-buckets:** The routing table is partitioned into buckets covering exponential distance ranges \([2^i, 2^{i+1})\) from *your own ID*. Each bucket stores up to **k** contacts, ordered by LRU (least-recently-seen first).  
- **RPCs:** `PING`, `STORE(key,value)`, `FIND_NODE(targetID)`, `FIND_VALUE(key)`.  
- **Parallelism:** Query up to **α** nodes concurrently (typically small; e.g., 2–4) for low latency and resilience.

---

## 3) Routing table behavior (k-buckets)
**Insert(contact):**  
1. Compute bucket index \(i = \lfloor \log_2 d(self, contact) \rfloor\).  
2. If contact is in bucket → move to MRU (tail).  
3. Else if bucket not full → append.  
4. Else (full): `PING` the LRU entry; if it’s dead, evict it and append the new contact; if alive, keep the old entry (optionally put the newcomer in a *replacement cache*).

**Split rule:** Only split a full bucket whose range contains **your own ID** (prevents over-splitting far-away regions).  
**Refresh:** Periodically pick a random ID in each bucket’s range and run a lookup to keep entries fresh.  
**Diversity (hardening):** Limit per-/24 or per-ASN peers, vary subprefixes, etc., to resist eclipse attacks.

---

## 4) Iterative lookup (routing) — the algorithm
Used for both `FIND_NODE(targetID)` and `FIND_VALUE(key)` (with a slight twist).

### Data structures
- `Shortlist`: sorted (by XOR distance to target) set of candidate nodes.  
- `Queried` / `Seen` / `TimedOut` sets to control concurrency and retries.  
- Up to **α** in-flight requests at any time.

### Termination
Stop when you have already queried the **k closest** known nodes and the last round yielded **no closer** nodes than the current best-k (i.e., no progress).

### Pseudocode — `FIND_NODE`
```python
def iterative_find_node(target, k=20, alpha=3, timeout=2.0):
    shortlist = SortedByXorDistance(target)
    shortlist.add_all(alpha_closest_from_routing_table(target))
    queried = set()
    best_prev = None

    while True:
        batch = []
        for n in shortlist.iter():
            if n not in queried and len(batch) < alpha:
                batch.append(n)
        if not batch:
            break

        replies = parallel_rpc_find_node(batch, target, timeout=timeout)
        queried.update(batch)

        for (node, ok, result_nodes) in replies:
            touch_routing_table(node, ok)
            if not ok:
                continue
            shortlist.add_all(result_nodes)

        best_now = shortlist.k_best(k)
        if best_prev is not None and same_set(best_prev, best_now):
            break  # no improvement
        best_prev = best_now

    return shortlist.k_best(k)
```

### Pseudocode — `FIND_VALUE`
- Same loop, but each request is `FIND_VALUE(key)` and may return the value itself.  
- On first value hit, you can **replicate/cache** along the path to improve locality.

```python
def iterative_find_value(key, k=20, alpha=3):
    t = hash_key(key)
    shortlist = ...
    while True:
        batch = next_alpha_unqueried(shortlist)
        if not batch:
            break
        replies = parallel_rpc_find_value(batch, key)
        for node, ok, payload in replies:
            if not ok:
                continue
            if payload.has_value:
                replicate_value_to_k_closest(key, payload.value, shortlist.k_best(k))
                return payload.value
            shortlist.add_all(payload.closest_nodes)
        if no_progress(shortlist):
            break
    return None
```

### Concurrency & failures
- Non-blocking RPCs; keep ≤ α in flight.  
- If a node times out, mark it suspect for this lookup; consider background `PING` before eviction.  
- Deduplicate queries; never query the same node twice in one lookup.

---

## 5) XOR distance properties (used in routing)
- **Definition:** \(d(a,b) = a \oplus b\).  
- **Associative / self-inverse:** \(x \oplus x = 0,\; x \oplus 0 = x\).  
- **Key identity:** \(d(a,c) = d(a,b) \oplus d(b,c)\).  
- **Translation invariance:** \(d(a\oplus t,\; c\oplus t) = d(a,c)\).  
- **Not a metric:** triangle inequality need not hold; “distance” is an ordering useful for routing, not Euclidean length.

**Tiny example (4-bit):**  
- \(a=0110,\; b=1011,\; c=1101\).  
- \(d(a,b)=1101\), \(d(b,c)=0110\).  
- \(d(a,b)\oplus d(b,c)=1011 = d(a,c)\). ✔

---

## 6) Why k-buckets are anchored at your own ID
Because XOR distance is translation-invariant, each node can treat itself as the origin (XOR-shifting the space by its ID) and partition peers by **distance bands**: bucket \(i\) holds contacts with \(2^i \le d(self, x) < 2^{i+1}\). Equivalently, those contacts share the first \(i\) most-significant bits with you and **differ** at bit \(i\).

**4-bit illustration (self = 0110):**  
- `0111` → \(d=0001\) → bucket 0.  
- `1011` → \(d=1101\) (MSB at position 3) → bucket 3.

This layout guarantees coverage at every XOR “scale,” enabling logarithmic-time routing.

---

## 7) Keeping things fresh
- **LRU buckets:** Favor long-lived peers; `PING` LRU before eviction.  
- **Replication:** Values live on the **k** closest nodes to their key.  
- **Caching:** Successful `FIND_VALUE` lookups may cache along the path.  
- **Republish/TTL:** Periodically republish values so they survive churn.

---

## 8) Parameters (typical)
- **k (bucket size / replication):** 8–20 (paper suggests ~20).  
- **α (parallelism):** 2–4.  
- **Timeouts:** a few seconds; tune to your network RTTs.  
- **Refresh period:** ≈ 1 hour per bucket is common.

---

## 9) Strengths & trade-offs
**Pros**  
- \(O(\log N)\) hops, low bandwidth.  
- Resilient to churn via LRU + α-parallelism.  
- Simple, four-RPC API.

**Cons**  
- Vulnerable to Sybil/eclipse without identity/work and neighbor diversity.  
- Hot keys can hotspot without extra load-balancing.  
- Needs good bootstrap peers to join.

---

## 10) Join procedure (bootstrap)
1. Insert a known bootstrap contact.  
2. Run `FIND_NODE(self_id)` and a few lookups for random IDs to seed buckets.  
3. Normal traffic plus periodic refresh will maintain coverage.

---

## 11) Worked mini-trace (4-bit, α=2, k=3)
- **Self:** `0010`, target `t=1010`.  
- Seed: `{0110, 1111}`.  
- **Round 1:**  
  - Ask both → returns `{1011,1001,0111}` and `{1010,1100,1110}`.  
  - Merge/sort → top `{1010,1001,1011}`.  
- **Round 2:**  
  - Query `{1010,1001}`.  
  - If `FIND_VALUE` and `1010` has the value → stop early and cache/replicate; for `FIND_NODE`, finish when no closer nodes are learned.

---

## 12) Implementation tips
- Avoid querying the same node twice per lookup; suppress duplicates early.  
- Return live, recently seen contacts first.  
- Keep a small *replacement cache* per bucket.  
- Consider IP/ASN diversity caps and subprefix shards for security.

---

## 13) Reference
- Petar Maymounkov, David Mazieres. **“Kademlia: A Peer-to-Peer Information System Based on the XOR Metric.”** IPTPS 2002.

---

[← Back to Core Concepts](README.md)
