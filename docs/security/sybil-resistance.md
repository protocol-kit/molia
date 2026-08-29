# Sybil Resistance

This document specifies Sybil- and abuse-resistance mechanisms for Molia DHT. It aligns with [WireGuard Integration](wireguard-integration.md), [Transport & NAT Traversal](../networking/transport-nat-traversal.md), and [Shared-Nothing Architecture](../architecture/shared-nothing-architecture.md).

---

## 0) Threat Model & Goals

- Adversary can spawn many identities, spoof pre-handshake metadata, and attempt DoS/spam.
- Goals: throttle unauthenticated floods, raise per-identity cost, favor well-behaved peers, and keep hot paths cheap.

---

## 1) Pre‑Handshake Proof‑of‑Work (PoW) via WireGuard Ephemeral

Leverage the unencrypted ephemeral public key in WireGuard Initiation to enforce a lightweight PoW before expensive processing.

- Server keeps a short‑lived puzzle nonce `Ns` (prevents precomputation and allows to tune difficulty over time/load) and difficulty `d` (leading‑zero bits).
- Accept Initiation only if the client’s ephemeral X25519 public key `E` satisfies:
  - `BLAKE3(E || Ns)` has at least `d` leading zero bits.
- Silent by default: for unknown peers that do not present valid PoW, the server remains silent (no expensive work).
- Publishing `(Ns, d)`: nodes publish the current puzzle nonce `Ns` and difficulty `d` via:
  - Peer discovery records (gossiped capability fields).
- Clients are expected to fetch `(Ns, d)` out‑of‑band and solve before sending Initiation.
- If not satisfied, respond with Cookie Reply carrying `(Ns, d)`; client re-initiates with a new ephemeral that passes.
- Properties:
  - No protocol changes: the ephemeral is already public in Initiation; clients can re‑draw ephemerals.
  - Stateless on the fast path: verification is a single hash.
  - Dynamic difficulty: adjust `d` per load, per /24, or per ASN.

Verification (server):
```text
fn verify_ephemeral_pow(ephemeral_pub: [u8;32], nonce: [u8;16], difficulty_bits: u8) -> bool {
  let h = blake3(ephemeral_pub || nonce);
  leading_zero_bits(h) >= difficulty_bits
}
```

Client solve loop (conceptual):
```text
loop {
  let sk, E = x25519_generate_ephemeral();
  if verify_ephemeral_pow(E, Ns, d) { send_initiation(E, sk, …); break; }
}
```

- Rotation: rotate `Ns` every 30–120 s; overlap 1 previous to avoid thrash.
- Sharding: handshake shard validates PoW (cheap); post‑handshake session is pinned to its owning shard.
- Safety: Initiation is still cookie‑gated; PoW is additive, not a replacement.

---

## 2) Dynamic Difficulty & Class‑Based Policies

- Global baseline `d_base`; overlays per /24 and per ASN.
- Autoscale: raise `d` when pre‑handshake queue > X% or CPU > Y%; decay when healthy.
- Handshake classes:
  - New/unknown: full PoW.
  - Recently successful peer IPs: reduced PoW for Δt.
  - Quarantined ranges: higher `d` and tighter rate limits.

---

## 3) Admission Tokens (Post‑Handshake)

- On successful WG handshake + PoW, mint a short‑lived admission token (HMAC bound to WG peer key, includes rate budget).
- Present token on subsequent RPCs to skip/relax PoW for Δt.
- Tokens are per‑peer and per‑shard; not transferable.

---

## 4) Operation‑Level Cost Stamping

- For spam‑sensitive ops (e.g., `ANNOUNCE_PROVIDER`, `STORE`), require a small, verifiable client‑side cost stamp:
  - Hashcash-like: `BLAKE3(key || salt || nonce)` has at least `d` leading zero bits.
  - Difficulty tuned per op and network health; verify is O(1) hash.
- Combine with per‑peer quotas and per‑prefix budgets to prevent flooding hotspots.

---

## 5) Behavioral Scoring & Quarantine

- Maintain per‑peer EWMA of responsiveness, correctness, equivocation, and abuse signals.
- Penalize timeouts, malformed frames, and inconsistent records; reward good behavior.
- Quarantine tiers gate α concurrency, announce/store quotas, and elevate PoW difficulty.

---

## 6) Rate Limiting

- Pre‑handshake: token buckets per IP and per /24; cookie‑only responses beyond thresholds.
- Post‑handshake: per‑peer and per‑prefix buckets; circuit‑breaker on repeated failures.
- Relays: strict egress caps; prioritize control traffic.

---

## 7) Integration with Sharding & Zero‑Alloc

- Handshake shard performs PoW verify + cookie with zero heap alloc; cheap hash only.
- Admission tokens kept in shard‑local slab; lookup O(1) by peer key.
- Operation stamps verified on hot path with a single hash.

---

## 8) Configuration & Rotation

- `pow.difficulty_base`, per‑class overlays, per‑range multipliers.
- `pow.nonce_ttl_secs` and overlap; admission token TTL and budgets.
- Safe defaults and ceilings to avoid self‑DoS.

---

## 9) Observability

- Counters: PoW passes/fails, cookie replies, difficulty histogram, tokens minted/consumed, stamps verified, drops by reason.
- Heatmaps by ASN/region for targeted abuse.
- Alerts: PoW fail rate spikes, cookie floods, token abuse, op‑level drop rates.

---

## 10) Testing & Adversarial Sims

- Synthetic flood with varied IPs/ASNs; verify autoscaling of difficulty and stable tail latency.
- NAT rebinding thrash; ensure session pinning and token continuity.
- Spam of provider/store ops; confirm stamp verification and quotas.

---

## 11) Rollout Plan

1. Implement PoW verify (server) + cookie carriage of `(Ns, d)`; client solver.
2. Add autoscaling controller and per‑range overlays.
3. Mint/verify admission tokens; wire quotas.
4. Add op‑level stamps for provider/store.
5. Instrumentation and alerts; chaos tests.

---

## 12) References

- Userspace WireGuard engine (for integration and handshake context): [BoringTun](https://github.com/cloudflare/boringtun)

---

[← Back to Security](README.md)
