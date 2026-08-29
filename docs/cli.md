# CLI (`molia`)

The `molia` binary is a single-process node: per-core UDP shards, optional userspace WireGuard, and an optional WebRTC gateway. No Tokio.

## Data directory

`--data-dir PATH` (default `.`) holds:

| Path | Role |
|---|---|
| `identity.json` | Ed25519 seed + X25519 secret, plus derived pubkeys and `node_id` |
| `peerstore/shard-N/` | `wal.log` (peers + DHT records), optional `snapshot.bin` |

If `identity.json` is missing but `identity.bin` exists, the node loads the old 64-byte file once and rewrites JSON.

`ed25519_seed` is the signing secret. `ed25519_pubkey` is what `--get-mutable` wants.

## Flags

```
molia --listen 0.0.0.0:4001 --bootstrap 127.0.0.1:4000
      [--shards N] [--data-dir PATH] [--new-identity] [--clear-peerstore]
      [--wg] [--relay] [--log-level L] [--ttl SECS]
      [--put VAL] [--get HEX]
      [--put-mutable NS SALT VAL SEQ] [--get-mutable PUBKEY NS SALT]
      [--announce KEY META] [--providers KEY]
      [--webrtc-gateway [ADDR]]
```

**Node**
- `--listen ADDR` — UDP bind (default `0.0.0.0:4001`)
- `--bootstrap A,B` — seed addresses
- `--shards N` — default `available_parallelism()`
- `--data-dir PATH`
- `--new-identity` — overwrite `identity.json`
- `--clear-peerstore` — delete `peerstore/` then start
- `--wg` — encrypt RPCs after a plaintext PING/PONG key exchange
- `--relay` — allow two-hop relay
- `--log-level L` — tracing filter (`info`, `debug`, `molia=debug`, …)
- `--ttl SECS` — soft TTL for `--put` / `--put-mutable` (default 86400)

**One-shot** (bootstrap, then print and exit)
- `--put VAL` — immutable; key = BLAKE3(value)
- `--get HEX` — FIND_VALUE
- `--put-mutable NS SALT VAL SEQ` — named record; Ed25519 sig over `key‖value‖seq‖ttl‖not_before`; key = BLAKE3(owner_pubkey‖NS‖SALT). Local and replica STORE both reject a bad signature or a key that does not match that derivation.
- `--get-mutable PUBKEY NS SALT` — key = BLAKE3(PUBKEY‖NS‖SALT); print value only if the envelope verifies with that Ed25519 PUBKEY
- `--announce KEY META` — provider record (“I have KEY”)
- `--providers KEY` — list announced providers

**WebRTC**
- `--webrtc-gateway [ADDR]` — playground + ICE/DTLS/SCTP (str0m, no Tokio). Default `127.0.0.1:9080`.

| Method | Path | Role |
|---|---|---|
| `GET` | `/` | Playground (`playgroud/webrtc/index.html`) |
| `POST` | `/rtc/offer` | Browser SDP offer → SDP answer; one ICE/DTLS/SCTP session |
| `POST` | `/rpc` | HTTP fallback: one 12-byte header + Protobuf frame → local UDP node |
| `PUT`/`GET`/`DELETE` | `/room/…` | Optional two-tab signaling (no node ICE) |

DataChannel label is `molia`. One SCTP message = one UDP RPC datagram. Requires a running node (the flag is on the binary).

## Playground

```bash
# long-running seed
cd playgroud/peer1
cargo run --bin molia -- --listen 127.0.0.1:4001 --shards 1 --data-dir .

# immutable put / get from another cwd
cargo run --bin molia -- --listen 127.0.0.1:4002 --bootstrap 127.0.0.1:4001 --shards 1 --put hello
cargo run --bin molia -- --listen 127.0.0.1:4003 --bootstrap 127.0.0.1:4001 --shards 1 --get ea8f163d…

# browser ICE into the seed
cargo run --bin molia -- --listen 127.0.0.1:4001 --shards 1 --data-dir playgroud/peer1 --webrtc-gateway
# open http://127.0.0.1:9080 → role Gateway (ICE) → Connect → Ping / Put / Get
```

`--wg` must be used on both sides for an encrypted path. Intro PING/PONG stay plaintext and carry X25519 + Ed25519 + a binding signature. Later RPCs wrap as dummy IPv4 inside BoringTun.

Page details: [playgroud/webrtc/README.md](../playgroud/webrtc/README.md).

[← Documentation index](README.md)
