# WebRTC playground

Browser fallback from [transport-nat-traversal.md](../../docs/networking/transport-nat-traversal.md) §7. Same 12-byte header + Protobuf as UDP. `--webrtc-gateway` runs ICE/DTLS/SCTP (str0m) and answers `POST /rtc/offer`.

## Gateway (ICE) — default

From the repo root, on a running node:

```bash
cargo run --bin molia -- --listen 127.0.0.1:4001 --shards 1 --data-dir playgroud/peer1 --webrtc-gateway
```

Optional bind (default `127.0.0.1:9080`):

```bash
cargo run --bin molia -- --listen 127.0.0.1:4001 --shards 1 --webrtc-gateway 127.0.0.1:9081
```

Open http://127.0.0.1:9080:

1. Role **Gateway (ICE)** → Connect.
2. The page waits for host ICE candidates, `POST`s the SDP offer to `/rtc/offer`, and sets the SDP answer.
3. When status is `datachannel open`, **Ping / Put / Get** ride DataChannel `molia` into the local node.

Without an open channel, those buttons `POST /rpc` (HTTP fallback).

Put/Get keys are BLAKE3-256 of the value via [hash-wasm](https://www.npmjs.com/package/hash-wasm) (CDN). Putting `hello` yields `ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f`. The node identity is `{data-dir}/identity.json`.

## Two-tab P2P (room signaling)

ICE/DTLS/SCTP stay in the browsers. The node only stores SDP/ICE lines.

1. Tab A: role **Offerer (two-tab)**, room `demo`, Connect.
2. Tab B: role **Answerer (two-tab)**, same room, Connect.
3. When status is `datachannel open`, Ping / Put / Get also send on that channel (peer-to-peer, not the DHT unless you still use `/rpc`).

Standalone page with no DHT node:

```bash
cargo run --example webrtc_play
# or: cargo run --example webrtc_play -- 127.0.0.1:9081
```

## Rust DataChannel shim (no browser)

In-process reliable pipe (`dc_pair()`), then UDP to a local node:

```bash
cargo run --example webrtc_dc
```

Expected: PING/PONG, STORE, FIND_VALUE over the `molia` channel stand-in.
