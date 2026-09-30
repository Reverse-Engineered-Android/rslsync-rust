# rustsync

`rustsync` is a Linux Rust implementation of the core folder
synchronization protocol used by the upstream client 3.1.2. It interoperates
with the official Linux client over direct TCP + SRPEH, exchanges signed merge
metadata, and transfers verified file content through both DirectTorrent 3.1.2
response modes. The verified core is bidirectional in both directions.

The compatibility boundary is intentionally explicit. Regular files, nested
paths, directories, tombstones, recreation, metadata changes, and deterministic
conflict preservation are implemented. Tracker relays, selective sync,
encrypted folders, permissions/ACL identity, and every proprietary UI feature
are outside this project. See [`COMPATIBILITY.md`](COMPATIBILITY.md).

## Linux Quick Start

Build and run all tests:

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

Scan and atomically apply a tree with the standalone core:

```bash
cargo run -- scan /path/to/folder
cargo run -- apply /path/to/source /path/to/target
```

Inspect a share key without printing its secret body:

```bash
cargo run -- inspect-key 'A...'
```

Generate a writable compatibility key:

```bash
cargo run -- generate-key --read-write
```

For two-way upstream interoperability use an `A` or `D` read-write key. `B` and
`E` keys parse and derive authentication material, but cannot sign new A/D
metadata. The share ID is `SHA-1(PSK)`. For A/D keys the 20-byte PSK is
`SHA-1(Ed25519_public_key)`; B/E keys use their decoded 20-byte body.

## Upstream Modes

Serve a persistent peer with LAN discovery:

```bash
cargo run -- serve-upstream /path/to/sync-root --listen 0.0.0.0:57301 \
  --key 'A...' --device-name linux-rust
```

Add `--no-discovery` to disable UDP announcements. The default peer ID is
stable for a share ID and device name; use `--peer-id <40-hex>` for a fixed
external identity.

Continuously dial a known upstream peer:

```bash
cargo run -- connect-upstream /path/to/sync-root 192.0.2.10:57301 \
  --key 'A...' --device-name linux-rust
```

`connect-upstream` retries with capped exponential backoff. Both modes scan and
reconcile on every accepted or dialed synchronization session. `serve-upstream`
also advertises the peer on upstream LAN multicast, subnet broadcast, and
loopback UDP port `3838`.

Use a firewall and trusted network while testing experimental
interoperability. Never commit share keys, credentials, peer secrets,
databases, `.sync/` state, logs, or runtime paths.

## Implemented Core

- Upstream LAN discovery ping encoding and periodic advertisement.
- Share-key parsing, SRPEH authentication, A/D Ed25519 metadata signing, and
  legacy TLS-PSK compatibility.
- SRPEH AES-128 stream encryption with independent directional keys/nonces.
- Tunnel check and V1/V2 tunnel packet framing and multiplexing.
- Peer messages `id`, `get_root`, `root`, `get_nodes`, `nodes`, `get_files`,
  `files`, `get_have_pieces`, `have_pieces`, and `state_notify`.
- Top-level node-path discovery and exact/descendant path-scoped file requests.
- DirectTorrent `proto v3` `{data, meta}` responses and `proto v2`
  login/metadata/request/piece exchanges.
- SHA-1 piece verification, SHA-1 file identity, exact `rp = 4 * piece_count`,
  signature checks, atomic writes, mode, and mtime application.
- Persistent per-root reconciliation state under `.sync/`, local tombstones,
  `.Conflict`/`.Conflict2` siblings, and conflict archives for delete races.
- Directory metadata and nested tree nodes using metadata plus ordered child
  digests; type changes preserve the losing filesystem value.

## Reconciliation Summary

| Local / remote condition | Result | Local action |
|---|---|---|
| Same metadata | Equal | Adopt newer advertised mode/mtime; no download |
| Local changed, remote unchanged | LocalWins | Keep local and advertise it |
| Remote changed, local unchanged | RemoteWins | Atomically replace/remove/create |
| Both changed, or type differs | Conflict | Preserve local; install remote |
| Local tombstone, remote active | Conflict | Keep tombstone; write remote as `.Conflict` |
| Local edit, remote tombstone | Conflict | Archive local data; commit tombstone |

The complete SRPEH byte stream, peer messages, transfer frames, and state
machines are in [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## Repository Map

- `src/discovery.rs`: LAN discovery packet codec and advertiser.
- `src/srpeh.rs`: SRPEH handshake, proofs, and directional AES stream.
- `src/tls.rs`: legacy OpenSSL PSK transport.
- `src/protocol.rs`: bencode metadata, hashes, tree nodes, tunnel, and torrent.
- `src/sync_session.rs`: peer sessions, merge, reconciliation, and transfers.
- `src/sync_state.rs`: synchronized baselines, fingerprints, and tombstones.
- `src/scan.rs` / `src/apply.rs`: standalone tree scan and atomic apply.
- `src/secret.rs`: non-secret share-key and signing-key derivation.

## Testing

`cargo test --all-targets` runs 64 unit tests and 2 integration tests. The suite
covers SRPEH proof/cipher continuity, tunnel frames, metadata signatures,
content hashes, node discovery, atomic apply, reconciliation decisions,
tombstones, recreation, conflict siblings, type changes, and nested directory
values.

The tests generate temporary keys and temporary roots. They do not require or
ship captures, credentials, databases, share keys, logs, or host paths.
