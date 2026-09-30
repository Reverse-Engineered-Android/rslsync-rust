# rustsync

`rustsync` is a Linux Rust implementation of the core folder
synchronization protocol used by the upstream client 3.1.2. It interoperates
with the official Linux client over direct TCP + SRPEH, exchanges signed merge
metadata, and transfers verified file content through both DirectTorrent 3.1.2
response modes. The verified core is bidirectional in both directions.

The compatibility boundary is intentionally explicit. Regular files, nested
paths, directories, tombstones, recreation, metadata changes, and deterministic
conflict preservation are implemented. The additional encrypted-folder,
selective-sync, POSIX-permission, and tracker layers are independent Rust
designs implemented in this repository; they do not depend on proprietary
client code or configuration. See [`COMPATIBILITY.md`](COMPATIBILITY.md).

## Linux Quick Start

Build and run all tests:

```bash
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
```

## Binary Releases

The release workflow builds static Linux executables and Debian packages for
the following architectures:

| Architecture | Rust target | Debian architecture |
| ------------ | ----------- | ------------------- |
| x86_64 | `x86_64-unknown-linux-musl` | `amd64` |
| aarch64 | `aarch64-unknown-linux-musl` | `arm64` |
| riscv64 | `riscv64gc-unknown-linux-musl` | `riscv64` |
| LoongArch64 new world | `loongarch64-unknown-linux-musl` | `loong64` |

Every pushed commit builds all four targets and exposes the raw executable and
`.deb` file as separately named Actions artifacts. Pushing a `v<version>` tag
that matches `Cargo.toml` additionally publishes those files to the matching
GitHub release. The LoongArch build uses the upstream Linux LP64D ABI (kernel
5.19+, musl 1.2.5) and is therefore intended for the new-world ABI. OpenSSL is
vendored and statically linked so the executable does not require a system
OpenSSL installation.

## REST Server and Web Console

The embedded server exposes the existing one-shot core operations through
JSON, manages configured sync folders, and automatically serves the bundled
web console:

```bash
cargo run -- serve-ui --listen 127.0.0.1:8787 \
  --state .rustsync-server/state.json
```

Open `http://127.0.0.1:8787/`. The server binds to loopback by default and
stores its password hash, access rules, and folder registry in the state file
with mode `0600`.

When no password is configured, the first trusted client can complete initial
setup. After a password is set, requests from non-exempt clients require either
the `Authorization: Bearer <token>` header or the `rustsync_session` cookie
issued by `POST /api/v1/auth/login`. Local access is exempt by default:

```text
127.0.0.0/8
::1/128
```

The exempt list is configurable as individual IPs or CIDR networks. The server
uses the direct socket peer address and deliberately does not trust forwarded
headers.

## Android client

The repository includes a native Android client in [`android/`](android/).
It packages the `rustsync` executable for `arm64-v8a`, `armeabi-v7a`, `x86`,
and `x86_64`, launches the embedded REST server, and provides tools for every
CLI operation. Folder registration supports app-private storage, native
absolute paths, external app storage, and SAF document trees through a
bidirectional app-private mirror. The Android workflow publishes installable
APK artifacts on every CI run and attaches them to version-tag releases.

One-shot CLI commands can execute on a running server with `--server`. Supply
`--server-token`, or use `--server-password` to log in first:

```bash
cargo run -- --server http://127.0.0.1:8787 scan /srv/sync/docs
cargo run -- --server http://127.0.0.1:8787 \
  --server-password 'change-me' generate-key --read-write
```

Set `RUSTSYNC_SERVER`, plus `RUSTSYNC_SERVER_TOKEN` or
`RUSTSYNC_SERVER_PASSWORD`, to make server dispatch the normal path for
automation and scheduled jobs.

`scan`, `apply`, `pull`, key generation/inspection, discovery ping encoding,
encrypt/decrypt, and tracker announce run in the server process through the
same Rust core functions as local mode. Long-running listeners remain local
commands because they own their sockets and daemon lifetime. See
[`docs/REST_API.md`](docs/REST_API.md) for endpoint contracts.

Scan and atomically apply a tree with the standalone core:

```bash
cargo run -- scan /path/to/folder
cargo run -- apply /path/to/source /path/to/target
```

Selective scan rules use comma-separated patterns; `**` crosses directories,
`*` stays within one path component, and exclusions win over inclusions:

```bash
cargo run -- scan /path/to/folder --include 'docs/**,*.md' --exclude 'private/**,*.tmp'
```

Pack a directory into an authenticated encrypted vault and restore it with a
passphrase. The vault stores encrypted metadata and opaque object names:

```bash
cargo run -- encrypt-tree /path/to/plain /path/to/vault --passphrase 'change-me'
cargo run -- decrypt-tree /path/to/vault /path/to/restored --passphrase 'change-me'
```

The tracker implementation uses an independent HTTP announce contract and
compact peer lists:

```bash
cargo run -- tracker-serve --listen 127.0.0.1:8000
cargo run -- tracker-announce --url http://127.0.0.1:8000/announce \
  --info-hash <40-hex> --peer-id <40-hex> --port 57301
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

Use a firewall and trusted network while testing experimental Standard Folder
key and synchronization interoperability. Never commit share keys, credentials,
peer secrets, databases, `.sync/` state, logs, or runtime paths.

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
- Selective sync patterns with include/exclude precedence and descendant-safe
  directory traversal.
- POSIX mode, uid, and gid metadata capture/check/apply policies.
- Independent AES-256-GCM encrypted vaults with PBKDF2-HMAC-SHA256 key
  derivation, authenticated paths, and opaque object names.
- Independent HTTP tracker announce/client/server with compact peer lists.
- Upstream merge-controller compatibility fields and empty-ACL exchange:
  `acl_hash`, `active_size`, `exclusive_merge_connection`, ACL node/entry
  pagination, and `get_files_next`.

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
- `src/selective.rs`: portable include/exclude path matching.
- `src/permissions.rs`: POSIX permission metadata and policy enforcement.
- `src/encrypted.rs`: authenticated encrypted-folder vault format.
- `src/tracker.rs`: independent HTTP tracker protocol and registry.
- `src/acl.rs`: signed ACL entry model and deterministic ACL hashes.
- `src/secret.rs`: non-secret share-key and signing-key derivation.

## Testing

`cargo test --all-targets` runs 80 unit tests and 4 integration tests. The suite
covers SRPEH proof/cipher continuity, tunnel frames, metadata signatures,
content hashes, node discovery, atomic apply, reconciliation decisions,
tombstones, recreation, conflict siblings, type changes, and nested directory
values.

The tests generate temporary keys and temporary roots. They do not require or
ship captures, credentials, databases, share keys, logs, or host paths.
