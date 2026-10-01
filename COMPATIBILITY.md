# Compatibility Status

## Verified With Upstream Client 3.1.2

The verified target is the official Linux upstream client 3.1.2 (build 1076).
The tested direct-TCP interoperability path is SRPEH followed by encrypted
Upstream tunnel/merge/DirectTorrent traffic.

| Capability | Status | Verification |
|---|---|---|
| SRPEH client/server handshake | Compatible | Mutual proof validation and encrypted frame continuation |
| Peer identity and metadata signatures | Compatible | Official accepted Rust `id` without `bad_signature` |
| Tunnel check and multiplexing | Compatible | Official logged an SRP tunnel to the Rust peer |
| Root/tree/file metadata exchange | Compatible | Official and Rust negotiated nested top-level paths |
| Official -> Rust regular-file download | Compatible | 70,000 and 98,304-byte cases matched byte hashes and metadata |
| Rust -> Official regular-file upload | Compatible | Official reached `STATE_VERIFY_DATA`, `POST_DOWNLOAD_WORK`, and completion |
| Bidirectional create/update/delete/recreate | Compatible | Reconciliation and tombstone transitions passed |
| Nested directory/file paths | Compatible | Dynamic top-level discovery included a nested official file |
| File-to-directory type change | Compatible | Losing value preserved and remote type installed |
| Local edit versus remote tombstone | Compatible | Local data archived before deletion |
| Concurrent edit/conflict | Compatible | Local value retained as `.Conflict`/`.ConflictN`; remote installed |
| Periodic reconnect and rescan | Compatible | Dial and accept paths rerun scan/reconciliation per session |
| Legacy TLS-PSK transport | Retained | Compatibility transport for older protocol paths |
| Standard Folder `A/B` key family | Compatible | `standard-B`/`standard-B-upstream` gates: official writes, Rust `B` reads, and the reverse |
| Standard Folder `D/E/F` key family | Implemented | Key derivation, role links, and official content transform |
| Encrypted-only `F` peers, both roles | Compatible | `F` dials and answers `D`/`E`; ciphertext name and bytes verified |
| Read-only `E` relay to/from `F` | Compatible | `E` serves the writer's signed entry to `F`; `E` decrypts from an `F` responder |
| Advanced Folder `G/H` | Out of scope | Explicitly rejected at parsing and API boundaries |

The reproducible official matrix completed all of these cases against the
upstream client 3.1.2 (build 1076):

```text
standard-A                        (standard folder, writable A key)
standard-B                        (official A writes, Rust B reads)
standard-B-upstream               (Rust A writes, official B reads)
encrypted-D                       (encrypted folder, writable D key)
read-only-E                       (official D writes, Rust E reads)
read-only-E-upstream              (Rust D writes, official E reads)
encrypted-only-official-F-reads   (Rust D writes, official F stores ciphertext)
encrypted-only-rust-F-reads       (official D writes, Rust F stores ciphertext)
encrypted-only-rust-F-responder   (Rust F serves, official D writes)
encrypted-only-official-F-responder (official F serves, Rust D reads)
read-only-E-serves-official-F     (read-only E relays the writer's entry to F)
read-only-E-reads-official-F      (read-only E decrypts from an F responder)
```

Every case in this list is a hard gate in the default `--key-family all` run;
the encrypted-only, read-only-relay, and standard read-only cases are not
opt-in. Both halves of the Standard Folder `A/B` family are covered, so the
read-only role is verified against the official client rather than assumed from
the writable one.

Run the matrix with `scripts/official_compat.py`, supplying a local official
binary and an empty work directory. The script creates temporary roots and a
writable A key, and fails if the official logs contain `unexpected packet`,
`failed to verify signature`, `Invalid have_pieces info`,
`must be merge slave for get_root`, `failed to verify metadata hash`, or
`bad signature`.

```bash
python3 scripts/official_compat.py \
  --official-bin ./upstream-client \
  --rust-bin target/debug/rustsync \
  --work-dir ./compat-work \
  --timeout 120
```

## Verified Invariants

- A/D keys provide the Ed25519 signing material required to originate signed
  metadata and DirectTorrent logins.
- B/E keys can authenticate and verify, but are not used to fabricate signed
  A/D metadata. F keys are encrypted-only and cannot decrypt content.
- A read-only `E` peer that relays a writer's content advertises the writer's
  Ed25519 public key and forwards the writer's signed entry byte-for-byte; it
  never fabricates a signature of its own. The relay identity is derived from
  public key material only, so no read-only secret is required.
- D derives E/F roles, E derives F, and D/E expose their derived keys through
  REST/Web UI. Advanced Folder keys are rejected.
- D/E/F piece nonces and AES-128 counter content transforms match the official
  implementation and are covered by fixture tests.
- The `epieces` field length is `16 + n*20 + (16 - (n*20 % 16))`; the padding
  always adds a full block when the SHA-1 hashes fill whole AES blocks, which is
  why the parser and `expected_torrent_info_size_for_shape` share
  `encrypted_folder::encrypted_epieces_len`.
- A read-only E peer interoperates with a writable official D peer: it receives
  content, updates, nested directories, empty files, metadata and deletions, and
  publishes nothing back (`read-only-E` case in `scripts/official_compat.py`).
- DirectTorrent `proto v3` login is answered with the official 3.1.2
  length-prefixed `{data, meta}` body; `proto v2` login is echoed and continues
  with metadata/request/piece messages in uncompressed tunnel DATA frames.
- Every file transfer verifies length, all 32 KiB SHA-1 pieces, the combined
  file hash, `rp = 4 * piece_count`, and the signed identity before apply.
- Downloads stage beside the destination and rename only after complete
  verification. A failed download cannot truncate an existing file.
- Unsafe paths containing empty, `.`, `..`, or `.sync` components are rejected.
- Recursive scans omit `.sync` and process nested paths after their parents.
- Synchronized metadata, local fingerprints, and file hashes are persisted so
  local-only, remote-only, and both-side changes are distinguishable.
- Local deletion creates a newer `state=2` tombstone by incrementing
  `write_times`. Recreation replaces it with a newer active record on the next
  scan, and local tree changes invalidate cached remote-version decisions.
- Concurrent merge requests are serialized by delaying non-initiator
  `get_root`, cancelling a local request when the peer's request arrives, and
  retrying unanswered root requests after the merge cooldown.

## Reconciliation Matrix

| Baseline | Local state | Remote state | Decision | Outcome |
|---|---|---|---|---|
| Equal | unchanged | unchanged/metadata-only | Equal | Adopt mode/mtime |
| Present | changed | unchanged | LocalWins | Advertise local entry |
| Present | unchanged | changed | RemoteWins | Apply remote entry |
| Present | changed | changed | Conflict | Preserve local; apply remote |
| Present | type X | type Y | Conflict | Preserve type X; install type Y |
| Active | tombstone | active | Conflict | Keep tombstone; remote to `.Conflict` |
| Active | edited | tombstone | Conflict | Archive edit; commit tombstone |
| Missing | present | present | Conflict | Preserve local; install remote |

Conflict siblings are named `<name>.Conflict`, `<name>.Conflict2`, and so on.
When a remote tombstone wins over a local edit, the local object is moved under
`.sync/Archive/<unix-time>-conflict-<name>`. Any preservation failure aborts
the destination replacement.

## Current Limits

- An encrypted-only `F` folder is read-only by construction: it holds no
  content key, so it stores the ciphertext verbatim under the encrypted path
  name and can never publish a plaintext object or sign metadata. It
  interoperates in both roles — the SRPEH response carries the responder's own
  role (`type=4` for an encrypted-only peer) and both sides derive the SRP
  password from that declaration, so an `F` folder both dials and answers
  `D`/`E` peers.
- A read-only `E` node interoperates with an encrypted-only `F` peer in both
  roles, verified against official client 3.1.2 build 1076:
  * *Read-only `E` serving an `F` peer.* The node relays the writer's content:
    a read-only share key carries no Ed25519 seed, so the node advertises the
    **writer's** public key (`ed25519(D_body ‖ 0×12)`) and forwards the writer's
    signed entry verbatim -- exactly what the official client does. A fresh
    encrypted-only official `F` peer then pulls the ciphertext from the
    read-only node alone and stores it under the encrypted path name
    (`read-only-relay-serve` case in `scripts/official_compat.py`).
  * *A read-only `E` node pulling from an official `F` folder.* The `F` peer
    advertises `type=4` in its SRPEH response; the node derives the 20-byte
    access key from that declaration and decrypts the ciphertext back to
    plaintext (`read-only-relay-read` case in `scripts/official_compat.py`).
  Both directions are hard gates in the default matrix, not opt-in.
- The upstream compatibility path has no tracker, relay, NAT traversal, or
  multi-source piece repair. The repository's independent HTTP tracker layer
  (`src/tracker.rs`) is used for peer-candidate discovery by `SyncNode`; it is
  not an upstream tracker wire implementation.
- Selective sync is implemented for the standalone scan and `SyncNode` scan
  paths through `src/selective.rs`; upstream wire negotiation does not carry a
  remote selection policy.
- Encrypted folders are an independent AES-256-GCM vault format in
  `src/encrypted.rs`; key rotation and streaming chunk manifests are not part
  of the v2 vault yet. The upstream Standard Folder D/E/F transform is
  implemented separately in `src/encrypted_folder.rs`.
- POSIX mode/uid/gid metadata is captured and enforceable in the standalone
  manifest/vault APIs. The upstream wire metadata currently carries mode/mtime;
  ACLs and cross-host user-name mapping remain outside the compatibility path.
- ACL merge-controller message names, `acl_hash`, `active_size`,
  `exclusive_merge_connection`, node offsets, and `get_files_next` are handled
  for compatibility. Empty ACL folders complete the exchange; full upstream
  certificate-chain, revoke, and managed-folder master/slave authorization
  semantics remain a focused follow-up. A peer `not_master` event is handled as
  a merge retry signal.
- No full GUI/WebUI implementation.
- A single peer session performs a complete reconciliation exchange and closes
  after a short settle interval; daemon modes repeat sessions and rescan.
- The nested directory hash formula and dynamic nested transfers are
  implemented, but an exhaustive official matrix for every timestamp corner
  case is not claimed.
- Upstream client 3.1.2 may skip a pure attribute-only job when its local `pvi`
  content state is already complete. `rustsync` adopts verified metadata-only
  updates without downloading unchanged content.
- Upstream client 3.1.2 normalizes tested `0600` and `0640` source modes to
  decimal `420` (`0644`) on the wire. The official matrix therefore verifies
  the observable `0644` result and exact mtime; byte hashes match exactly.

## Completion Boundary

`rustsync` is complete for the core Linux folder-synchronization path
needed for bidirectional interoperability with the upstream client 3.1.2. It
is not a feature-complete replacement for the entire upstream product.
Unsupported capabilities fail explicitly instead of silently discarding data.
