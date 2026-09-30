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

The reproducible official matrix completed all of these cases against the
upstream client 3.1.2 (build 1076):

```text
create-multi-piece-both-directions
update-multi-piece-both-directions
delete-both-directions
recreate-both-directions
nested-directories-and-empty-files-both-directions
official-to-Rust-file-metadata
Rust-to-official-file-metadata
rust-to-official-file-to-directory-change
official-to-Rust-file-to-directory-change
```

Run the matrix with `scripts/official_compat.py`, supplying a local official
binary and an empty work directory. The script creates temporary roots and a
writable A key, and fails if the official logs contain `unexpected packet`,
`failed to verify signature`, `Invalid have_pieces info`, or
`must be merge slave for get_root`.

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
  A/D metadata.
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

- No tracker, relay, NAT traversal, or multi-source piece repair.
- No selective sync, ignore patterns, or partial trees.
- No encrypted-folder key rotation or encrypted-storage state format.
- No owner/group/ACL synchronization; only file mode and mtime are applied.
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
