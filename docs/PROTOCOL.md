# Upstream Sync 3.1.2 Core Protocol Report

This report is the implementation-level protocol specification for the core
Linux folder-synchronization path in `rustsync`. It covers discovery,
connection/authentication, tunnel multiplexing, metadata merge, downloads,
uploads, reconciliation, conflicts, tombstones, retries, and byte framing.
The official-product boundary is recorded in `COMPATIBILITY.md`.

## 1. Layer Model

```text
LAN multicast / broadcast / loopback / known hosts
  -> RESSN discovery ping
  -> TCP peer candidate
  -> SRPEH authentication and AES-128 directional streams
  -> tunnel_connect / tunnel_accept
  -> V1/V2 tunnel multiplexer
  -> peer merge channels and DirectTorrent subchannels
  -> signed metadata + SHA-1 piece trees
  -> reconciliation state machine
  -> staged verified filesystem apply
```

Upstream client 3.1.2 direct-LAN connections use SRPEH. After the SRPEH final
message, the same TCP stream carries AES-encrypted bytes; SRPEH does not add a
second length frame to the application payload. Therefore the first encrypted
application frame is still `u32_be payload_length || payload`.

The code retains a legacy TLS-PSK transport for older paths. That transport is
not the 3.1.2 LAN transport verified by the current interoperability runs.

## 2. Discovery

### 2.1 Packet

```text
"RESSN\0" ||
bencode {
  m: "ping",
  peer: peer_id[20],
  port: TCP listen port,
  shares: [share_id[20], ...]
}
```

The advertised UDP destinations are `239.192.0.0:3838` multicast,
`255.255.255.255:3838` broadcast, and `127.0.0.1:3838` loopback. The receiving
endpoint derives the candidate as `source_ip:advertised_port`; it must not
trust the UDP source port.

### 2.2 State Machine

```text
BOUND
  -> BUILD_PING(peer, port, shares)
  -> SEND_MULTICAST + SEND_BROADCAST + SEND_LOOPBACK
  -> WAIT(1s)
  -> BUILD_PING ...

RECEIVE
  -> CHECK_MAGIC
  -> DECODE_STRICT_BENCODE
  -> CHECK m == "ping"
  -> CHECK peer == 20 bytes
  -> CHECK port in 1..=65535
  -> CHECK every share == 20 bytes
  -> CANDIDATE(source_ip, port, peer, shares)
  -> CONNECT
```

Invalid magic, trailing bytes, missing fields, non-byte values, or malformed
identifiers reject only that datagram. Discovery supplies candidates; it does
not authenticate the peer. Authentication occurs in SRPEH.

## 3. Share Key and Identity

| Key type | Read/write behavior | Authentication PSK | Metadata signing |
|---|---|---|---|
| `A` | writable | `SHA-1(Ed25519 public key)` | derived Ed25519 secret |
| `D` | writable | `SHA-1(Ed25519 public key)` | derived Ed25519 secret |
| `B` | read-only compatibility | decoded 20-byte key body | not available |
| `E` | read-only compatibility | decoded 20-byte key body | not available |

For all supported types:

```text
share_id = SHA-1(psk)[20]
```

The A/D `id.pk` field is the same 32-byte Ed25519 public key used to verify
file metadata. Sending an unrelated identity constant makes the official peer
report `bad_signature`.

## 4. SRPEH

### 4.1 Framing

The first request is unencrypted:

```text
"RESSN\0" || u32_be payload_length || bencode request
```

All later handshake messages before AES activation are:

```text
u32_be payload_length || bencode message
```

The maximum SRPEH frame is 16 KiB. After activation, the encrypted TCP byte
stream contains ordinary application frames without another SRPEH wrapper.

### 4.2 Handshake Byte Stream

```text
client -> server:
  "RESSN\0" || len || bencode {
    nonce: client_nonce[16],
    share: share_id[20],
    type?: integer
  }

server -> client:
  len || bencode {
    pub: server_public[],
    salt: salt[16]
  }

client -> server:
  len || bencode {
    pub: client_public[],
    resp: client_proof[20]
  }

server -> client:
  len || bencode {
    nonce: server_nonce[16],
    resp: server_proof[20]
  }

both directions:
  AES-128 encrypted raw application bytes
```

The server rejects a share mismatch before accepting the client proof. Both
proofs are mandatory; a peer that fails either proof is disconnected.

### 4.3 SRP Parameters and Proofs

The implementation uses generator `g = 2`, the observed 128-byte SRPEH
modulus `N`, a 16-byte random salt, and:

```text
inner       = SHA1(username || ":" || password)
x           = SHA1(salt || inner)
v           = g^x mod N
k           = SHA1(N || pad_to_N(g))
u           = SHA1(pad_to_N(A) || pad_to_N(B))

client A    = g^a mod N
server B    = (k*v + g^b) mod N
client key  = MGF1-SHA1((B - k*g^x)^(a + u*x) mod N, 40)
server key  = MGF1-SHA1((A*v^u)^b mod N, 40)

prefix      = SHA1(N) XOR SHA1(g) || SHA1(username) || salt
client resp = SHA1(prefix || A || B || key)[20]
server resp = SHA1(A || client_resp || key)[20]
```

`MGF1-SHA1` emits 40 bytes as `SHA1(shared || u32_be counter)` for counters
`0, 1`. `username` is the 20-byte share ID and `password` is the 20-byte PSK.

### 4.4 Directional AES Streams

The 40-byte SRP result is split as:

```text
session_key[0..16]   client -> server AES-128 key
session_key[16..20]  client -> server u32_be counter seed
session_key[20..36]  server -> client AES-128 key
session_key[36..40]  server -> client u32_be counter seed
```

Each direction has a 16-byte random nonce and:

```text
counter_offset = u32_be(seed) widened to u64
IV             = nonce XOR little_endian_u64(counter_offset) || 8 zero bytes
keystream      = AES-128-ECB(key, IV) for a 16-byte block
next_IV_input  = counter_offset + 16
ciphertext     = plaintext XOR continuous keystream
```

The counter advances by 16 for every AES block. State survives partial reads
and writes, so packet boundaries do not reset the stream.

### 4.5 SRPEH State Machine

```text
CLIENT                              SERVER
------                              ------
SEND_REQUEST                        READ_MAGIC
                                    READ_REQUEST
                                    CHECK_SHARE
READ_SERVER_PUBLIC                  SEND_SERVER_PUBLIC_SALT
VERIFY_PUBLICS
COMPUTE_KEY
SEND_CLIENT_PROOF                   READ_CLIENT_PROOF
                                    VERIFY_CLIENT_PROOF
READ_SERVER_PROOF                   SEND_SERVER_NONCE_PROOF
VERIFY_SERVER_PROOF
ACTIVATE_CLIENT_CIPHERS             ACTIVATE_SERVER_CIPHERS
---------- encrypted application stream ----------
```

Any length overflow, truncated frame, zero/invalid public value, proof
mismatch, or share mismatch terminates the connection before application data.

## 5. Tunnel Check

Immediately after SRPEH, each side exchanges one uncompressed peer frame:

```text
u32_be payload_length
bencode {
  encryption_required: 1,
  ifp: 100,
  m: "tunnel_connect" | "tunnel_accept",
  p: peer_id[20],
  v: "3.1.2"
}
```

The TCP initiator sends `tunnel_connect`; the listener validates it and replies
with `tunnel_accept`. Version `3.1.2`, `ifp=100`, and `encryption_required=1`
are mandatory.

## 6. Tunnel Multiplexer

### 6.1 V2 Packet

```text
0x02
u32_be total_length             // includes these 5 header bytes
packet_type: u8
connection_id: u32_be
body[total_length - 10]
```

Types:

| Value | Name | Body | Handling |
|---:|---|---|---|
| 1 | OPEN | empty | allocate/accept connection; reply ACK |
| 2 | ACK | empty | complete local OPEN |
| 3 | DATA | wire payload | append to per-connection buffer |
| 4 | CLOSE | empty | release connection; fail incomplete download |
| 5 | PING | opaque | echo on the same connection |
| 6 | DATA_COMPRESSED | zlib DATA | inflate and dispatch as DATA |

### 6.2 V1 Packet

```text
u16_be total_length             // includes the two length bytes
0x01
packet_type: u8
connection_id: u32_be
body[total_length - 8]
```

V2 is the normal implementation path. V1 is accepted for compatibility.
Zero connection IDs, malformed lengths, truncated packets, and oversized frames
are fatal connection errors. Late inbound or outbound data for an ID whose
CLOSE has already been observed is dropped.

### 6.3 Multiplexer State

```text
LOCAL_OPEN:
  choose_nonzero_id -> send OPEN -> WAIT_ACK -> OPEN

REMOTE_OPEN:
  validate_id -> add_known -> send ACK -> OPEN

OPEN:
  DATA / DATA_COMPRESSED -> BUFFER
  PING -> ECHO
  CLOSE -> RELEASE

LOCAL_CLOSE:
  remove_known -> send CLOSE -> CLOSED

PROTOCOL_ERROR:
  fail active downloads -> close TCP -> reconnect/reaccept
```

## 7. Wire Payload Framing

Each DATA body is one of:

```text
u32_be payload_length
optional zlib stream
bencode PeerMessage
```

or a DirectTorrent ident:

```text
"\x13BitTorrent proto v2" | "\x13BitTorrent proto v3"
u32_be bencode_length
bencode DirectTorrentMessage
```

Identity and DirectTorrent subchannel messages are emitted as uncompressed
DATA tunnel frames. Ordinary peer merge messages may use zlib only when
compression makes the frame smaller.

## 8. Peer Messages

| Message | Sender | Required/important fields | Receiver action |
|---|---|---|---|
| `id` | both | `m`, `name`, `peer`, `pk`, `share`, `tags`, `v` | validate identity/share/version |
| `get_root` | requester | `hash`, `time`, `force_full_merge`, `extra` | answer with local root |
| `root` | responder | `hash`, `time`, `your_time`, `force_full_merge`, `extra` | compare roots/times |
| `get_nodes` | requester | `paths: [{path: "/"}]` | answer top-level tree nodes |
| `nodes` | responder | `nodes: {path: node}` | update request-path set |
| `get_files` | requester | `paths: ["/", ...]` | answer exact/descendant entries |
| `files` | responder | `files: [{have, main, sig}]` | verify and reconcile |
| `get_have_pieces` | requester | none | answer local piece availability |
| `have_pieces` | responder | `bitlist`, `hash`, `prev_hash` | accept availability data |
| `state_notify` | both | `tree_hash`, `have_pieces_hash`, `m` | immediately request `get_root`; reconcile in the current session |
| `get_acl_nodes` / `acl_nodes` | merge peers | `acl_hash`, `nodes` | exchange ACL tree nodes before file nodes |
| `get_acl_entries` / `acl_entries` | merge peers | `acl_hash`, `offset`, `entries` | page signed ACL entries |
| `acl_entries_accepted` | merge peers | `acl_hash` | finish ACL merge and continue root/node exchange |
| `not_master` | merge peer | `m` | cancel the current merge attempt and retry as requester |

`id.pk` is the A/D metadata public key. `files.main` is signed with
`Ed25519_sign(SHA1(bencode(main)))`.

The upstream merge-controller also carries `acl_hash`, `active_size`,
`exclusive_merge_connection`, and node `offset` fields. `rustsync` emits and
recognizes these fields for forward compatibility. An empty ACL is represented
by the deterministic hash of an empty signed-entry list; ACL entry bodies use
the upstream `type`, `t`, `s`, `o`, `ot`, `issuer`, and `sig` vocabulary.

## 9. Metadata, Hashes, and Tree Nodes

| Object | Formula |
|---|---|
| Piece | `SHA1(piece_bytes)` |
| File | `SHA1(concat(piece_hash_0 ... piece_hash_n))` |
| Info hash | `SHA1(share_id || component_0 || 0x00 || ... || file_hash)` |
| Metadata signature | `Ed25519_sign(SHA1(bencode(main)))` |
| Root tree hash | `SHA1(concat(top_level_node_value))` |
| Leaf node value | `metadata_hash` |
| Directory node value | `SHA1(metadata_hash || SHA1(concat(child_node_values)))` |
| Node wire `file` | node value above |
| Directory metadata hash | hash of metadata fields with its computed node value |

Child values are ordered by UTF-8 path component. Path requests match an entry
when the requested wire path is the entry itself or a slash-delimited ancestor.

### 9.1 `write_times` and `have_pieces`

`write_times` is carried only when its low two bits are nonzero. Writers emit
`1`, `2`, or `3`; readers mask the field with `0x3` and normalize `0` away
before hashing. The metadata signature is computed over the canonical `main`
dictionary after that normalization, so the two-bit representation is part of
the signed compatibility contract.

`have_pieces.bitlist` has exactly one byte per tree node, including directory
nodes, zero-length files, and tombstones. The implementation uses `1` for a
complete local node and `2` for an incomplete node; a zero-length active file
is complete and therefore does not disappear from the bitlist. For a nonempty
tree, `hash = SHA1(tree_hash || bitlist)`. An empty tree uses
`SHA1(empty_input)`. The current snapshot exchange sends `prev_hash` as 20 zero
bytes.

## 10. Concurrent Merge Channels

The initiator and listener each open one merge tunnel connection:

```text
M_local: OPEN -> ID_SENT -> GET_ROOT_SENT -> ROOT_RECEIVED
       -> GET_NODES_SENT -> NODES_RECEIVED
       -> FILES_SENT + HAVE_SENT + GET_FILES_SENT
       -> FILES_RECEIVED -> DOWNLOADS_SCHEDULED -> SETTLING -> COMPLETE

M_peer: OPEN -> ID_RECEIVED -> GET_ROOT_RECEIVED -> ROOT_SENT
      -> GET_NODES_RECEIVED -> NODES_SENT
      -> FILES_SENT + HAVE_SENT
      -> GET_FILES_RECEIVED -> FILES_SENT -> COMPLETE
```

Responses always return on the connection carrying their request. `nodes`
may add top-level paths and trigger another path-scoped `get_files`.
Only the current merge connection may deliver `root`, `nodes`, `files`, and
`have_pieces` responses. Responses from a retired merge connection are ignored.
A local path change cancels transfers for that path, closes the old merge
connection, and starts reconciliation against the refreshed tree.

## 11. DirectTorrent Download State Machine

```text
REMOTE_METADATA_VERIFIED
  -> EMPTY_FILE? -> APPLY_EMPTY_FILE -> RECORD_BASELINE -> FILE_PRESENT
  -> NONEMPTY_FILE -> NEED_DATA
  -> TUNNEL_OPEN
  -> LOGIN_SENT {
       f: relative_path,
       i: info_hash[20],
       p: requester_peer_id[20],
       s: share_id[20],
       sig: Ed25519 signature[64]
     }
  -> IDENT_VERSION_SELECTED
     | proto v3 -> CONTENT_BODY_RECEIVED {data, meta} -> PARSE_META
     | proto v2 -> LOGIN_ECHOED
                  -> EXTENDED_HANDSHAKE_SENT
                  -> INTERESTED + UNCHOKED
                  -> METADATA_REQUESTED/RECEIVED -> PARSE_INFO
                  -> PIECES_REQUESTED/RECEIVED
  -> CHECK_FILE_HASH
  -> CHECK_INFO_SIZE
  -> CHECK_PIECE_HASH_ARRAY
  -> CHECK_RP_LENGTH
  -> CHECK_DATA_LENGTH
  -> CHECK_LENGTH
  -> CHECK_ALL_PIECE_HASHES
  -> POST_DOWNLOAD_WORK
  -> STAGE_COMPLETE
  -> APPLY_MODE_MTIME
  -> ATOMIC_RENAME
  -> RECORD_BASELINE
  -> TUNNEL_CLOSE
  -> FILE_PRESENT
```

Official logs expose the corresponding transitions:

```text
DOWNLOAD -> STATE_VERIFY_DATA -> POST_DOWNLOAD_WORK
         -> Finished post-download-work
         -> Finished downloading file
```

The initial DirectTorrent frame is:

```text
"\\x13BitTorrent proto v2" ||
u32_be login_bencode_length ||
bencode(login)
```

The requester sends one complete login. The responder validates `f`, `i`, the
optional `p`/`s` fields, and `sig`. The ident magic selects one of two official
3.1.2 response modes.

For `proto v3`, the responder sends one length-prefixed bencoded content body
without another login or BitTorrent handshake:

```text
u32_be content_bencode_length ||
bencode({
  data: complete_file_bytes,
  meta: bencode({info: torrent_info})
})
```

For `proto v2`, the responder echoes the complete login and the subchannel then
carries BEP-3-style length-prefixed BitTorrent messages. The extension handshake
is opcode `0x14`, extension ID `0`; metadata requests and responses use the
negotiated `ut_metadata` ID. Each metadata piece is at most 16 KiB. File blocks
use request (`0x06`) and piece (`0x07`) messages. Both modes require the same
encoded `info` dictionary with `length`, `"piece length"` (32768), `pieces`, and
`rp`; `rp` must be exactly `4 * piece_count` bytes.

Sending another ident prefix after login is rejected as the invalid length
`0x13426974` (`"BitT"`). Sending a `proto v3` content body in `proto v2` mode is
rejected as `Wrong ident`; sending content without `f`/`i` is rejected as
`Invalid header v2`. Any verification failure moves the download to `ERROR` and
leaves the destination untouched.

## 12. DirectTorrent Upload State Machine

```text
REMOTE_METADATA_READY
  -> LOAD_LOCAL_META
  -> READ_LOGIN {
       f, i, optional p/s, sig
     }
  -> CHECK_PATH_AND_FILE_HASH
  -> CHECK_OPTIONAL_PEER_AND_SHARE
  -> CHECK_INFO_HASH
  -> CHECK_SIGNATURE
  -> IDENT_VERSION_SELECTED
     | proto v3 -> BUILD_CONTENT_BODY {data, meta}
                  -> SEND_LENGTH_PREFIXED_CONTENT_BODY
                  -> TUNNEL_CLOSE
     | proto v2 -> SEND_ECHOED_LOGIN
                  -> WAIT_EXTENDED_HANDSHAKE
                  -> SEND_METADATA_SIZE + UT_METADATA_ID
                  -> SEND_BITFIELD(all pieces)
                  -> SEND_UNCHOKED
                  -> WAIT_METADATA_REQUEST[msg_type=0, piece=i]
                  -> SEND_METADATA_RESPONSE[msg_type=1, piece=i, total_size]
                  -> WAIT_INTERESTED
                  -> WAIT_PIECE_REQUEST[index, begin, length]
                  -> CHECK_REQUEST_BOUNDS
                  -> SEND_PIECE_RESPONSE[index, begin, data]
                  -> WAIT_REQUESTS_OR_CLOSE
                  -> TUNNEL_CLOSE
```

`proto v3` serves the authenticated aggregate `{data, meta}` response. `proto
v2` serves only authenticated metadata and requested blocks. Path, share, file
hash, info-hash, signature, metadata-size, or piece-bound failure closes only
that DirectTorrent subchannel and never sends unrequested or out-of-range
content.

## 13. Local Scan and State

```text
SCAN_ROOT
  -> LOCK_SYNC_STATE
  -> OMIT .sync
  -> ENUMERATE_FILES_DIRECTORIES
  -> VALIDATE_RELATIVE_PATH
  -> HASH_32K_PIECES
  -> BUILD_METADATA
  -> SIGN_A_D_METADATA
  -> COMPARE_WITH_PERSISTED_BASELINE
  -> ACTIVE_MISSING -> INCREMENT_WRITE_TIMES -> SIGN_DELETED_TOMBSTONE
  -> TOMBSTONE_RECREATED -> INCREMENT_WRITE_TIMES -> SIGN_ACTIVE_METADATA
  -> SAVE_STATE
```

Three baselines are persisted per path:

```text
sync_metadata_hash  // last synchronized signed metadata
sync_fingerprint    // local type, mode, size, mtime, content hash
sync_file_hash      // last synchronized upstream file hash
```

Unsafe components `""`, `.`, `..`, and `.sync` are rejected. Temporary files
are created beside the destination and renamed only after complete verification.

## 14. Reconciliation State Machine

```text
FILES_RECEIVED
  -> PARSE_METADATA
  -> VERIFY_SIGNATURE
  -> METADATA_HASH_ALREADY_RECONCILED? -> SKIP_UNCHANGED_VERSION
  -> NEW_METADATA_VERSION
  -> CANCEL_STALE_DOWNLOADS_FOR_PATH
  -> LOCAL_TREE_CHANGED -> INVALIDATE_RECONCILED_VERSION_CACHE
  -> FOR_EACH_PATH:
       metadata_hash equal?             -> EQUAL
       entry type differs?              -> CONFLICT
       no synchronized baseline?        -> CONFLICT
       local fingerprint/hash unchanged? -> REMOTE_WINS
       remote file/metadata unchanged?  -> LOCAL_WINS
       otherwise                        -> CONFLICT
  -> APPLY_DECISION
  -> SAVE_BASELINE
  -> SETTLE
```

The merge loop keeps the convergence trigger in the same live session:

```text
LOCAL_ROOT_CHANGED
  -> STATE_NOTIFY(tree_hash, have_pieces_hash)
  -> GET_ROOT

REMOTE_STATE_NOTIFY
  -> GET_ROOT

ROOT_RECEIVED
  -> root equal -> PIECE_COMPARE -> STEADY
  -> root differs -> GET_NODES -> GET_FILES -> RECONCILE -> TRANSFERS
```

| Decision | Active file | Tombstone | Directory/type change |
|---|---|---|---|
| EQUAL | adopt metadata; no transfer | retain tombstone | retain directory |
| LOCAL_WINS | retain and advertise local | retain local tombstone | retain local type |
| REMOTE_WINS | atomically replace | remove local path | create directory or replace type |
| CONFLICT | preserve local; install remote | archive local edit; commit tombstone | preserve losing type; install remote type |

No synchronized baseline is treated as a conflict to avoid silently overwriting
an unrelated destination. Reconciliation is keyed by the current remote
metadata hash, not only by path. A later tombstone or replacement metadata
version is therefore processed even when an older version for the same path was
already reconciled; downloads for that older version are closed before the new
decision is applied.

## 15. Conflict and Tombstone State Machine

```text
BASELINE
  --local only--> LOCAL_EDIT
  --remote only--> REMOTE_EDIT
  --both/type race--> CONFLICT

LOCAL_EDIT --remote active--> RENAME_LOCAL_CONFLICT
                            -> WRITE_REMOTE_ORIGINAL

LOCAL_EDIT --remote tombstone--> MOVE_LOCAL_TO_ARCHIVE
                              -> COMMIT_TOMBSTONE

LOCAL_TOMBSTONE --remote active--> KEEP_TOMBSTONE_AT_ORIGINAL
                                 -> WRITE_REMOTE_TO_CONFLICT_SIBLING

ANY_PRESERVE_FAILURE--> ABORT_BEFORE_DESTINATION_REPLACEMENT
```

Conflict siblings are `<name>.Conflict`, `<name>.Conflict2`, and so on.
Delete-race archives use `.sync/Archive/<unix-time>-conflict-<name>`. A local
deletion is represented by `state=2` and increments `write_times`; recreation
becomes `state=1` on the next scan and increments it again. A local tree change
invalidates the per-path remote-version cache, so unchanged remote active
metadata is reconsidered against the new local tombstone or replacement
instead of being skipped or resurrecting the deleted path.

## 16. Session, Reconnect, and Error State Machines

```text
DIAL:
  DISCONNECTED -> TCP_CONNECTING -> SRPEH_CLIENT
               -> TUNNEL_CHECK -> MERGE_EXCHANGE
               -> TRANSFERS -> SETTLE -> CLOSE -> WAIT_SHORT
               -> DISCONNECTED
  TCP/PROTOCOL/IO failure -> WAIT_BACKOFF(1s..60s) -> TCP_CONNECTING

ACCEPT:
  LISTENING -> ACCEPT -> DETECT_SRPEH_OR_LEGACY
            -> TUNNEL_CHECK -> MERGE_EXCHANGE
            -> TRANSFERS -> SETTLE -> CLOSE
            -> LISTENING
  peer failure affects only that handler; listener remains active
```

Error classes:

| Error | Action |
|---|---|
| SRPEH auth/proof/frame | close TCP before application state |
| tunnel protocol | close TCP and active subchannels |
| late data/close on retired subchannel | discard it without failing the current session |
| metadata signature/hash | reject entry; continue unrelated entries |
| download verification | discard staged data; preserve destination |
| conflict preservation | abort before destination replacement |
| transient TCP/IO | reconnect with capped exponential backoff |
| clean EOF after successful reconciliation | return success; daemon reconnects |

Each accepted or dialed session performs a fresh filesystem scan and complete
reconciliation. Local and remote `state_notify` messages trigger an immediate
`get_root` comparison in that session. The session then settles and closes;
daemon modes repeat the cycle, which provides periodic rescan and reconnect
behavior without requiring a permanently open merge channel.
