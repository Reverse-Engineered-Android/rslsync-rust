# REST API

The management server serves JSON under `/api/v1` and the bundled web client
from `/`. Requests larger than 1 MiB are rejected.

## Authentication

- `GET /api/v1/status` and `GET /api/v1/health` are public.
- When no password is configured, management endpoints are available for
  initial setup.
- When a password is configured, direct peer IPs matching the exempt IP/CIDR
  list do not need a password.
- Other clients must send `Authorization: Bearer <token>` or the
  `rustsync_session` cookie returned by login.
- Password changes invalidate existing sessions.

Login and logout:

```http
POST /api/v1/auth/login
Content-Type: application/json

{"password":"change-me"}
```

```http
POST /api/v1/auth/logout
Authorization: Bearer <token>
```

## Settings

```http
GET /api/v1/settings
PUT /api/v1/settings
DELETE /api/v1/password
```

`PUT /api/v1/settings` accepts any of these fields:

```json
{
  "password": "new-password",
  "clear_password": false,
  "password_exempt_ips": ["127.0.0.0/8", "::1/128"]
}
```

`password` and `clear_password` are mutually exclusive. Passwords must contain
8 to 1024 characters and are stored only as Argon2 hashes.

## Folders

```http
GET    /api/v1/folders
POST   /api/v1/folders
GET    /api/v1/folders/<id>
PUT    /api/v1/folders/<id>
DELETE /api/v1/folders/<id>
POST   /api/v1/folders/<id>/scan
POST   /api/v1/folders/<id>/sync
GET    /api/v1/folders/<id>/sync
PUT    /api/v1/folders/<id>/sync
POST   /api/v1/folders/<id>/links/generate
GET    /api/v1/sync/runs
```

Create payload:

```json
{
  "name": "Documents",
  "path": "/srv/sync/documents",
  "include": "docs/**,*.md",
  "exclude": "private/**,*.tmp",
  "enabled": true,
  "sync": {
    "access": "read-write",
    "peers": ["192.168.1.20:22000"],
    "auto_sync": true,
    "sync_interval_seconds": 300
  }
}
```

Paths must be existing absolute directories. Paths are canonicalized and
duplicate registrations are rejected. Include/exclude syntax is the same
comma-separated selection language used by `rustsync scan`. A folder scan
writes the normal `.rustsync-manifest.json` manifest below its root and stores
the scan summary in server state.

Set `"sync": {"link": "<raw key or rustsync URI>"}` to import a Standard
Folder. Supported link keys are `A`/`D` for read-write and `B`/`E` for
read-only. A URI can carry explicit peers:

```text
rustsync://A...?access=read-write&peer=192.168.1.20%3A22000&device=desktop
```

Generated share keys and links are returned only by creation or
`links/generate`; normal folder listings expose the key type and share ID but
never the secret key. The generate endpoint returns a `B` compatibility link
derived from an existing `A`/`D` folder key when read-only access is selected;
the folder remains read-write and keeps its original key.

`POST .../sync` starts a manual run and returns `202` with a run record. The
other two `sync` endpoints return run status/history and update automatic
synchronization settings without replacing the stored key. Include/exclude
rules are applied to every automatic and manual run as selective
synchronization.

Resilio Sync Advanced Folders and ACLs are outside this compatibility scope.
The repository does not implement the encrypted Standard Folder key and data
format, so encrypted links are not accepted.

## Direct Core Operations

These endpoints execute the same Rust functions as the corresponding local
CLI commands:

| Endpoint | CLI equivalent |
| --- | --- |
| `POST /api/v1/operations/scan` | `scan` |
| `POST /api/v1/operations/apply` | `apply` |
| `POST /api/v1/operations/pull` | `pull` |
| `POST /api/v1/operations/keys/generate` | `generate-key` |
| `POST /api/v1/operations/keys/inspect` | `inspect-key` |
| `POST /api/v1/operations/ping/encode` | `encode-ping` |
| `POST /api/v1/operations/vault/encrypt` | `encrypt-tree` |
| `POST /api/v1/operations/vault/decrypt` | `decrypt-tree` |
| `POST /api/v1/operations/tracker/announce` | `tracker-announce` |

Examples:

```json
{
  "root": "/srv/sync/documents",
  "output": null,
  "include": "docs/**",
  "exclude": "private/**"
}
```

```json
{
  "source": "/srv/source",
  "target": "/srv/target",
  "manifest": null,
  "conflict": "overwrite",
  "permissions": "preserve"
}
```

```json
{
  "source": "/srv/plain",
  "destination": "/srv/vault",
  "passphrase": "change-me"
}
```

Generated keys and vault passphrases are sensitive response/request values.
Use HTTPS through a trusted reverse proxy before exposing the API beyond a
trusted local network.

## Static Client

- `GET /` and `GET /index.html`
- `GET /app.js`
- `GET /styles.css`

The client uses same-origin JSON requests and the session cookie. Responses
include a restrictive Content Security Policy and `nosniff`.
