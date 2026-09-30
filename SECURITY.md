# Security

## Publication boundary

The public repository must contain source, tests, documentation and synthetic
examples only. Never publish:

- share keys, passwords, API tokens, cookies, certificates or private keys;
- Telegram credentials or chat IDs;
- absolute workstation/server paths;
- Telethon sessions, SQLite databases, `runs/`, logs, screenshots or captures;
- runtime configuration from upstream or any other service.

The `inspect-key` command prints only public metadata and whether PSK material
is available. It never prints key bytes.

## Threat model

The native TCP protocol has no TLS in this release and is suitable only for a
trusted test network. It verifies manifest, file and piece hashes but does not
authenticate peers. Use the upstream compatibility layer only with keys and
networks you control, and treat the official-client boundary as a fail-closed
compatibility gate.
