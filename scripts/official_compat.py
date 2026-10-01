#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from pathlib import Path


PEER_ID = "1337133713371337133713371337133713371337"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
OFFICIAL_NORMALIZED_MODE = 0o644
OFFICIAL_LOG_FORBIDDEN = (
    "unexpected packet",
    "failed to verify signature",
    "invalid have_pieces info",
    "must be merge slave for get_root",
    # A peer that publishes a torrent whose `pieces` do not describe the bytes
    # in `data` is rejected and banned, which is what the encrypted-folder
    # ciphertext/plaintext split got wrong before.
    "failed to verify metadata hash",
    "responsible for metadata not being loaded",
    "bad signature",
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


OFFICIAL_PORT_BAND_START = 20000
OFFICIAL_PORT_BAND_END = 32000


def reserve_official_ports(count):
    """Distinct TCP+UDP-reservable ports for `count` official peers.

    `official_listening_port` always restarts its scan, so calling it twice in
    one harness hands out the same port twice and the second official peer
    silently falls back to `port + 1`. This hands out distinct ports instead.
    """
    ports = []
    for port in range(OFFICIAL_PORT_BAND_START, OFFICIAL_PORT_BAND_END):
        if len(ports) == count:
            break
        if any(port == taken for taken in ports):
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.bind(("0.0.0.0", port))
            except OSError:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                try:
                    tcp.bind(("0.0.0.0", port))
                except OSError:
                    continue
                ports.append(port)
    if len(ports) != count:
        raise RuntimeError(f"unable to reserve {count} TCP+UDP official ports")
    return ports


def official_listening_port():
    """Reserve a port the official peer can bind for *both* TCP and UDP.

    The official client binds its peer port twice: once for TCP and once for its
    UDP discovery socket. When the UDP bind loses a race it silently falls back
    to `port + 1` (`UDP port bind failed ...: 98`) while the harness keeps
    dialing the configured port, so a dialer knocks on a port nothing listens
    on. Ports are drawn from a band *outside* `ip_local_port_range`
    (32768-60999), so no unrelated outbound connection can steal the UDP half
    between the probe and the official client's own bind.
    """
    for port in range(OFFICIAL_PORT_BAND_START, OFFICIAL_PORT_BAND_END):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                udp.bind(("0.0.0.0", port))
            except OSError:
                continue
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                try:
                    tcp.bind(("0.0.0.0", port))
                except OSError:
                    continue
                return port
    raise RuntimeError("unable to reserve a TCP+UDP port for the official peer")


def wait_until(predicate, timeout, description):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise RuntimeError(f"timed out waiting for {description}")


def wait_same_file(left_path, right_path, expected_hash, timeout):
    def synchronized():
        return (
            left_path.is_file()
            and right_path.is_file()
            and sha256(left_path) == expected_hash
            and sha256(right_path) == expected_hash
        )

    wait_until(synchronized, timeout, f"{left_path.name} byte synchronization")


def wait_absent(left_path, right_path, timeout):
    wait_until(
        lambda: not left_path.exists() and not right_path.exists(),
        timeout,
        f"{left_path.name} deletion synchronization",
    )


def apply_metadata(path, mode, mtime):
    path.chmod(mode)
    os.utime(path, (mtime, mtime))


def metadata_state(path):
    stat_result = path.stat()
    return stat_result.st_mode & 0o7777, stat_result.st_mtime


def assert_official_logs_clean(log_paths):
    failures = []
    for log_path in log_paths:
        if not log_path.is_file():
            continue
        for line_number, line in enumerate(
            log_path.read_text(errors="replace").splitlines(), start=1
        ):
            normalized = line.casefold()
            for marker in OFFICIAL_LOG_FORBIDDEN:
                if marker in normalized:
                    failures.append(f"{log_path.name}:{line_number}: {marker}")
    if failures:
        raise RuntimeError("official compatibility log errors: " + "; ".join(failures))


class OfficialApi:
    def __init__(self, port, password):
        self.base_url = f"http://127.0.0.1:{port}/gui/"
        encoded = base64.b64encode(f"admin:{password}".encode()).decode()
        self.headers = {
            "Authorization": f"Basic {encoded}",
            "User-Agent": "rustsync-official-compat",
        }
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(CookieJar())
        )
        self.token = self._read_token()

    def _request(self, url, data=None):
        request = urllib.request.Request(url, data=data, headers=self.headers)
        with self.opener.open(request, timeout=10) as response:
            return response.read()

    def _read_token(self):
        deadline = time.monotonic() + 20
        while True:
            try:
                page = self._request(self.base_url + "token.html", b"").decode()
                match = re.search(r">([^<]+)<", page)
                if not match:
                    raise RuntimeError("official WebUI token was not present")
                return match.group(1)
            except Exception:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.2)

    def action(self, action, **parameters):
        query = {
            "token": self.token,
            "action": action,
            "t": str(int(time.time() * 1000)),
        }
        query.update(parameters)
        url = self.base_url + "?" + urllib.parse.urlencode(query)
        payload = json.loads(self._request(url))
        if payload.get("status") not in (None, 200):
            raise RuntimeError(f"official API {action} failed: {payload}")
        return payload


def start_process(command, log_path, environment=None):
    log_handle = log_path.open("wb")
    process = subprocess.Popen(
        command,
        stdout=log_handle,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        env=environment,
    )
    return process, log_handle


def stop_process(process):
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait()


def official_bound_peer_port(log_path):
    """The TCP peer port the official client actually bound.

    Read back from its own log so a silent port fallback can never be mistaken
    for a protocol failure.
    """
    if not log_path.is_file():
        return None
    pattern = re.compile(
        r"bound listening socket \d+ to IP 0\.0\.0\.0:(\d+)"
    )
    found = None
    for line in log_path.read_text(errors="replace").splitlines():
        match = pattern.search(line)
        if match:
            # Keep scanning: a UDP collision makes the client re-bind on
            # `port + 1` and only the last bind is the one peers can reach.
            found = int(match.group(1))
    return found


def verify_version(official_bin):
    output = subprocess.check_output(
        [str(official_bin), "--help"], stderr=subprocess.STDOUT, text=True
    )
    if "3.1.2 (1076)" not in output:
        raise RuntimeError("official binary is not upstream client 3.1.2 build 1076")


def generate_share_key(rust_bin, family):
    return subprocess.check_output(
        [
            str(rust_bin),
            "generate-key",
            "--read-write",
            "--key-family",
            family,
        ],
        text=True,
    ).strip()


ROLE_FOR_KEY_TYPE = {"E": "read-only", "F": "encrypted"}
def derive_share_key(rust_bin, key, role):
    role = ROLE_FOR_KEY_TYPE.get(role, role)
    return subprocess.check_output(
        [str(rust_bin), "generate-key", "--from", key, "--derive", role],
        text=True,
    ).strip()


def inspect_share(rust_bin, key, allow_read_only=False):
    output = subprocess.check_output(
        [str(rust_bin), "inspect-key", key], text=True
    )
    values = dict(
        line.split("=", 1)
        for line in output.splitlines()
        if "=" in line
    )
    allowed = {"A", "D", "B", "E", "F"} if allow_read_only else {"A", "D"}
    if values.get("type") not in allowed:
        raise RuntimeError("generated key is not a writable A/D key")
    return values


def configure_official(
    config_path, storage_path, official_root, webui_port, listening_port=0
):
    config = {
        "device_name": "official-compat",
        "storage_path": str(storage_path),
        "listening_port": listening_port,
        "use_upnp": False,
        "folder_rescan_interval": 1,
        "webui": {
            "listen": f"127.0.0.1:{webui_port}",
            "login": "admin",
            "password": "research",
            "allow_empty_password": False,
        },
    }
    config_path.write_text(json.dumps(config))
    return official_root


def run_matrix(official_root, rust_root, timeout):
    results = []

    rust_multi = b"R" * 98304
    official_multi = b"O" * 70000
    rust_hash = hashlib.sha256(rust_multi).hexdigest()
    official_hash = hashlib.sha256(official_multi).hexdigest()
    (rust_root / "rust-multi.bin").write_bytes(rust_multi)
    (official_root / "official-multi.bin").write_bytes(official_multi)
    wait_same_file(rust_root / "rust-multi.bin", official_root / "rust-multi.bin", rust_hash, timeout)
    wait_same_file(
        official_root / "official-multi.bin", rust_root / "official-multi.bin", official_hash, timeout
    )
    results.append("create-multi-piece-both-directions")

    rust_multi = b"R2" * 45000
    official_multi = b"O2" * 43000
    rust_hash = hashlib.sha256(rust_multi).hexdigest()
    official_hash = hashlib.sha256(official_multi).hexdigest()
    (rust_root / "rust-multi.bin").write_bytes(rust_multi)
    (official_root / "official-multi.bin").write_bytes(official_multi)
    wait_same_file(rust_root / "rust-multi.bin", official_root / "rust-multi.bin", rust_hash, timeout)
    wait_same_file(
        official_root / "official-multi.bin", rust_root / "official-multi.bin", official_hash, timeout
    )
    results.append("update-multi-piece-both-directions")

    (rust_root / "rust-multi.bin").unlink()
    (official_root / "official-multi.bin").unlink()
    wait_absent(rust_root / "rust-multi.bin", official_root / "rust-multi.bin", timeout)
    wait_absent(official_root / "official-multi.bin", rust_root / "official-multi.bin", timeout)
    results.append("delete-both-directions")

    (rust_root / "rust-multi.bin").write_bytes(b"R3")
    (official_root / "official-multi.bin").write_bytes(b"O3")
    wait_same_file(
        rust_root / "rust-multi.bin",
        official_root / "rust-multi.bin",
        hashlib.sha256(b"R3").hexdigest(),
        timeout,
    )
    wait_same_file(
        official_root / "official-multi.bin",
        rust_root / "official-multi.bin",
        hashlib.sha256(b"O3").hexdigest(),
        timeout,
    )
    results.append("recreate-both-directions")

    for source_root, target_root, prefix in (
        (official_root, rust_root, "official"),
        (rust_root, official_root, "rust"),
    ):
        nested = source_root / f"{prefix}-nested" / "deep" / "leaf"
        nested.mkdir(parents=True)
        payload_path = nested / "payload.bin"
        empty_path = source_root / f"{prefix}-nested" / "empty.bin"
        payload_path.write_bytes(f"{prefix}-nested".encode())
        empty_path.write_bytes(b"")
        wait_same_file(
            payload_path,
            target_root / f"{prefix}-nested" / "deep" / "leaf" / "payload.bin",
            hashlib.sha256(f"{prefix}-nested".encode()).hexdigest(),
            timeout,
        )
        wait_until(
            lambda: (target_root / f"{prefix}-nested" / "empty.bin").is_file() and (
                target_root / f"{prefix}-nested" / "empty.bin"
            ).stat().st_size == 0,
            timeout,
            f"{prefix} nested empty file",
        )
    results.append("nested-directories-and-empty-files-both-directions")

    official_metadata = official_root / "official-metadata.bin"
    official_metadata.write_bytes(b"metadata-content")
    wait_same_file(
        official_metadata,
        rust_root / "official-metadata.bin",
        hashlib.sha256(b"metadata-content").hexdigest(),
        timeout,
    )
    apply_metadata(official_metadata, 0o640, 1_700_000_100)
    wait_until(
        lambda: metadata_state(rust_root / "official-metadata.bin")
        == (OFFICIAL_NORMALIZED_MODE, 1_700_000_100),
        timeout,
        "official-to-Rust file metadata",
    )
    results.append("official-to-Rust-file-metadata")

    rust_metadata = rust_root / "rust-metadata.bin"
    rust_metadata.write_bytes(b"metadata-content-from-rust")
    wait_same_file(
        rust_metadata,
        official_root / "rust-metadata.bin",
        hashlib.sha256(b"metadata-content-from-rust").hexdigest(),
        timeout,
    )
    apply_metadata(rust_metadata, 0o600, 1_700_000_200)
    wait_until(
        lambda: metadata_state(official_root / "rust-metadata.bin")
        == (OFFICIAL_NORMALIZED_MODE, 1_700_000_200),
        timeout,
        "Rust-to-official file metadata",
    )
    results.append("Rust-to-official-file-metadata")

    rust_type = rust_root / "rust-type-change"
    rust_type.write_bytes(b"file")
    wait_same_file(
        rust_type,
        official_root / "rust-type-change",
        hashlib.sha256(b"file").hexdigest(),
        timeout,
    )
    rust_type.unlink()
    rust_type.mkdir()
    (rust_type / "inside.bin").write_bytes(b"directory-content")
    wait_same_file(
        rust_type / "inside.bin",
        official_root / "rust-type-change" / "inside.bin",
        hashlib.sha256(b"directory-content").hexdigest(),
        timeout,
    )
    results.append("rust-to-official-file-to-directory-change")

    official_type = official_root / "official-type-change"
    official_type.write_bytes(b"file")
    wait_same_file(
        official_type,
        rust_root / "official-type-change",
        hashlib.sha256(b"file").hexdigest(),
        timeout,
    )
    official_type.unlink()
    official_type.mkdir()
    (official_type / "inside.bin").write_bytes(b"directory-content")
    wait_same_file(
        official_type / "inside.bin",
        rust_root / "official-type-change" / "inside.bin",
        hashlib.sha256(b"directory-content").hexdigest(),
        timeout,
    )
    results.append("official-to-Rust-file-to-directory-change")

    return results


# --- Encrypted-folder primitives -------------------------------------------
#
# An encrypted-only (`F`) peer has no content key, so it stores the on-disk
# object under the *encrypted* path name and keeps the ciphertext verbatim.
# These helpers reproduce that transform so the encrypted-only cases can assert
# on exact names and bytes. They are self-checked against the official vectors
# captured from client 3.1.2 build 1076.

BASE32_ALPHABET = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
PIECE_LENGTH = 32 * 1024


def base32_decode(text):
    accumulator = 0
    bits = 0
    output = bytearray()
    for character in text:
        accumulator = (accumulator << 5) | BASE32_ALPHABET.index(character.encode())
        bits += 5
        if bits >= 8:
            bits -= 8
            output.append((accumulator >> bits) & 0xFF)
    return bytes(output)


def base32_encode(data):
    accumulator = 0
    bits = 0
    output = bytearray()
    for byte in data:
        accumulator = (accumulator << 8) | byte
        bits += 8
        while bits >= 5:
            bits -= 5
            output.append(BASE32_ALPHABET[(accumulator >> bits) & 0x1F])
    if bits:
        output.append(BASE32_ALPHABET[(accumulator << (5 - bits)) & 0x1F])
    return output.decode()


def _openssl(args, payload):
    return subprocess.run(
        ["openssl", "enc", *args, "-nopad", "-nosalt"],
        input=payload,
        capture_output=True,
        check=True,
    ).stdout


def _transform_piece(content_key, piece_hash, offset, piece):
    base_nonce = hashlib.sha1(
        content_key + piece_hash + offset.to_bytes(8, "little")
    ).digest()[:16]
    output = bytearray(piece)
    for block_index in range(0, len(output), 16):
        counter = bytearray(base_nonce)
        absolute = (offset + block_index).to_bytes(8, "little")
        for index in range(8):
            counter[index] ^= absolute[index]
        keystream = _openssl(
            ["-aes-128-ecb", "-K", content_key.hex()], bytes(counter)
        )
        for index in range(min(16, len(output) - block_index)):
            output[block_index + index] ^= keystream[index]
    return bytes(output)


def encrypt_content(content_key, plaintext):
    output = bytearray(plaintext)
    for offset in range(0, len(plaintext), PIECE_LENGTH):
        chunk = plaintext[offset:offset + PIECE_LENGTH]
        output[offset:offset + len(chunk)] = _transform_piece(
            content_key, hashlib.sha1(chunk).digest(), offset, chunk
        )
    return bytes(output)


def encrypted_path_name(content_key, component):
    raw = component.encode()
    padding = 16 - (len(raw) % 16)
    prefix = hashlib.sha1(raw + b"" + content_key).digest()[:8]
    wrapped = _openssl(
        ["-aes-128-cbc", "-K", content_key.hex(), "-iv", (prefix + b"\x00" * 8).hex()],
        raw + bytes([padding]) * padding,
    )
    return base32_encode(prefix + wrapped)


def content_key_for_read_only_key(read_only_key):
    body = base32_decode(read_only_key[1:])
    if len(body) != 36:
        raise RuntimeError("read-only encrypt-capable key body is not 36 bytes")
    return body[20:36]


def _self_check_encrypted_primitives():
    read_only = "EH5L5UOAVPTVUQTRQRVGFD5XGUQB5B6ZDZR47LKBWQANFZSCU5CTMTFG3CI"
    content_key = content_key_for_read_only_key(read_only)
    if content_key.hex() != "cc79f5a836801a5cc854e8a6c994db12":
        raise RuntimeError("content key derivation does not match the official vector")
    if encrypt_content(content_key, b"hello sample metadata").hex() != (
        "f5b3ceaa2ffd4c720db685170ce3e30c89831673b7"
    ):
        raise RuntimeError("encrypted content does not match the official vector")
    if encrypted_path_name(content_key, "sample.bin") != (
        "YBH7Z2MYKTYT5TTLVCWU5MFB3QXYP5IUWOR6KEA"
    ):
        raise RuntimeError("encrypted path name does not match the official vector")


_self_check_encrypted_primitives()


def run_read_only_matrix(official_root, rust_root, timeout):
    """A read-only Rust peer must receive everything and publish nothing."""

    results = []
    official_payload = b"RO" * 40000
    official_hash = hashlib.sha256(official_payload).hexdigest()

    # 1. The writable official peer seeds content the read-only peer receives.
    (official_root / "ro-seed.bin").write_bytes(official_payload)
    wait_same_file(
        official_root / "ro-seed.bin", rust_root / "ro-seed.bin", official_hash, timeout
    )
    results.append("read-only-receives-official-content")

    # 2. An update to that file propagates to the read-only peer.
    updated = b"RO2" * 40000
    updated_hash = hashlib.sha256(updated).hexdigest()
    (official_root / "ro-seed.bin").write_bytes(updated)
    wait_same_file(
        official_root / "ro-seed.bin", rust_root / "ro-seed.bin", updated_hash, timeout
    )
    results.append("read-only-receives-official-update")

    # 3. Nested directories and empty files arrive intact.
    nested = official_root / "ro-nested" / "deep"
    nested.mkdir(parents=True)
    (nested / "leaf.bin").write_bytes(b"read-only-nested")
    (official_root / "ro-nested" / "empty.bin").write_bytes(b"")
    wait_same_file(
        nested / "leaf.bin",
        rust_root / "ro-nested" / "deep" / "leaf.bin",
        hashlib.sha256(b"read-only-nested").hexdigest(),
        timeout,
    )
    wait_until(
        lambda: (rust_root / "ro-nested" / "empty.bin").is_file()
        and (rust_root / "ro-nested" / "empty.bin").stat().st_size == 0,
        timeout,
        "read-only nested empty file",
    )
    results.append("read-only-receives-nested-and-empty")

    # 4. Metadata changes propagate (mode is normalized by the protocol).
    metadata_path = official_root / "ro-metadata.bin"
    metadata_path.write_bytes(b"read-only-metadata")
    wait_same_file(
        metadata_path,
        rust_root / "ro-metadata.bin",
        hashlib.sha256(b"read-only-metadata").hexdigest(),
        timeout,
    )
    apply_metadata(metadata_path, 0o640, 1_700_000_300)
    wait_until(
        lambda: metadata_state(rust_root / "ro-metadata.bin")
        == (OFFICIAL_NORMALIZED_MODE, 1_700_000_300),
        timeout,
        "read-only official-to-Rust file metadata",
    )
    results.append("read-only-receives-metadata")

    # 5. A local change on the read-only peer must never reach the writer.
    local_extra = rust_root / "ro-local-only.bin"
    local_extra.write_bytes(b"read-only-peer-local-write")
    local_modified = rust_root / "ro-seed.bin"
    local_modified.write_bytes(b"read-only-peer-modified-seed")
    time.sleep(5)
    if (official_root / "ro-local-only.bin").exists():
        raise RuntimeError("read-only peer published a new file to the writable peer")
    if sha256(official_root / "ro-seed.bin") != updated_hash:
        raise RuntimeError("read-only peer overwrote the writable peer's content")
    results.append("read-only-publishes-nothing")

    # 6. A deletion on the writable peer propagates to the read-only peer.
    (official_root / "ro-seed.bin").unlink()
    wait_until(
        lambda: not (rust_root / "ro-seed.bin").exists(),
        timeout,
        "read-only deletion propagation",
    )
    results.append("read-only-receives-deletion")

    return results


def run_read_only_writer_matrix(official_root, rust_root, timeout):
    """Mirror of `run_read_only_matrix`: here the writable peer is Rust and the
    read-only peer is the official client.

    `run_read_only_matrix` holds the read-write `D` key on the official side, so
    it only exercises Rust's encrypted *decryption* path. This case is the one
    that proves Rust's encrypted *writer* path is upstream-compatible: Rust
    holds `D`, encrypts content and metadata on the wire, and the official
    client must decrypt and reconstruct it.
    """

    results = []

    # 1. Rust seeds multi-piece encrypted content the official peer receives.
    rust_payload = b"RW" * 40000
    rust_hash = hashlib.sha256(rust_payload).hexdigest()
    (rust_root / "ro-seed.bin").write_bytes(rust_payload)
    wait_same_file(
        rust_root / "ro-seed.bin", official_root / "ro-seed.bin", rust_hash, timeout
    )
    results.append("read-only-writer-official-receives-content")

    # 2. An update on the writable Rust peer propagates to the official peer.
    updated = b"RW2" * 40000
    updated_hash = hashlib.sha256(updated).hexdigest()
    (rust_root / "ro-seed.bin").write_bytes(updated)
    wait_same_file(
        rust_root / "ro-seed.bin", official_root / "ro-seed.bin", updated_hash, timeout
    )
    results.append("read-only-writer-official-receives-update")

    # 3. Nested directories and empty files arrive intact.
    nested = rust_root / "ro-nested" / "deep"
    nested.mkdir(parents=True)
    (nested / "leaf.bin").write_bytes(b"read-only-writer-nested")
    (rust_root / "ro-nested" / "empty.bin").write_bytes(b"")
    wait_same_file(
        nested / "leaf.bin",
        official_root / "ro-nested" / "deep" / "leaf.bin",
        hashlib.sha256(b"read-only-writer-nested").hexdigest(),
        timeout,
    )
    wait_until(
        lambda: (official_root / "ro-nested" / "empty.bin").is_file()
        and (official_root / "ro-nested" / "empty.bin").stat().st_size == 0,
        timeout,
        "read-only writer nested empty file",
    )
    results.append("read-only-writer-receives-nested-and-empty")

    # 4. Metadata changes propagate from the writable Rust peer.
    metadata_path = rust_root / "ro-metadata.bin"
    metadata_path.write_bytes(b"read-only-writer-metadata")
    wait_same_file(
        metadata_path,
        official_root / "ro-metadata.bin",
        hashlib.sha256(b"read-only-writer-metadata").hexdigest(),
        timeout,
    )
    apply_metadata(metadata_path, 0o640, 1_700_000_400)
    wait_until(
        lambda: metadata_state(official_root / "ro-metadata.bin")
        == (OFFICIAL_NORMALIZED_MODE, 1_700_000_400),
        timeout,
        "read-only writer metadata propagation",
    )
    results.append("read-only-writer-metadata")

    # 5. The read-only official peer must never publish back to the writer.
    # The client may enforce read-only permissions locally, so a rejected local
    # write is acceptable; what must never happen is the change reaching Rust.
    try:
        (official_root / "ro-official-local-only.bin").write_bytes(
            b"official-read-only-local-write"
        )
    except OSError:
        pass
    try:
        (official_root / "ro-seed.bin").write_bytes(
            b"official-read-only-modified-seed"
        )
    except OSError:
        pass
    time.sleep(5)
    if (rust_root / "ro-official-local-only.bin").exists():
        raise RuntimeError(
            "read-only official peer published a new file to the writable Rust peer"
        )
    if sha256(rust_root / "ro-seed.bin") != updated_hash:
        raise RuntimeError(
            "read-only official peer overwrote the writable Rust peer's content"
        )
    results.append("read-only-official-publishes-nothing")

    # 6. A deletion on the writable Rust peer propagates to the official peer.
    # Delete a file the read-only peer never touched locally: `ro-seed.bin` was
    # deliberately diverged in step 5, and preserving that local edit instead of
    # applying the remote deletion is the expected conflict behaviour.
    (rust_root / "ro-metadata.bin").unlink()
    wait_until(
        lambda: not (official_root / "ro-metadata.bin").exists(),
        timeout,
        "read-only writer deletion propagation",
    )
    results.append("read-only-writer-deletion")

    return results


def run_encrypted_only_reader_matrix(
    official_root, rust_root, timeout, rust_bin, writer_key
):
    """Rust writes `D`, an official encrypted-only `F` peer reads.

    The official peer must store the ciphertext under the encrypted path name;
    the folder never publishes a plaintext object.
    """

    results = []
    # The content key comes from the read-only link key of the writable key the
    # Rust peer serves with.
    read_only = derive_share_key(rust_bin, writer_key, "read-only")
    content_key = content_key_for_read_only_key(read_only)

    payload = b"encrypted-only-official-reader" * 100
    encrypted_name = encrypted_path_name(content_key, "eo-reader.bin")
    (rust_root / "eo-reader.bin").write_bytes(payload)
    destination = official_root / encrypted_name
    expected_ciphertext = encrypt_content(content_key, payload)
    wait_until(
        lambda: destination.is_file()
        and destination.read_bytes() == expected_ciphertext,
        timeout,
        "encrypted-only official reader ciphertext byte synchronization",
    )
    if (official_root / "eo-reader.bin").exists():
        raise RuntimeError("encrypted-only official peer stored a plaintext path")
    results.append("encrypted-only-official-reader-stores-ciphertext")

    # An update propagates and re-encrypts.
    updated = payload + b"-updated"
    updated_ciphertext = encrypt_content(content_key, updated)
    (rust_root / "eo-reader.bin").write_bytes(updated)
    wait_until(
        lambda: destination.is_file()
        and destination.read_bytes() == updated_ciphertext,
        timeout,
        "encrypted-only official reader update",
    )
    results.append("encrypted-only-official-reader-update")

    # A deletion propagates.
    (rust_root / "eo-reader.bin").unlink()
    wait_until(
        lambda: not destination.exists(),
        timeout,
        "encrypted-only official reader deletion",
    )
    results.append("encrypted-only-official-reader-deletion")
    return results


def run_encrypted_only_writer_matrix(
    official_root, rust_root, timeout, rust_bin, writer_key
):
    """An official `D` peer writes, Rust reads with only the `F` key.

    Rust must reproduce the encrypted path name and keep the ciphertext
    verbatim; it holds no content key, so nothing may be decrypted to disk.
    """

    results = []
    read_only = derive_share_key(rust_bin, writer_key, "read-only")
    content_key = content_key_for_read_only_key(read_only)

    payload = b"encrypted-only-rust-reader" * 100
    encrypted_name = encrypted_path_name(content_key, "eo-writer.bin")
    (official_root / "eo-writer.bin").write_bytes(payload)
    destination = rust_root / encrypted_name
    expected_ciphertext = encrypt_content(content_key, payload)
    wait_until(
        lambda: destination.is_file()
        and destination.read_bytes() == expected_ciphertext,
        timeout,
        "encrypted-only Rust reader ciphertext byte synchronization",
    )
    if (rust_root / "eo-writer.bin").exists():
        raise RuntimeError("encrypted-only Rust peer stored a plaintext path")
    results.append("encrypted-only-rust-reader-stores-ciphertext")

    updated = payload + b"-updated"
    updated_ciphertext = encrypt_content(content_key, updated)
    (official_root / "eo-writer.bin").write_bytes(updated)
    wait_until(
        lambda: destination.is_file()
        and destination.read_bytes() == updated_ciphertext,
        timeout,
        "encrypted-only Rust reader update",
    )
    results.append("encrypted-only-rust-reader-update")

    (official_root / "eo-writer.bin").unlink()
    wait_until(
        lambda: not destination.exists(),
        timeout,
        "encrypted-only Rust reader deletion",
    )
    results.append("encrypted-only-rust-reader-deletion")
    return results


def run_official_case(
    official_bin,
    rust_bin,
    work_dir,
    timeout,
    case_name,
    key_family,
    key,
    rust_key=None,
    matrix=None,
    official_key=None,
    rust_dials=False,
):
    case_dir = work_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    official_root = case_dir / "official"
    rust_root = case_dir / "rust"
    storage_path = case_dir / "storage"
    official_root.mkdir()
    rust_root.mkdir()
    storage_path.mkdir()
    config_path = case_dir / "official-config.json"
    rust_port = free_port()
    official_port = official_listening_port()
    webui_port = free_port()
    configure_official(
        config_path, storage_path, official_root, webui_port, official_port
    )

    # `share` describes the official peer's key, `rust_share` the key the Rust
    # peer serves with. They differ whenever one side holds a derived role.
    share = inspect_share(rust_bin, official_key or key, allow_read_only=True)
    rust_share = inspect_share(rust_bin, rust_key or key, allow_read_only=True)
    if rust_share["share_id"] != share["share_id"]:
        raise RuntimeError("derived Rust key does not share the writer's share ID")
    matrix = matrix or run_matrix
    ping_hex = subprocess.check_output(
        [
            str(rust_bin),
            "encode-ping",
            "--peer-id",
            PEER_ID,
            "--port",
            str(rust_port),
            "--share-id",
            share["share_id"],
        ],
        text=True,
    ).strip()
    ping_packet = bytes.fromhex(ping_hex)

    official_process = None
    rust_process = None
    dial_process = None
    official_log = None
    rust_log = None
    dial_log = None
    stop_advertiser = False
    advertiser_error = []

    def advertise():
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            while not stop_advertiser:
                sender.sendto(ping_packet, ("127.0.0.1", 3838))
                time.sleep(0.5)
        except Exception as error:
            advertiser_error.append(error)
        finally:
            sender.close()

    try:
        if rust_dials:
            # The official peer owns the listening socket and Rust dials it.
            # `rust_dials` selects the topology only; encrypted-only peers
            # interoperate in both roles.
            dial_process, dial_log = start_process(
                [
                    str(rust_bin),
                    "connect-upstream",
                    str(rust_root),
                    f"127.0.0.1:{official_port}",
                    "--key",
                    rust_key or key,
                    "--device-name",
                    f"rust-official-{case_name}",
                    "--peer-id",
                    PEER_ID,
                ],
                case_dir / "rust.log",
            )
        else:
            rust_process, rust_log = start_process(
                [
                    str(rust_bin),
                    "serve-upstream",
                    str(rust_root),
                    "--listen",
                    f"127.0.0.1:{rust_port}",
                    "--key",
                    rust_key or key,
                    "--device-name",
                    f"rust-official-{case_name}",
                    "--peer-id",
                    PEER_ID,
                ],
                case_dir / "rust.log",
            )
        official_process, official_log = start_process(
            [
                str(official_bin),
                "--config",
                str(config_path),
                "--nodaemon",
                "--log",
                str(case_dir / "official-app.log"),
            ],
            case_dir / "official.log",
        )
        wait_until(
            lambda: official_bound_peer_port(case_dir / "official-app.log") is not None,
            timeout,
            f"{case_name} official peer listener",
        )
        bound_port = official_bound_peer_port(case_dir / "official-app.log")
        if bound_port != official_port:
            raise RuntimeError(
                f"{case_name} official peer bound port {bound_port}, but the case "
                f"dials {official_port}; the reserved port was taken"
            )
        api = OfficialApi(webui_port, "research")
        api.action("setlicenseagreed", value="true")
        api.action("starttrialperiod")
        folder = api.action(
            "addsyncfolder",
            path=str(official_root),
            secret=official_key or key,
        )["value"]
        if not rust_dials:
            api.action(
                "setknownhosts",
                id=folder["folderid"],
                hosts=f"127.0.0.1:{rust_port}",
                isfolder="true",
            )
        api.action("setpause", value="false")
        advertiser_thread = threading.Thread(target=advertise, daemon=True)
        advertiser_thread.start()
        wait_until(
            lambda: (official_root / ".sync" / "ID").exists(),
            timeout,
            f"{case_name} official folder initialization",
        )
        time.sleep(3)
        results = matrix(official_root, rust_root, timeout)
        if advertiser_error:
            raise RuntimeError(f"discovery advertiser failed: {advertiser_error[0]}")
        assert_official_logs_clean(
            [case_dir / "official.log", case_dir / "official-app.log"]
        )
        return {
            "case": case_name,
            "key_family": key_family,
            "share_key_type": share["type"],
            "rust_key_type": rust_share["type"],
            "share_id": share["share_id"],
            "results": results,
            "work_dir": str(case_dir),
        }
    finally:
        stop_advertiser = True
        stop_process(official_process)
        stop_process(rust_process)
        stop_process(dial_process)
        if official_log:
            official_log.close()
        if rust_log:
            rust_log.close()
        if dial_log:
            dial_log.close()


def start_official_peer(official_bin, case_dir, name, storage_path, root, timeout):
    """Start one official client and return ``(process, log, api, peer_port)``.

    The listener port is reserved for both TCP and UDP, and the port the client
    actually bound is read back from its own log so a silent `port + 1` fallback
    can never be mistaken for a protocol failure.
    """
    port = official_listening_port()
    webui_port = free_port()
    config_path = case_dir / f"{name}-config.json"
    configure_official(config_path, storage_path, root, webui_port, port)
    process, log = start_process(
        [
            str(official_bin),
            "--config",
            str(config_path),
            "--nodaemon",
            "--log",
            str(case_dir / f"{name}-app.log"),
        ],
        case_dir / f"{name}.log",
    )
    wait_until(
        lambda: official_bound_peer_port(case_dir / f"{name}-app.log") is not None,
        timeout,
        f"{name} official peer listener",
    )
    bound_port = official_bound_peer_port(case_dir / f"{name}-app.log")
    if bound_port != port:
        raise RuntimeError(
            f"{name} official peer bound port {bound_port}, but the case dials "
            f"{port}; the reserved port was taken"
        )
    api = OfficialApi(webui_port, "research")
    api.action("setlicenseagreed", value="true")
    api.action("starttrialperiod")
    return process, log, api, port


def run_relay_serve_case(
    official_bin,
    rust_bin,
    work_dir,
    timeout,
    case_name,
    writer_key,
    read_only_key,
    encrypted_key,
):
    """A read-only `E` node relays the writer's content to an encrypted-only `F`.

    Phase 1 seeds the read-only node from a writable official `D` peer. Phase 2
    kills the writer and points a fresh encrypted-only official `F` peer at the
    read-only node alone. A read-only share key carries no Ed25519 seed, so the
    node must advertise the *writer's* public key and forward the writer's
    signed entry verbatim -- exactly what the official client does -- or the
    encrypted-only peer rejects the entry with `failed to verify signature`.
    """
    case_dir = work_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    writer_root = case_dir / "writer"
    relay_root = case_dir / "relay"
    reader_root = case_dir / "reader"
    for directory in (
        writer_root,
        relay_root,
        reader_root,
        case_dir / "writer-storage",
        case_dir / "reader-storage",
    ):
        directory.mkdir()
    rust_port = free_port()
    read_only = inspect_share(rust_bin, read_only_key, allow_read_only=True)
    encrypted = inspect_share(rust_bin, encrypted_key, allow_read_only=True)
    if read_only["share_id"] != encrypted["share_id"]:
        raise RuntimeError("relay keys do not share the writer's share ID")
    content_key = content_key_for_read_only_key(read_only_key)
    payload = b"relay-serve-payload" * 100
    encrypted_name = encrypted_path_name(content_key, "relay-serve.bin")
    expected_ciphertext = encrypt_content(content_key, payload)

    writer_process = writer_log = None
    reader_process = reader_log = None
    rust_process = rust_log = None
    try:
        # Phase 1: the writable official peer seeds the read-only Rust node.
        rust_process, rust_log = start_process(
            [
                str(rust_bin),
                "serve-upstream",
                str(relay_root),
                "--listen",
                f"127.0.0.1:{rust_port}",
                "--key",
                read_only_key,
                "--device-name",
                f"rust-{case_name}",
                "--peer-id",
                PEER_ID,
            ],
            case_dir / "rust.log",
        )
        writer_process, writer_log, writer_api, _ = start_official_peer(
            official_bin,
            case_dir,
            "writer",
            case_dir / "writer-storage",
            writer_root,
            timeout,
        )
        folder = writer_api.action(
            "addsyncfolder", path=str(writer_root), secret=writer_key
        )["value"]
        writer_api.action(
            "setknownhosts",
            id=folder["folderid"],
            hosts=f"127.0.0.1:{rust_port}",
            isfolder="true",
        )
        writer_api.action("setpause", value="false")
        wait_until(
            lambda: (writer_root / ".sync" / "ID").exists(),
            timeout,
            f"{case_name} writer folder initialization",
        )
        time.sleep(3)
        (writer_root / "relay-serve.bin").write_bytes(payload)
        wait_until(
            lambda: (relay_root / "relay-serve.bin").is_file()
            and (relay_root / "relay-serve.bin").read_bytes() == payload,
            timeout,
            f"{case_name} read-only node receives the writer's plaintext",
        )

        # Phase 2: the writer leaves; a fresh `F` peer must pull the ciphertext
        # from the read-only node alone.
        stop_process(writer_process)
        writer_process = None
        time.sleep(2)
        reader_process, reader_log, reader_api, _ = start_official_peer(
            official_bin,
            case_dir,
            "reader",
            case_dir / "reader-storage",
            reader_root,
            timeout,
        )
        reader_folder = reader_api.action(
            "addsyncfolder", path=str(reader_root), secret=encrypted_key
        )["value"]
        if reader_folder.get("secrettype") != 4:
            raise RuntimeError(
                "official encrypted-only peer did not open with secrettype=4"
            )
        reader_api.action(
            "setknownhosts",
            id=reader_folder["folderid"],
            hosts=f"127.0.0.1:{rust_port}",
            isfolder="true",
        )
        reader_api.action("setpause", value="false")
        destination = reader_root / encrypted_name
        wait_until(
            lambda: destination.is_file()
            and destination.read_bytes() == expected_ciphertext,
            timeout,
            f"{case_name} encrypted-only reader receives relayed ciphertext",
        )
        if (reader_root / "relay-serve.bin").exists():
            raise RuntimeError("encrypted-only reader stored a plaintext path")
        assert_official_logs_clean(
            [
                case_dir / "writer.log",
                case_dir / "writer-app.log",
                case_dir / "reader.log",
                case_dir / "reader-app.log",
            ]
        )
        return {
            "case": case_name,
            "key_family": "encrypt-capable",
            "share_key_type": encrypted["type"],
            "rust_key_type": read_only["type"],
            "share_id": read_only["share_id"],
            "results": [
                "read-only-relay-receives-writer-plaintext",
                "read-only-relay-serves-encrypted-only-peer",
                "read-only-relay-ciphertext-bytes",
            ],
            "work_dir": str(case_dir),
        }
    finally:
        stop_process(writer_process)
        stop_process(reader_process)
        stop_process(rust_process)
        for handle in (writer_log, reader_log, rust_log):
            if handle:
                handle.close()


def run_relay_read_case(
    official_bin,
    rust_bin,
    work_dir,
    timeout,
    case_name,
    writer_key,
    read_only_key,
    encrypted_key,
):
    """A read-only `E` node pulls from an official encrypted-only `F` folder.

    An official `D` peer seeds an official `F` folder with the ciphertext and is
    then killed. The read-only Rust node dials the `F` folder, which declares
    `type=4` in its SRPEH response; the node must derive the 20-byte access key
    from that declaration and decrypt the ciphertext back to plaintext.
    """
    case_dir = work_dir / case_name
    if case_dir.exists():
        shutil.rmtree(case_dir)
    case_dir.mkdir(parents=True)
    writer_root = case_dir / "writer"
    f_root = case_dir / "official-f"
    relay_root = case_dir / "relay"
    for directory in (
        writer_root,
        f_root,
        relay_root,
        case_dir / "writer-storage",
        case_dir / "f-storage",
    ):
        directory.mkdir()
    read_only = inspect_share(rust_bin, read_only_key, allow_read_only=True)
    encrypted = inspect_share(rust_bin, encrypted_key, allow_read_only=True)
    if read_only["share_id"] != encrypted["share_id"]:
        raise RuntimeError("relay keys do not share the writer's share ID")
    content_key = content_key_for_read_only_key(read_only_key)
    payload = b"relay-read-payload" * 100
    encrypted_name = encrypted_path_name(content_key, "relay-read.bin")
    expected_ciphertext = encrypt_content(content_key, payload)

    writer_process = writer_log = None
    f_process = f_log = None
    dial_process = dial_log = None
    try:
        writer_process, writer_log, writer_api, writer_port = start_official_peer(
            official_bin,
            case_dir,
            "writer",
            case_dir / "writer-storage",
            writer_root,
            timeout,
        )
        f_process, f_log, f_api, f_port = start_official_peer(
            official_bin,
            case_dir,
            "official-f",
            case_dir / "f-storage",
            f_root,
            timeout,
        )
        writer_folder = writer_api.action(
            "addsyncfolder", path=str(writer_root), secret=writer_key
        )["value"]
        f_folder = f_api.action(
            "addsyncfolder", path=str(f_root), secret=encrypted_key
        )["value"]
        if f_folder.get("secrettype") != 4:
            raise RuntimeError(
                "official encrypted-only peer did not open with secrettype=4"
            )
        writer_api.action(
            "setknownhosts",
            id=writer_folder["folderid"],
            hosts=f"127.0.0.1:{f_port}",
            isfolder="true",
        )
        f_api.action(
            "setknownhosts",
            id=f_folder["folderid"],
            hosts=f"127.0.0.1:{writer_port}",
            isfolder="true",
        )
        writer_api.action("setpause", value="false")
        f_api.action("setpause", value="false")
        wait_until(
            lambda: (writer_root / ".sync" / "ID").exists()
            and (f_root / ".sync" / "ID").exists(),
            timeout,
            f"{case_name} folder initialization",
        )
        time.sleep(3)
        (writer_root / "relay-read.bin").write_bytes(payload)
        wait_until(
            lambda: (f_root / encrypted_name).is_file()
            and (f_root / encrypted_name).read_bytes() == expected_ciphertext,
            timeout,
            f"{case_name} official encrypted-only peer stores the ciphertext",
        )

        # The writer leaves; the read-only node must decrypt from `F` alone.
        stop_process(writer_process)
        writer_process = None
        time.sleep(2)
        dial_process, dial_log = start_process(
            [
                str(rust_bin),
                "connect-upstream",
                str(relay_root),
                f"127.0.0.1:{f_port}",
                "--key",
                read_only_key,
                "--device-name",
                f"rust-{case_name}",
                "--peer-id",
                PEER_ID,
            ],
            case_dir / "rust.log",
        )
        destination = relay_root / "relay-read.bin"
        wait_until(
            lambda: destination.is_file() and destination.read_bytes() == payload,
            timeout,
            f"{case_name} read-only node decrypts the encrypted-only ciphertext",
        )
        if (relay_root / encrypted_name).exists():
            raise RuntimeError("read-only node kept the encrypted path name")
        assert_official_logs_clean(
            [
                case_dir / "writer.log",
                case_dir / "writer-app.log",
                case_dir / "official-f.log",
                case_dir / "official-f-app.log",
            ]
        )
        return {
            "case": case_name,
            "key_family": "encrypt-capable",
            "share_key_type": encrypted["type"],
            "rust_key_type": read_only["type"],
            "share_id": read_only["share_id"],
            "results": [
                "encrypted-only-official-peer-serves-ciphertext",
                "read-only-node-decrypts-encrypted-only-ciphertext",
            ],
            "work_dir": str(case_dir),
        }
    finally:
        stop_process(writer_process)
        stop_process(f_process)
        stop_process(dial_process)
        for handle in (writer_log, f_log, dial_log):
            if handle:
                handle.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-bin", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument(
        "--key-family",
        choices=(
            "all",
            "standard",
            "encrypt-capable",
            "read-only-encrypt-capable",
            "read-only-upstream-encrypt-capable",
            "encrypted-only",
            "encrypted-only-upstream",
            "encrypted-only-responder",
            "encrypted-only-official-responder",
            "read-only-relay-serve",
            "read-only-relay-read",
            "standard-read-only",
            "standard-read-only-upstream",
        ),
        default="all",
    )
    arguments = parser.parse_args()

    official_bin = arguments.official_bin.resolve()
    rust_bin = arguments.rust_bin.resolve()
    if not official_bin.is_file() or not rust_bin.is_file():
        raise RuntimeError("official and Rust binaries must exist")
    verify_version(official_bin)

    if arguments.work_dir:
        work_dir = arguments.work_dir.resolve()
        work_dir.mkdir(parents=True, exist_ok=True)
    else:
        work_dir = Path(tempfile.mkdtemp(prefix="rustsync-official-compat-"))

    # (case directory, key family, official peer's key type, Rust derived role
    # or None to serve the writer key, official derived role or None, matrix,
    # whether the Rust peer dials the official listener instead of serving)
    #
    # `read-only-encrypt-capable` exercises Rust's encrypted *reader* path
    # (official writes D, Rust reads E). `read-only-upstream-encrypt-capable`
    # is its mirror and exercises Rust's encrypted *writer* path (Rust writes
    # D, official reads E), which no other case covers.
    #
    # An encrypted-only `F` peer authenticates with the 20-byte access key
    # instead of the 36-byte read-only body, and it announces that role as
    # `type=4` inside the SRPEH response. The other side derives its SRP
    # password from that declaration, so an `F` folder both dials and answers
    # `D`/`E` peers. The two encrypted-only cases cover one direction each.
    cases = {
        "standard": ("standard-A", "standard", "A", None, None, None, False),
        # The other half of the Standard Folder `A/B` family: the official peer
        # writes with `A`, the Rust peer reads with the derived `B` link key.
        # `B` carries no Ed25519 seed, so it must receive content and publish
        # nothing, exactly like the encrypt-capable `E` role.
        "standard-read-only": (
            "standard-B",
            "standard",
            "A",
            "read-only",
            None,
            "read-only",
            False,
        ),
        # Mirror: Rust writes with `A`, the official peer reads with `B`.
        "standard-read-only-upstream": (
            "standard-B-upstream",
            "standard",
            "B",
            None,
            "read-only",
            "read-only-writer",
            False,
        ),
        "encrypt-capable": (
            "encrypted-D",
            "encrypt-capable",
            "D",
            None,
            None,
            None,
            False,
        ),
        "read-only-encrypt-capable": (
            "read-only-E",
            "encrypt-capable",
            "D",
            "read-only",
            None,
            "read-only",
            False,
        ),
        "read-only-upstream-encrypt-capable": (
            "read-only-E-upstream",
            "encrypt-capable",
            "E",
            None,
            "read-only",
            "read-only-writer",
            False,
        ),
        # Rust holds the writable `D` key and writes; the official
        # encrypted-only `F` peer receives the ciphertext under encrypted path
        # names and stores it verbatim.
        "encrypted-only": (
            "encrypted-only-official-F-reads",
            "encrypt-capable",
            "F",
            None,
            "encrypted",
            "encrypted-only-reader",
            False,
        ),
        # Mirror image: the official peer holds the writable `D` key, Rust holds
        # only the encrypted-only `F` key, and Rust dials the official listener.
        "encrypted-only-upstream": (
            "encrypted-only-rust-F-reads",
            "encrypt-capable",
            "D",
            "encrypted",
            None,
            "encrypted-only-writer",
            True,
        ),
        # Rust holds only `F` but *serves*: it announces `type=4` so the
        # official `D` dialer derives the 20-byte access key, and Rust stores
        # the ciphertext the official writer publishes.
        "encrypted-only-responder": (
            "encrypted-only-rust-F-responder",
            "encrypt-capable",
            "D",
            "encrypted",
            None,
            "encrypted-only-writer",
            False,
        ),
        # The official encrypted-only `F` peer serves and Rust `D` dials it,
        # which only works because we honour the responder's declared type.
        "encrypted-only-official-responder": (
            "encrypted-only-official-F-responder",
            "encrypt-capable",
            "F",
            None,
            "encrypted",
            "encrypted-only-reader",
            True,
        ),
        # A read-only `E` node relays the writer's content to an encrypted-only
        # `F` peer. A read-only share key carries no Ed25519 seed, so the node
        # advertises the writer's public key and forwards the writer's signed
        # entry verbatim, exactly like the official client.
        "read-only-relay-serve": (
            "read-only-E-serves-official-F",
            "encrypt-capable",
            "F",
            "read-only",
            "encrypted",
            "relay-serve",
            False,
        ),
        # The mirror direction: the read-only `E` node dials an official
        # encrypted-only `F` folder, which declares `type=4` in its SRPEH
        # response, and decrypts the ciphertext back to plaintext.
        "read-only-relay-read": (
            "read-only-E-reads-official-F",
            "encrypt-capable",
            "F",
            "read-only",
            "encrypted",
            "relay-read",
            True,
        ),
    }
    matrices = {
        "read-only": run_read_only_matrix,
        "read-only-writer": run_read_only_writer_matrix,
    }
    # Every case is a hard gate, including the encrypted-only ones: an `F`
    # folder does synchronize with the official client, provided the `F` peer is
    # the dialer.
    default_cases = (
        "standard",
        "encrypt-capable",
        "read-only-encrypt-capable",
        "read-only-upstream-encrypt-capable",
        "encrypted-only",
        "encrypted-only-upstream",
        "encrypted-only-responder",
        "encrypted-only-official-responder",
        "read-only-relay-serve",
        "read-only-relay-read",
        "standard-read-only",
        "standard-read-only-upstream",
    )
    selected = (
        [cases[name] for name in default_cases]
        if arguments.key_family == "all"
        else [cases[arguments.key_family]]
    )
    summaries = []
    for (
        case_name,
        key_family,
        expected_type,
        rust_role,
        official_role,
        matrix_name,
        rust_dials,
    ) in selected:
        # A fixed key can only pin the writer: derived roles come from it.
        fixed = os.environ.get("RUSTSYNC_FIXED_SHARE_KEY")
        if fixed and expected_type == "A":
            raise RuntimeError(
                "RUSTSYNC_FIXED_SHARE_KEY is an encrypt-capable D key and cannot "
                "pin the standard-A case; unset it to exercise every case"
            )
        key = fixed or generate_share_key(rust_bin, key_family)
        rust_key = derive_share_key(rust_bin, key, rust_role) if rust_role else None
        official_key = (
            derive_share_key(rust_bin, key, official_role) if official_role else None
        )
        matrix = matrices.get(matrix_name)
        if matrix_name == "encrypted-only-reader":
            # An `F` reader stores the ciphertext, so the matrix needs the
            # writable key to derive the content key and the expected names.
            matrix = lambda official_root, rust_root, timeout: (  # noqa: E731
                run_encrypted_only_reader_matrix(
                    official_root, rust_root, timeout, rust_bin, key
                )
            )
        elif matrix_name == "encrypted-only-writer":
            matrix = lambda official_root, rust_root, timeout: (  # noqa: E731
                run_encrypted_only_writer_matrix(
                    official_root, rust_root, timeout, rust_bin, key
                )
            )
        if matrix_name in ("relay-serve", "relay-read"):
            # The relay cases run their own multi-peer harness: they need a
            # writable official `D` writer *and* an official `F` peer, plus a
            # phase boundary where the writer is killed.
            runner = (
                run_relay_serve_case
                if matrix_name == "relay-serve"
                else run_relay_read_case
            )
            summary = runner(
                official_bin,
                rust_bin,
                work_dir,
                arguments.timeout,
                case_name,
                key,
                rust_key,
                official_key,
            )
        else:
            summary = run_official_case(
                official_bin,
                rust_bin,
                work_dir,
                arguments.timeout,
                case_name,
                key_family,
                key,
                rust_key=rust_key,
                matrix=matrix,
                official_key=official_key,
                rust_dials=rust_dials,
            )
        if summary["share_key_type"] != expected_type:
            raise RuntimeError(
                f"{case_name} generated {summary['share_key_type']}, expected {expected_type}"
            )
        summaries.append(summary)

    result = {
        "official_version": "upstream client 3.1.2 build 1076",
        "cases": summaries,
        "work_dir": str(work_dir),
    }
    (work_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"official compatibility matrix failed: {error}", file=sys.stderr)
        raise SystemExit(1)
