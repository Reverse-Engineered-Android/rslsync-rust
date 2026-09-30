#!/usr/bin/env python3
import argparse
import base64
import hashlib
import json
import os
import re
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
)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


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


def verify_version(official_bin):
    output = subprocess.check_output(
        [str(official_bin), "--help"], stderr=subprocess.STDOUT, text=True
    )
    if "3.1.2 (1076)" not in output:
        raise RuntimeError("official binary is not upstream client 3.1.2 build 1076")


def inspect_share(rust_bin, key):
    output = subprocess.check_output(
        [str(rust_bin), "inspect-key", key], text=True
    )
    values = dict(
        line.split("=", 1)
        for line in output.splitlines()
        if "=" in line
    )
    if values.get("type") != "A":
        raise RuntimeError("generated key is not a writable A key")
    return values


def configure_official(config_path, storage_path, official_root, webui_port):
    config = {
        "device_name": "official-compat",
        "storage_path": str(storage_path),
        "listening_port": 0,
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--official-bin", type=Path, required=True)
    parser.add_argument("--rust-bin", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--timeout", type=int, default=120)
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

    official_root = work_dir / "official"
    rust_root = work_dir / "rust"
    storage_path = work_dir / "storage"
    official_root.mkdir()
    rust_root.mkdir()
    storage_path.mkdir()
    config_path = work_dir / "official-config.json"
    rust_port = free_port()
    webui_port = free_port()
    configure_official(config_path, storage_path, official_root, webui_port)

    key = subprocess.check_output([str(rust_bin), "generate-key", "--read-write"], text=True).strip()
    share = inspect_share(rust_bin, key)
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
    official_log = None
    rust_log = None
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
        rust_process, rust_log = start_process(
            [
                str(rust_bin),
                "serve-upstream",
                str(rust_root),
                "--listen",
                f"127.0.0.1:{rust_port}",
                "--key",
                key,
                "--device-name",
                "rust-official-compat",
                "--peer-id",
                PEER_ID,
            ],
            work_dir / "rust.log",
        )
        official_process, official_log = start_process(
            [
                str(official_bin),
                "--config",
                str(config_path),
                "--nodaemon",
                "--log",
                str(work_dir / "official-app.log"),
            ],
            work_dir / "official.log",
        )
        api = OfficialApi(webui_port, "research")
        api.action("setlicenseagreed", value="true")
        api.action("starttrialperiod")
        folder = api.action(
            "addsyncfolder",
            path=str(official_root),
            secret=key,
        )["value"]
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
            arguments.timeout,
            "official folder initialization",
        )
        time.sleep(3)
        results = run_matrix(official_root, rust_root, arguments.timeout)
        if advertiser_error:
            raise RuntimeError(f"discovery advertiser failed: {advertiser_error[0]}")
        assert_official_logs_clean(
            [work_dir / "official.log", work_dir / "official-app.log"]
        )
        summary = {
            "official_version": "upstream client 3.1.2 build 1076",
            "share_key_type": share["type"],
            "share_id": share["share_id"],
            "results": results,
            "work_dir": str(work_dir),
        }
        (work_dir / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(json.dumps(summary, indent=2))
    finally:
        stop_advertiser = True
        stop_process(official_process)
        stop_process(rust_process)
        if official_log:
            official_log.close()
        if rust_log:
            rust_log.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"official compatibility matrix failed: {error}", file=sys.stderr)
        raise SystemExit(1)
