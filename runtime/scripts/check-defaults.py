#!/usr/bin/env python3
"""Check zero-argument startup without changing the host's /etc, /run or network.

cargo build -p portal-runtime
unshare --user --map-root-user --net --mount python3 runtime/scripts/check-defaults.py
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

BIN = Path(__file__).resolve().parents[2] / "target/debug/portal-runtime"
assert os.geteuid() == 0 and Path("/proc/self/uid_map").read_text().split()[2] == "1", "run in an isolated user, mount and network namespace"
# The mount operations require a mount namespace owned by this user namespace.
# Refuse to continue on any failure, before writing the tested default paths.
subprocess.run(["mount", "--make-rprivate", "/"], check=True)
for directory in ["/etc", "/run"]:
    subprocess.run(["mount", "-t", "tmpfs", "-o", "mode=755", "tmpfs", directory], check=True)
subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
key = Path("/etc/portal/device.key")


def start_and_check(arguments, interface="portal0", port=51821):
    with tempfile.TemporaryFile(mode="w+") as log:
        process = subprocess.Popen([str(BIN), *arguments], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 10
            while True:
                assert process.poll() is None, "runtime exited before readiness"
                try:
                    token = Path("/run/portal.token").read_text().strip()
                    output = os.pread(log.fileno(), 65536, 0).decode()
                    links = [line.removeprefix("web panel: ") for line in output.splitlines() if line.startswith("web panel: ")]
                    if not links:
                        raise ValueError("waiting for startup login link")
                    assert len(links) == 1, "startup printed multiple login links"
                    login = urlsplit(links[0])
                    assert login.fragment == "token=" + token, "startup link uses a different token"
                    assert login.hostname == "127.0.0.1" and login.port and login.scheme == "http"
                    if port:
                        assert login.port == port, "startup link uses a different port"
                    base = f"http://{login.netloc}"
                    request = urllib.request.Request(base + "/api/v1/snapshot", headers={"Authorization": "Bearer " + token})
                    data = json.loads(opener.open(request, timeout=1).read())
                    break
                except (OSError, ValueError, urllib.error.URLError):
                    if time.monotonic() >= deadline:
                        raise AssertionError("runtime did not become ready")
                    time.sleep(0.05)
            assert data["healthy"] and data["mode"] == "manual"
            assert data["interface"]["name"] == interface
            assert data["interface"]["addresses"] == []
            assert opener.open(base + "/", timeout=1).status == 200
            assert key.stat().st_size == 32 and key.stat().st_mode & 0o777 == 0o600
            assert key.parent.stat().st_mode & 0o777 == 0o700
            assert Path("/run/portal.token").stat().st_mode & 0o777 == 0o600
            return data
        except BaseException:
            log.seek(0)
            print(log.read())
            raise
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            assert not Path("/run/portal.token").exists(), "API token was not cleaned up"


first = start_and_check([])
assert first["interface"]["listen"] == "0.0.0.0:51820"
fingerprint = hashlib.sha256(key.read_bytes()).digest()
second = start_and_check(["run"])
assert second["interface"]["public_key"] == first["interface"]["public_key"]
assert hashlib.sha256(key.read_bytes()).digest() == fingerprint
print("PASS: bare startup and run use default TUN, UDP, API and token paths; random private key survives restart", flush=True)

config = Path("/etc/portal/runtime.json")
config.write_text("{}")
failed = subprocess.run([str(BIN), "run"], capture_output=True, text=True, timeout=10)
assert failed.returncode != 0 and "/etc/portal/device.json" in failed.stderr
assert not Path("/sys/class/net/portal0").exists(), "managed configuration silently fell back to manual mode"
print("PASS: default JSON configuration is discovered and missing enrollment does not start an unprotected manual agent", flush=True)

overridden = start_and_check(["run", "--tun", "custom0", "--listen", "127.0.0.1:51900", "--api-listen", "127.0.0.1:51901"], "custom0", 51901)
assert overridden["interface"]["listen"] == "127.0.0.1:51900"
assert overridden["interface"]["public_key"] == first["interface"]["public_key"]
print("PASS: explicit manual options override startup defaults", flush=True)

start_and_check(["run", "--api-listen", "127.0.0.1:0"], port=0)
print("PASS: startup login link uses the current token and the actual bound port, including port 0", flush=True)

key.unlink()
failed = subprocess.run([str(BIN), "run"], capture_output=True, text=True, timeout=10)
assert failed.returncode != 0 and "device key" in failed.stderr and not key.exists()
generated = subprocess.run([str(BIN), "keygen"], capture_output=True, text=True, check=True)
assert key.exists() and "public key:" in generated.stdout
unchanged = key.read_bytes()
failed = subprocess.run([str(BIN), "keygen"], capture_output=True, text=True)
assert failed.returncode != 0 and key.read_bytes() == unchanged
print("PASS: missing managed key is preserved for recovery; keygen has a default path and never overwrites a key", flush=True)
