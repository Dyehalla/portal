#!/usr/bin/env python3
"""Real HTTPS/TUN/UDP check inside disposable, unprivileged network namespaces.

Build with cargo build --workspace, then run:
  unshare --user --map-root-user --net python3 runtime/scripts/check-managed.py
Requires Linux user namespaces, iproute2, nsenter, openssl and Python 3.
Set PORTAL_TEST_NAT=1 to also exercise STUN and a stateful NAT (requires nft).
"""
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "target/debug"
PROCESSES = []
LOGS = []
os.umask(0o077)


def run(*args, prefix=()):
    return subprocess.check_output([*prefix, *map(str, args)], text=True, stderr=subprocess.PIPE).strip()


def spawn(label, args, directory, prefix=()):
    log = directory / (label + ".log")
    LOGS.append(log)
    with log.open("wb") as output:
        process = subprocess.Popen([*prefix, *map(str, args)], stdout=output, stderr=output)
    PROCESSES.append(process)
    return process


def write_json(path, value):
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(value))
    temp.replace(path)


def wait_for(check, description, seconds=12):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            if check():
                return
        except (OSError, ValueError, urllib.error.URLError, subprocess.CalledProcessError) as error:
            last = error
        time.sleep(0.1)
    raise AssertionError(f"timeout: {description}; last error: {last}")


def command(config, operation, **values):
    body = json.dumps(dict(operation=operation, **values))
    # Execute in the device's network namespace, keeping the parent client's
    # sockets and routes independent of the destination's local routing table.
    code = """import json,sys,urllib.request,urllib.error,pathlib
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
request=urllib.request.Request('http://127.0.0.1:51821/api/v1/command',sys.argv[2].encode(),headers={'Authorization':'Bearer '+pathlib.Path(sys.argv[1]).read_text().strip(),'Content-Type':'application/json'})
try:print(opener.open(request,timeout=32).read().decode())
except urllib.error.HTTPError as error:sys.exit(error.read().decode())
"""
    return json.loads(run("python3", "-c", code, config["api_token_file"], body, prefix=config.get("_namespace", ())))["message"]


def echo(address, port=8080, connection=None):
    if connection is None:
        connection = socket.create_connection((address, port), timeout=1)
    connection.sendall(b"portal\n")
    assert connection.recv(64) == b"portal\n"
    return connection


def denied(address, port=8080, connection=None):
    try:
        c = echo(address, port, connection)
    except (OSError, AssertionError):
        return True
    c.close()
    return False


def web_probe(config):
    code = """import json,pathlib,sys,urllib.request,urllib.error
base='http://127.0.0.1:51821'
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
token=pathlib.Path(sys.argv[1]).read_text().strip()
def request(path,headers={}):
 return opener.open(urllib.request.Request(base+path,headers=headers),timeout=5)
page=request('/')
assert page.status==200 and 'Portal' in page.read().decode()
assert page.headers['Cache-Control']=='no-store'
assert "frame-ancestors 'none'" in page.headers['Content-Security-Policy']
assert request('/app.js').headers['Content-Type'].startswith('text/javascript')
assert request('/style.css').headers['Content-Type'].startswith('text/css')
for headers,status in [({},401),({'Authorization':'Bearer '+token,'Origin':'http://untrusted.example'},403),({'Authorization':'Bearer '+token,'Host':'untrusted.example:51821'},403)]:
 try:request('/api/v1/snapshot',headers)
 except urllib.error.HTTPError as error:assert error.code==status
 else:raise AssertionError('unprotected snapshot')
# SSH forwarding changes the browser-facing Host and Origin ports, not the listener.
forwarded={'Host':'127.0.0.1:51822','Origin':'http://127.0.0.1:51822'}
assert request('/',forwarded).status==200
try:request('/api/v1/snapshot',forwarded)
except urllib.error.HTTPError as error:assert error.code==401
else:raise AssertionError('forwarded port bypassed token authentication')
assert request('/api/v1/snapshot',dict(forwarded,Authorization='Bearer '+token)).status==200
for origin in ['http://127.0.0.1:51821','http://localhost:51822','http://untrusted.example']:
 try:request('/api/v1/snapshot',dict(forwarded,Authorization='Bearer '+token,Origin=origin))
 except urllib.error.HTTPError as error:assert error.code==403
 else:raise AssertionError('forwarded port allowed cross-origin access')
response=request('/api/v1/snapshot',{'Authorization':'Bearer '+token})
raw=response.read().decode()
assert token not in raw and 'access_token' not in raw and 'credential_file' not in raw and 'private_key' not in raw
data=json.loads(raw)
assert data['healthy'] and data['mode']=='managed' and data['network']['lease_active']
assert len(data['peers'])==1 and data['peers'][0]['device_id']
assert data['peers'][0]['incoming_tcp']==[8080] or data['peers'][0]['outgoing_tcp']==[8080]
print(json.dumps(data['network']['device_id']))
"""
    return json.loads(run("python3", "-c", code, config["api_token_file"], prefix=config.get("_namespace", ())))


def setup_nat(directory, namespace):
    gateway = spawn("nat-namespace", ["unshare", "--net", "sleep", "infinity"], directory)
    gateway_ns = ("nsenter", "--target", str(gateway.pid), "--net", "--")
    wait_for(lambda: Path(f"/proc/{gateway.pid}/ns/net").readlink() != Path("/proc/self/ns/net").readlink(), "NAT namespace")
    run("ip", "link", "set", "pb", "netns", gateway.pid, prefix=namespace)
    run("ip", "addr", "add", "192.0.2.2/24", "dev", "pb", prefix=gateway_ns)
    run("ip", "link", "set", "lo", "up", prefix=gateway_ns)
    run("ip", "link", "set", "pb", "up", prefix=gateway_ns)
    run("ip", "link", "add", "lan", "type", "veth", "peer", "name", "client", prefix=gateway_ns)
    # Enter B via its persistent namespace process rather than a global netns mount.
    peer_pid = namespace[2]
    run("ip", "link", "set", "client", "netns", peer_pid, prefix=gateway_ns)
    run("ip", "addr", "add", "10.77.0.1/24", "dev", "lan", prefix=gateway_ns)
    run("ip", "link", "set", "lan", "up", prefix=gateway_ns)
    run("ip", "addr", "add", "10.77.0.2/24", "dev", "client", prefix=namespace)
    run("ip", "link", "set", "client", "up", prefix=namespace)
    run("ip", "route", "add", "default", "via", "10.77.0.1", prefix=namespace)
    run("sysctl", "-qw", "net.ipv4.ip_forward=1", prefix=gateway_ns)
    rules = """table ip portal_test {
 chain forward {
  type filter hook forward priority 0; policy drop;
  ct state established,related accept
  iifname "lan" accept
 }
 chain postrouting {
  type nat hook postrouting priority srcnat; policy accept;
  oifname "pb" ip saddr 10.77.0.2 udp sport 51820 snat to 192.0.2.2:45678
  oifname "pb" ip saddr 10.77.0.2 masquerade
 }
}
"""
    subprocess.run([*gateway_ns, "nft", "-f", "-"], input=rules, text=True, check=True)



def main(directory):
    assert os.geteuid() == 0, "run using unshare --user --map-root-user --net"
    assert Path("/proc/self/uid_map").read_text().split()[2] == "1", "use an isolated user namespace"
    peer_namespace = spawn("namespace", ["unshare", "--net", "sleep", "infinity"], directory)
    namespace = ("nsenter", "--target", str(peer_namespace.pid), "--net", "--")
    wait_for(lambda: Path(f"/proc/{peer_namespace.pid}/ns/net").readlink() != Path("/proc/self/ns/net").readlink(), "peer namespace")
    run("ip", "link", "set", "lo", "up")
    run("ip", "link", "add", "pa", "type", "veth", "peer", "name", "pb")
    run("ip", "link", "set", "pb", "netns", peer_namespace.pid)
    run("ip", "addr", "add", "192.0.2.1/24", "dev", "pa")
    run("ip", "link", "set", "pa", "up")
    run("ip", "link", "set", "lo", "up", prefix=namespace)
    run("ip", "addr", "add", "192.0.2.2/24", "dev", "pb", prefix=namespace)
    run("ip", "link", "set", "pb", "up", prefix=namespace)
    nat = os.environ.get("PORTAL_TEST_NAT") == "1"
    if nat:
        setup_nat(directory, namespace)

    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=portal-test", "-addext", "subjectAltName=IP:192.0.2.1", "-addext", "basicConstraints=critical,CA:FALSE", "-keyout", directory / "tls.key", "-out", directory / "tls.pem")
    coordinator_config = directory / "coordinator.json"
    write_json(coordinator_config, {"listen": "0.0.0.0:8443", "state_dir": str(directory / "coordinator"), "lease_seconds": 30, "tls": {"cert_file": str(directory / "tls.pem"), "key_file": str(directory / "tls.key")}})
    coordinator_args = [BIN / "portal-coordinator", "--config", coordinator_config]
    coordinator = spawn("coordinator", coordinator_args, directory)
    wait_for(lambda: (directory / "coordinator/admin.token").exists(), "coordinator bootstrap")
    context = ssl.create_default_context(cafile=str(directory / "tls.pem"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    wait_for(lambda: opener.open("https://192.0.2.1:8443/health", timeout=1).status == 200, "HTTPS coordinator listener")
    owner_token = directory / "coordinator/admin.token"
    configs = []
    for name, endpoint in [("a", "192.0.2.1:51820"), ("b", "192.0.2.2:51820")]:
        state = directory / name
        state.mkdir(mode=0o700)
        run(BIN / "portal", "keygen", "--private-key-file", state / "device.key")
        write_json(state / "policy.json", {})
        config = {"tun_name": "portal0", "private_key_file": str(state / "device.key"), "listen": "0.0.0.0:51820", "workers": 2, "api_token_file": str(state / "api.token"), "coordinator": {"url": "https://192.0.2.1:8443", "device_name": name, "credential_file": str(state / "device.json"), "policy_file": str(state / "policy.json"), "map_file": str(state / "map.json"), "ca_file": str(directory / "tls.pem"), "endpoints": [endpoint]}}
        if nat and name == "b":
            config["coordinator"]["endpoints"] = []

        write_json(state / "runtime.json", config)
        run(BIN / "portal", "enroll", "--config", state / "runtime.json", "--user-token-file", owner_token)
        config["_path"] = state / "runtime.json"
        configs.append(config)
    a, b = configs
    b["_namespace"] = namespace
    identity_a = json.loads(Path(a["coordinator"]["credential_file"]).read_text())["device"]
    identity_b = json.loads(Path(b["coordinator"]["credential_file"]).read_text())["device"]
    grant = {identity_a["public_key"]: {"tcp": [8080]}}
    write_json(Path(b["coordinator"]["policy_file"]), grant)

    if nat:
        # Block all WireGuard replies before either agent can establish a session.
        subprocess.run(["nft", "-f", "-"], input="""table inet portal_block {
 chain input { type filter hook input priority -10; policy accept; udp dport 51820 drop; }
}
""", text=True, check=True)
    agents = []
    for name, config in zip(("a", "b"), configs):
        agents.append(spawn("agent-" + name, [BIN / "portal", "run", "--config", config["_path"]], directory, prefix=config.get("_namespace", ())))
    wait_for(lambda: all("peers=1" in command(c, "status") for c in configs), "applied peer maps")
    assert web_probe(a) == identity_a["id"]
    assert web_probe(b) == identity_b["id"]
    print("PASS: embedded web panel, authenticated JSON snapshots, origin checks and private credentials omitted", flush=True)
    print("PASS: enrollment, policy publication and two managed agents", flush=True)

    echo_server = """import socket,threading,time
def serve(family,port):
 s=socket.socket(family);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
 if family==socket.AF_INET6:s.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
 s.bind(('::' if family==socket.AF_INET6 else '0.0.0.0',port));s.listen()
 def client(c):
  with c:
   while True:
    data=c.recv(4096)
    if not data:break
    c.sendall(data)
 while True:threading.Thread(target=client,args=(s.accept()[0],),daemon=True).start()
for family,port in [(socket.AF_INET,8080),(socket.AF_INET,8081),(socket.AF_INET6,8080)]:threading.Thread(target=serve,args=(family,port),daemon=True).start()
time.sleep(3600)
"""
    spawn("echo-b", ["python3", "-c", echo_server], directory, prefix=namespace)
    spawn("echo-a", ["python3", "-c", echo_server], directory)
    if nat:
        wait_for(lambda: "192.0.2.2:45678" in Path(b["coordinator"]["map_file"]).read_text(), "STUN-discovered external port")
        try:
            command(a, "connect", peer_device_id=identity_b["id"])
        except subprocess.CalledProcessError as error:
            assert "P2P direct path timed out" in error.stderr, error.stderr
        else:
            raise AssertionError("signaling ACK falsely reported a working blocked UDP path")
        run("nft", "delete", "table", "inet", "portal_block")
        print("PASS: blocked UDP path times out despite signaling ACK", flush=True)
    assert "path=direct" in command(a, "connect", peer_device_id=identity_b["id"])
    assert "path=direct" in command(a, "list")
    if nat:
        print("PASS: integrated coordinator STUN discovered via HTTPS map, translated UDP port, NAT hole punching and UDP recovery", flush=True)
    wait_for(lambda: echo(identity_b["ipv4"]).close() is None, "IPv4 TCP")
    wait_for(lambda: echo(identity_b["ipv6"]).close() is None, "IPv6 TCP")
    assert denied(identity_b["ipv4"], 8081), "ungranted port was reachable"
    reverse_probe = """import socket,sys
try:
 c=socket.create_connection((sys.argv[1],8080),timeout=1)
except OSError:
 print('denied')
else:
 c.close();raise SystemExit('unexpected reverse access')
"""
    assert run("python3", "-c", reverse_probe, identity_a["ipv4"], prefix=namespace) == "denied"
    print("PASS: P2P request/ACK, IPv4/IPv6 TCP, denied neighboring port and denied reverse access for the same owner", flush=True)
    try:
        command(a, "peer_remove", public_key=identity_b["public_key"])
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError("manual API changed managed peers")

    live = echo(identity_b["ipv4"])
    coordinator.terminate()
    coordinator.wait(timeout=5)
    write_json(Path(b["coordinator"]["policy_file"]), {})
    time.sleep(1.5)
    assert denied(identity_b["ipv4"], connection=live), "offline local revocation left established flow open"
    live.close()
    print("PASS: local revocation closes an established TCP flow while coordinator is offline", flush=True)
    write_json(Path(b["coordinator"]["policy_file"]), grant)
    wait_for(lambda: echo(identity_b["ipv4"]).close() is None, "offline regrant within confirmed map lease", seconds=5)
    wait_for(lambda: "lease_active=false" in command(a, "status") and "lease_active=false" in command(b, "status"), "monotonic lease expiration", seconds=35)
    assert denied(identity_b["ipv4"]), "expired map still allowed TCP"
    print("PASS: coordinator outage expires permissions on the packet path", flush=True)

    coordinator = spawn("coordinator-restart", coordinator_args, directory)
    wait_for(lambda: "lease_active=true" in command(a, "status") and "lease_active=true" in command(b, "status"), "coordinator reconnection", seconds=15)
    wait_for(lambda: echo(identity_b["ipv4"]).close() is None, "TCP after coordinator restart")
    context = ssl.create_default_context(cafile=str(directory / "tls.pem"))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context))
    request = urllib.request.Request("https://192.0.2.1:8443/api/v1/devices/" + identity_b["id"], method="DELETE", headers={"Authorization": "Bearer " + owner_token.read_text().strip()})
    assert opener.open(request, timeout=5).status == 204
    wait_for(lambda: "peers=0" in command(a, "status") and agents[1].poll() is None and "lease_active=false" in command(b, "status"), "online device revocation")
    assert denied(identity_b["ipv4"])
    print("PASS: restart recovery and online device revocation", flush=True)


with tempfile.TemporaryDirectory(prefix="portal-managed-") as temp:
    directory = Path(temp)
    try:
        main(directory)
    except BaseException:
        for log in LOGS:
            print(f"--- {log.name} ---\n{log.read_text()[-12000:]}")
        raise
    finally:
        for process in reversed(PROCESSES):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
