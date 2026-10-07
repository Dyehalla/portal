#!/usr/bin/env bash
# End-to-end: portal runtime + managed Samba -> kernel WireGuard + smbclient.
set -euo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"
die() { printf 'error: %s\n' "$*" >&2; exit 1; }
[[ $EUID -eq 0 ]] || die "run as root"
[[ -n ${SMB_TEST_USER:-} ]] || die "set SMB_TEST_USER to an existing non-root Linux account"
[[ $(id -u "$SMB_TEST_USER") -ne 0 ]] || die "SMB_TEST_USER must not be root"
for command in ip wg smbd smbclient testparm python3 timeout base64 od tr cmp grep ping pgrep ps; do
    command -v "$command" >/dev/null || die "missing command: $command"
done
[[ -c /dev/net/tun ]] || die "/dev/net/tun is unavailable"
runtime_bin="$repo_dir/target/debug/portal-runtime"
cli_bin="$repo_dir/target/debug/portal"
[[ -x $runtime_bin && -x $cli_bin ]] || die "build first: cargo build -p portal-runtime -p portal-cli"

tmp_dir=$(mktemp -d)
server_ns="psmb-$$"
client_ns="csmb-$$"
runtime_pid=""
smb_args=()
smb_port=1445
smb_uid=$(id -u "$SMB_TEST_USER")
if [[ ${SMB_AS_ROOT:-0} == 1 ]]; then
    smb_args+=(--smb-as-root)
    smb_port=445
    smb_uid=0
fi
server_created=0
client_created=0
cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n $runtime_pid ]]; then
        kill -TERM "$runtime_pid" 2>/dev/null || true
        for _ in {1..100}; do
            kill -0 "$runtime_pid" 2>/dev/null || break
            sleep 0.1
        done
        kill -KILL "$runtime_pid" 2>/dev/null || true
        wait "$runtime_pid" 2>/dev/null || true
    fi
    # Remove any session processes left by a failed test, in these namespaces only.
    for ns in "$server_ns" "$client_ns"; do
        while read -r pid; do
            [[ -z $pid ]] || kill -KILL "$pid" 2>/dev/null || true
        done < <(ip netns pids "$ns" 2>/dev/null || true)
    done
    [[ $server_created -eq 0 ]] || ip netns del "$server_ns" || true
    [[ $client_created -eq 0 ]] || ip netns del "$client_ns" || true
    rm -rf -- "$tmp_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The chosen Unix account must be able to traverse the test share's parent.
chmod 755 "$tmp_dir"
mkdir "$tmp_dir/share"
chmod 755 "$tmp_dir/share"
printf 'portal SMB over WireGuard\n' > "$tmp_dir/share/test.txt"
chmod 644 "$tmp_dir/share/test.txt"
ln -s /etc/passwd "$tmp_dir/share/outside"
python3 - "$tmp_dir" "$SMB_TEST_USER" <<'PY'
import pathlib, secrets, sys
root = pathlib.Path(sys.argv[1])
password = secrets.token_hex(24)
(root / "password").write_text(password + "\n")
(root / "auth").write_text(f"username = {sys.argv[2]}\npassword = {password}\n")
PY
wg genkey > "$tmp_dir/server.key"
wg pubkey < "$tmp_dir/server.key" > "$tmp_dir/server.pub"
wg genkey > "$tmp_dir/client.key"
wg pubkey < "$tmp_dir/client.key" > "$tmp_dir/client.pub"
base64 --decode "$tmp_dir/server.key" > "$tmp_dir/server.raw"
client_hex=$(base64 --decode "$tmp_dir/client.pub" | od -An -tx1 | tr -d ' \n')

ip netns add "$server_ns"
server_created=1
ip netns add "$client_ns"
client_created=1
ip -n "$server_ns" link set lo up
ip -n "$client_ns" link set lo up
# Create veth inside the test namespace, never in the host's network namespace.
ip -n "$server_ns" link add p0 type veth peer name c0
ip -n "$server_ns" link set c0 netns "$client_ns"
ip -n "$server_ns" addr add 192.0.2.1/24 dev p0
ip -n "$client_ns" addr add 192.0.2.2/24 dev c0
ip -n "$server_ns" link set p0 up
ip -n "$client_ns" link set c0 up
ip -n "$client_ns" link add wg-client type wireguard
ip netns exec "$client_ns" wg set wg-client private-key "$tmp_dir/client.key" \
    listen-port 51821 peer "$(cat "$tmp_dir/server.pub")" endpoint 192.0.2.1:51820 \
    allowed-ips 10.200.0.1/32 persistent-keepalive 1
ip -n "$client_ns" addr add 10.200.0.2/24 dev wg-client
ip -n "$client_ns" link set wg-client up

ip netns exec "$server_ns" "$runtime_bin" run \
    --tun portal0 --private-key-file "$tmp_dir/server.raw" --listen 192.0.2.1:51820 \
    --no-dual-stack --address 10.200.0.1/24 --api-token-file "$tmp_dir/api.token" \
    --peer-http-listen 10.200.0.1:8080 \
    --smb-root "$tmp_dir/share" --smb-listen 10.200.0.1 \
    --smb-user "$SMB_TEST_USER" --smb-password-file "$tmp_dir/password" \
    --smb-allow-peer 10.200.0.2 --smb-port "$smb_port" "${smb_args[@]}" > "$tmp_dir/runtime.log" 2>&1 &
runtime_pid=$!
for _ in {1..150}; do
    if ! kill -0 "$runtime_pid" 2>/dev/null; then
        cat "$tmp_dir/runtime.log" >&2
        die "runtime failed during startup"
    fi
    if grep -q '^READY ' "$tmp_dir/runtime.log"; then break; fi
    sleep 0.1
done
smb_pid=$(pgrep -P "$runtime_pid" -x smbd)
[[ $(ps -o euid= -p "$smb_pid" | tr -d ' ') == "$smb_uid" ]] || die "Samba process has unexpected UID"
ip netns exec "$server_ns" "$cli_bin" peer upsert --token-file "$tmp_dir/api.token" \
    --public-key "$client_hex" --endpoint 192.0.2.2:51821 --allowed-ip 10.200.0.2/32

smb=(ip netns exec "$client_ns" timeout 15 smbclient //10.200.0.1/documents \
    -p "$smb_port" -A "$tmp_dir/auth" --option='client min protocol=SMB2_02')
for _ in {1..30}; do
    if "${smb[@]}" -c "get test.txt $tmp_dir/downloaded" > "$tmp_dir/client.log" 2>&1; then break; fi
    sleep 0.1
done
[[ -f $tmp_dir/downloaded ]] || { cat "$tmp_dir/client.log" >&2; die "SMB read failed"; }
cmp "$tmp_dir/share/test.txt" "$tmp_dir/downloaded"
"${smb[@]}" -c "put $tmp_dir/downloaded forbidden.txt" > "$tmp_dir/write.log" 2>&1 || true
[[ ! -e $tmp_dir/share/forbidden.txt ]] || die "read-only share accepted a write"
"${smb[@]}" -c "get outside $tmp_dir/leaked" > "$tmp_dir/symlink.log" 2>&1 || true
[[ ! -s $tmp_dir/leaked ]] || die "share followed a symlink"
if ip netns exec "$client_ns" timeout 15 smbclient //10.200.0.1/documents -p "$smb_port" -N -c ls > "$tmp_dir/guest.log" 2>&1; then
    die "guest access succeeded"
fi
if ip netns exec "$client_ns" python3 -c 'import socket,sys; socket.create_connection(("192.0.2.1",int(sys.argv[1])),2).close()' "$smb_port" 2>/dev/null; then
    die "SMB is listening on the underlay interface"
fi
# Reachable WireGuard source IP without an SMB grant must still be rejected.
ip netns exec "$server_ns" "$cli_bin" peer upsert --token-file "$tmp_dir/api.token" \
    --public-key "$client_hex" --allowed-ip 10.200.0.2/32 --allowed-ip 10.200.0.3/32
ip -n "$client_ns" addr del 10.200.0.2/24 dev wg-client
ip -n "$client_ns" addr add 10.200.0.3/24 dev wg-client
ip netns exec "$client_ns" ping -n -c 1 -W 2 10.200.0.1 >/dev/null
if "${smb[@]}" -c ls > "$tmp_dir/denied-peer.log" 2>&1; then
    die "ungranted peer IP accessed the share"
fi
ip -n "$client_ns" addr del 10.200.0.3/24 dev wg-client
ip -n "$client_ns" addr add 10.200.0.2/24 dev wg-client
ip netns exec "$server_ns" "$cli_bin" shutdown --token-file "$tmp_dir/api.token"
for _ in {1..100}; do
    kill -0 "$runtime_pid" 2>/dev/null || break
    sleep 0.1
done
kill -0 "$runtime_pid" 2>/dev/null && die "runtime failed to stop"
wait "$runtime_pid"
runtime_pid=""
if ip netns exec "$client_ns" python3 -c 'import socket,sys; socket.create_connection(("10.200.0.1",int(sys.argv[1])),2).close()' "$smb_port" 2>/dev/null; then
    die "SMB remained available after shutdown"
fi
printf 'SMB over WireGuard passed: read, write denial, symlink denial, guest denial, peer denial, tunnel-only listener and shutdown.\n'
