#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repo_dir"

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

if [[ ${EUID} -ne 0 ]]; then
    die "run as root (the script creates network namespaces, TUN and WireGuard interfaces)"
fi

for command in ip wg ping base64; do
    need "$command"
done

tmp_dir=$(mktemp -d)
portal_ns="pwg-$$"
kernel_ns="kwg-$$"
portal_pid=""
portal_ns_created=0
kernel_ns_created=0

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$portal_pid" ]]; then
        kill -TERM "$portal_pid" 2>/dev/null || true
        wait "$portal_pid" 2>/dev/null || true
    fi
    if [[ $portal_ns_created -eq 1 ]]; then
        ip netns del "$portal_ns" 2>/dev/null || true
    fi
    if [[ $kernel_ns_created -eq 1 ]]; then
        ip netns del "$kernel_ns" 2>/dev/null || true
    fi
    rm -rf "$tmp_dir"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

portal_bin="$repo_dir/target/debug/examples/wireguard_interop"
[[ -x "$portal_bin" ]] || die "example not found; build it with: cargo build -p portal --example wireguard_interop"
printf 'Starting the userspace WireGuard example...\n'

ip netns add "$portal_ns"
portal_ns_created=1
ip netns add "$kernel_ns"
kernel_ns_created=1
ip -n "$portal_ns" link set lo up
ip -n "$kernel_ns" link set lo up

ip link add p0 type veth peer name k0
ip link set p0 netns "$portal_ns"
ip link set k0 netns "$kernel_ns"
ip -n "$portal_ns" addr add 192.0.2.1/24 dev p0
ip -n "$kernel_ns" addr add 192.0.2.2/24 dev k0
ip -n "$portal_ns" link set p0 up
ip -n "$kernel_ns" link set k0 up

wg genkey > "$tmp_dir/portal.key"
wg pubkey < "$tmp_dir/portal.key" > "$tmp_dir/portal.pub"
wg genkey > "$tmp_dir/kernel.key"
wg pubkey < "$tmp_dir/kernel.key" > "$tmp_dir/kernel.pub"
base64 --decode "$tmp_dir/portal.key" > "$tmp_dir/portal.key.raw"
base64 --decode "$tmp_dir/portal.pub" > "$tmp_dir/portal.pub.raw"
base64 --decode "$tmp_dir/kernel.key" > "$tmp_dir/kernel.key.raw"
base64 --decode "$tmp_dir/kernel.pub" > "$tmp_dir/kernel.pub.raw"

kernel_peer_options=(
    private-key "$tmp_dir/kernel.key"
    listen-port 51821
    peer "$(cat "$tmp_dir/portal.pub")"
    endpoint 192.0.2.1:51820
    allowed-ips 10.200.0.1/32,fd00:200::1/128
)
portal_args=(
    wg-portal
    0.0.0.0:51820
    "$tmp_dir/portal.key.raw"
    "$tmp_dir/kernel.pub.raw"
    192.0.2.2:51821
    10.200.0.2/32,fd00:200::2/128
)

if [[ ${WITH_PSK:-0} == 1 ]]; then
    wg genpsk > "$tmp_dir/psk"
    base64 --decode "$tmp_dir/psk" > "$tmp_dir/psk.raw"
    kernel_peer_options+=(preshared-key "$tmp_dir/psk")
    portal_args+=("$tmp_dir/psk.raw")
fi

if ! ip -n "$kernel_ns" link add wg-kernel type wireguard 2>"$tmp_dir/wg-error"; then
    cat "$tmp_dir/wg-error" >&2
    die "kernel WireGuard interface could not be created; check that WireGuard is enabled"
fi
ip netns exec "$kernel_ns" wg set wg-kernel "${kernel_peer_options[@]}"
ip -n "$kernel_ns" addr add 10.200.0.2/24 dev wg-kernel
ip -n "$kernel_ns" -6 addr add fd00:200::2/64 dev wg-kernel
ip -n "$kernel_ns" link set wg-kernel up

ip netns exec "$portal_ns" "$portal_bin" "${portal_args[@]}" >"$tmp_dir/portal.log" 2>&1 &
portal_pid=$!

for _ in {1..50}; do
    if ! kill -0 "$portal_pid" 2>/dev/null; then
        cat "$tmp_dir/portal.log" >&2
        die "userspace WireGuard device exited during startup"
    fi
    if ip -n "$portal_ns" link show wg-portal >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done
ip -n "$portal_ns" link show wg-portal >/dev/null 2>&1 || {
    cat "$tmp_dir/portal.log" >&2
    die "userspace TUN interface was not created"
}

ip -n "$portal_ns" addr add 10.200.0.1/24 dev wg-portal
ip -n "$portal_ns" -6 addr add fd00:200::1/64 dev wg-portal
ip -n "$portal_ns" link set wg-portal up

printf 'Testing userspace -> kernel IPv4...\n'
ip netns exec "$portal_ns" ping -n -c 3 -W 2 -I 10.200.0.1 10.200.0.2 || {
    ip netns exec "$kernel_ns" wg show wg-kernel >&2 || true
    cat "$tmp_dir/portal.log" >&2
    die "userspace-to-kernel IPv4 ping failed"
}

printf 'Testing kernel -> userspace IPv4...\n'
ip netns exec "$kernel_ns" ping -n -c 3 -W 2 -I 10.200.0.2 10.200.0.1 || {
    ip netns exec "$kernel_ns" wg show wg-kernel >&2 || true
    cat "$tmp_dir/portal.log" >&2
    die "kernel-to-userspace IPv4 ping failed"
}

printf 'Testing userspace -> kernel IPv6...\n'
ip netns exec "$portal_ns" ping -6 -n -c 3 -W 2 -I fd00:200::1 fd00:200::2 || {
    ip netns exec "$kernel_ns" wg show wg-kernel >&2 || true
    cat "$tmp_dir/portal.log" >&2
    die "userspace-to-kernel IPv6 ping failed"
}

printf 'Testing kernel -> userspace IPv6...\n'
ip netns exec "$kernel_ns" ping -6 -n -c 3 -W 2 -I fd00:200::2 fd00:200::1 || {
    ip netns exec "$kernel_ns" wg show wg-kernel >&2 || true
    cat "$tmp_dir/portal.log" >&2
    die "kernel-to-userspace IPv6 ping failed"
}

printf 'Kernel handshake and transfer counters:\n'
ip netns exec "$kernel_ns" wg show wg-kernel
if [[ ${WITH_PSK:-0} == 1 ]]; then
    printf 'Kernel/userspace interoperability passed (PSK enabled).\n'
else
    printf 'Kernel/userspace interoperability passed (no PSK).\n'
fi
