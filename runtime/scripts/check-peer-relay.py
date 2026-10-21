#!/usr/bin/env python3
"""One Portal peer hosts relay and files; two relay-only peers exchange files through it."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

BASE = pathlib.Path(__file__).resolve().parents[2]
BIN = BASE / 'target' / 'debug'


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix='portal-peer-relay-') as temporary:
    root = pathlib.Path(temporary)
    keys, processes, logs = [], [], []
    ports = [free_port() for _ in range(4)]
    relay_port = free_port(socket.SOCK_DGRAM)
    relay_address = f'127.0.0.1:{relay_port}'
    payload = bytes(range(256)) * 1200
    (root / 'share').mkdir()
    (root / 'share' / 'data.bin').write_bytes(payload)
    try:
        for i in range(4):
            output = subprocess.check_output([str(BIN / 'portal'), 'keygen', '--private-key-file', str(root / f'key{i}')], text=True)
            keys.append(output.strip().splitlines()[-1].removeprefix('public key: '))
        relay_peer = {'public_key': keys[0], 'endpoint': relay_address}
        for i in range(4):
            config = {'private_key_file': f'key{i}', 'listen': None, 'relays': [] if i == 0 else [relay_peer],
                      'api_listen': f'127.0.0.1:{ports[i]}', 'api_token_file': f'token{i}', 'services': []}
            if i == 0:
                config['relay_server'] = {'public_endpoint': relay_address, 'listen': relay_address, 'allowed_peers': keys[1:3]}
            if i in (0, 2):
                config['services'] = [{'type': 'files', 'root': 'share', 'allowed_downloaders': [keys[1]]}]
            path = root / f'config{i}.json'
            path.write_text(json.dumps(config))
            log = (root / f'log{i}').open('w+')
            logs.append(log)
            processes.append(subprocess.Popen([str(BIN / 'portal-runtime')], stdout=log, stderr=log,
                                             env={**os.environ, 'PORTAL_CONFIG': str(path)}))

        def post(i, path, body):
            token = (root / f'token{i}').read_text().strip()
            request = urllib.request.Request(f'http://127.0.0.1:{ports[i]}{path}', data=json.dumps(body).encode(),
                                             headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token})
            return urllib.request.urlopen(request, timeout=75)

        def api(i, path, body):
            with post(i, path, body) as response:
                return json.load(response)

        def command(i, operation, **fields):
            return api(i, '/api/v1/command', {'operation': operation, **fields})

        def state(i):
            return api(i, '/api/v1/state', {})

        def expect_error(status, callback):
            try:
                callback()
                raise AssertionError(f'expected HTTP {status}')
            except urllib.error.HTTPError as error:
                assert error.code == status, (error.code, error.read())

        for i in range(4):
            deadline = time.monotonic() + 15
            while True:
                if processes[i].poll() is not None:
                    raise RuntimeError(f'runtime {i} exited during startup')
                try:
                    command(i, 'health')
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(.05)
            assert state(i)['listen'] is None, 'application UDP must be disabled in this test'

        # Infrastructure permission, Portal trust and file permission are independent.
        # B trusts the outsider at the application layer, so its failure proves relay ACL enforcement.
        for i, peers in enumerate([[1, 2], [0, 2], [0, 1, 3], [2]]):
            for peer in peers:
                command(i, 'peer_upsert', public_key=keys[peer])
        own = state(0)
        assert own['relay_server']['endpoint'] == relay_address
        assert set(own['relay_server']['allowed_peers']) == set(keys[1:3])
        assert all(peer['relay_allowed'] for peer in own['peers'])
        assert state(1)['relay_server'] is None
        expect_error(400, lambda: command(1, 'relay_access_set', public_key=keys[2], allowed=True))
        expect_error(400, lambda: command(1, 'peer_upsert', public_key=keys[2], allow_relay=True))

        info = api(1, '/api/v1/peers/info', {'peer': keys[0]})
        assert info == {'public_key': keys[0], 'relay_server': relay_peer}
        assert next(peer for peer in state(1)['peers'] if peer['public_key'] == keys[0])['relay_server'] == relay_peer
        assert api(0, '/api/v1/peers/info', {'peer': keys[1]})['relay_server'] is None

        def download(reader, writer):
            with post(reader, '/api/v1/files/download', {'peer': keys[writer], 'path': 'data.bin'}) as response:
                assert response.headers['Content-Length'] == str(len(payload))
                assert response.read() == payload

        download(1, 2)  # A -> relay R -> B
        download(1, 0)  # The same relay R also serves its own ordinary file service.
        assert all(peer['path'] == 'relay' for peer in state(1)['peers'])
        assert api(2, '/api/v1/files/resources', {'peer': keys[0]}) == {'resources': []}
        expect_error(502, lambda: api(3, '/api/v1/files/resources', {'peer': keys[2]}))

        command(0, 'relay_access_set', public_key=keys[1], allowed=False)
        command(0, 'services_reload')
        assert keys[1] not in state(0)['relay_server']['allowed_peers'], 'service reload must preserve live relay permissions'
        deadline = time.monotonic() + 5
        while state(0)['relay_server']['connected_clients'] > 1:
            assert time.monotonic() < deadline, 'revoked relay connections were not evicted'
            time.sleep(.05)
        # Close the old cached application session, then verify a new handshake cannot pass.
        command(1, 'peer_upsert', public_key=keys[2], relay=relay_peer)
        expect_error(502, lambda: api(1, '/api/v1/files/resources', {'peer': keys[2]}))
        assert api(2, '/api/v1/peers/info', {'peer': keys[0]})['relay_server'] == relay_peer
        command(0, 'peer_upsert', public_key=keys[1], allow_relay=True)
        deadline = time.monotonic() + 30
        while True:
            try:
                download(1, 2)
                break
            except urllib.error.HTTPError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(.1)
        command(0, 'peer_remove', public_key=keys[1])
        assert keys[1] not in state(0)['relay_server']['allowed_peers']
        for i in (1, 2, 3, 0):
            command(i, 'shutdown')
            assert processes[i].wait(timeout=10) == 0
            assert not (root / f'token{i}').exists()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('127.0.0.1', relay_port))
        print('PASS: peer+relay, relay-only file transfer, capability discovery, separate ACLs, outsider rejection, live revoke/regrant, reload, removal, clean shutdown')
    except BaseException:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read())
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
