#!/usr/bin/env python3
"""Two rootless QUIC runtimes: web assets, state, file API, reload, revocation, shutdown."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.error
import argparse

BASE = pathlib.Path(__file__).resolve().parents[2]
BIN = BASE / 'target' / 'debug'
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--relay', action='store_true', help='run the built-in UDP peer-relay scenario')
options = parser.parse_args()
if options.relay:
    subprocess.run([os.sys.executable, str(BASE / "runtime/scripts/check-peer-relay.py")], check=True)
    raise SystemExit(0)


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix='portal-quic-') as temporary:
    root = pathlib.Path(temporary)
    share = root / 'share'
    share.mkdir()
    payload = bytes(range(256)) * 1200
    (share / 'data.bin').write_bytes(payload)
    processes, logs, keys = [], [], []
    tokens = [root / f'token{i}' for i in range(2)]
    apis = [free_port(socket.SOCK_STREAM) for _ in range(2)]
    udp = [free_port(socket.SOCK_DGRAM) for _ in range(2)]
    try:
        for i in range(2):
            output = subprocess.check_output([str(BIN / 'portal'), 'keygen', '--private-key-file', str(root / f'key{i}')], text=True)
            keys.append(output.strip().splitlines()[-1].removeprefix('public key: '))
        for i in range(2):
            settings = {'private_key_file': f'key{i}', 'listen': f'127.0.0.1:{udp[i]}',
                        'api_listen': f'127.0.0.1:{apis[i]}', 'api_token_file': f'token{i}', 'services': []}
            if i == 1:
                settings['services'] = [{'type': 'files', 'root': 'share', 'allowed_downloaders': [keys[0]]}]
            config = root / f'config{i}.json'
            config.write_text(json.dumps(settings))
            log = (root / f'log{i}').open('w+')
            logs.append(log)
            processes.append(subprocess.Popen([str(BIN / 'portal-runtime')], stdout=log, stderr=log,
                                               env={**os.environ, 'PORTAL_CONFIG': str(config)}))

        def command(i, body):
            request = urllib.request.Request(f'http://127.0.0.1:{apis[i]}/api/v1/command',
                data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + tokens[i].read_text().strip()})
            with urllib.request.urlopen(request, timeout=20) as response:
                return json.load(response)

        for i in range(2):
            deadline = time.monotonic() + 10
            while True:
                if processes[i].poll() is not None:
                    raise RuntimeError('runtime exited during startup')
                try:
                    command(i, {'operation': 'health'})
                    break
                except (OSError, ValueError):
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.05)
            status = command(i, {'operation': 'status'})['message']
            assert keys[i] in status and 'net=iroh' in status, status
            names = [(task / 'comm').read_text().strip() for task in pathlib.Path(f'/proc/{processes[i].pid}/task').iterdir()]
            assert 'portal-net' not in names and not any(name.startswith('portal-device') for name in names), names
        for i in range(2):
            command(i, {'operation': 'peer_upsert', 'public_key': keys[1-i], 'endpoint': f'127.0.0.1:{udp[1-i]}'})

        def snapshot(i):
            request = urllib.request.Request(f'http://127.0.0.1:{apis[i]}/api/v1/state',
                data=b'{}', headers={'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + tokens[i].read_text().strip()})
            with urllib.request.urlopen(request, timeout=10) as response:
                assert response.headers['Cache-Control'] == 'no-store'
                return json.load(response)

        # The embedded UI is public static data; live state always requires the token.
        for path, content_type in [('/', 'text/html'), ('/app.js', 'text/javascript'),
                                   ('/styles.css', 'text/css'), ('/favicon.svg', 'image/svg+xml')]:
            with urllib.request.urlopen(f'http://127.0.0.1:{apis[0]}{path}', timeout=10) as response:
                assert response.headers['Content-Type'].startswith(content_type)
                assert response.headers['Cache-Control'] == 'no-store'
                assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
                assert tokens[0].read_text().strip().encode() not in response.read()
        for route, extra_headers, body, expected in [
            ('/api/v1/state', {}, b'{}', 401),
            ('/api/v1/state', {'Authorization': 'Bearer ' + tokens[0].read_text().strip()}, b'{"extra":true}', 400),
            ('/api/v1/state', {'Authorization': 'Bearer ' + tokens[0].read_text().strip(), 'Origin': 'http://example.com'}, b'{}', 403),
            ('/', {'Host': 'example.com'}, None, 403),
        ]:
            request = urllib.request.Request(f'http://127.0.0.1:{apis[0]}{route}', data=body,
                headers={'Content-Type': 'application/json', **extra_headers})
            try:
                urllib.request.urlopen(request, timeout=10).close()
                raise AssertionError(f'HTTP {expected} expected for {route}')
            except urllib.error.HTTPError as error:
                assert error.code == expected, (route, error.code)
        for i in range(2):
            state = snapshot(i)
            assert state['healthy'] and state['can_reload']
            assert state['public_key'] == keys[i]
            assert state['listen'] == (f'127.0.0.1:{udp[i]}')
            assert state['peers'][0]['public_key'] == keys[1-i]
            assert state['peers'][0]['path'] == 'offline'

        # A second API instance cannot refresh or remove a live runtime's token.
        token_before_collision = tokens[0].read_text()
        collision_config = json.loads((root / 'config0.json').read_text())
        subprocess.check_output([str(BIN / 'portal'), 'keygen', '--private-key-file', str(root / 'collision.key')])
        collision_config['private_key_file'] = 'collision.key'
        collision_config['listen'] = f'127.0.0.1:{free_port(socket.SOCK_DGRAM)}'
        collision_config['api_listen'] = f'127.0.0.1:{free_port(socket.SOCK_STREAM)}'
        collision_path = root / 'collision.json'
        collision_path.write_text(json.dumps(collision_config))
        collision = subprocess.run([str(BIN / 'portal-runtime')], capture_output=True, text=True,
                                   env={**os.environ, 'PORTAL_CONFIG': str(collision_path)}, timeout=10)
        assert collision.returncode != 0 and 'in use' in collision.stderr, collision.stderr
        assert tokens[0].read_text() == token_before_collision
        command(0, {'operation': 'health'})
        def file_request(operation, payload=None):
            body = {'peer': keys[1], **(payload or {})}
            request = urllib.request.Request(f'http://127.0.0.1:{apis[0]}/api/v1/files/{operation}',
                data=json.dumps(body).encode(), headers={'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + tokens[0].read_text().strip()})
            return urllib.request.urlopen(request, timeout=20)

        def listing():
            with file_request('list', {'path': ''}) as response:
                return json.load(response)

        def names():
            return [entry['name'] for entry in listing()['entries']]

        def download(path):
            with file_request('download', {'path': path}) as response:
                assert response.headers['Content-Length'] == str(len(payload))
                assert response.headers['Content-Type'] == 'application/octet-stream'
                assert response.headers['Content-Disposition'].startswith('attachment;')
                return response.read()

        with file_request('resources') as response:
            resources = json.load(response)
            assert resources['resources'][0]['id'] == 'files'
        with file_request('metadata', {'path': 'data.bin'}) as response:
            metadata = json.load(response)
            assert metadata['size_bytes'] == len(payload)
        assert 'data.bin' in names()
        assert download('data.bin') == payload
        connections_before = command(0, {'operation': 'stats'})['message'].split()[0]
        assert connections_before == 'active_connections=1', connections_before
        command(0, {'operation': 'peer_upsert', 'public_key': keys[1], 'endpoint': f'127.0.0.1:{udp[1]}'})
        assert command(0, {'operation': 'stats'})['message'].split()[0] == connections_before
        assert download('data.bin') == payload
        assert 'path=direct' in command(0, {'operation': 'peer_stats', 'public_key': keys[1]})['message']
        state = snapshot(0)
        assert state['peers'][0]['path'] == 'direct'
        assert state['stats']['connections'] == 1 and state['stats']['rx_bytes'] > 0
        try:
            file_request('download', {'path': 'x' * 17000})
            raise AssertionError('oversized QUIC request accepted by HTTP API')
        except urllib.error.HTTPError as error:
            assert error.code == 400
            assert '16 KiB' in json.load(error)['message']
        status_before = command(1, {'operation': 'status'})
        token_before = tokens[1].read_text()
        server_config = root / 'config1.json'
        settings = json.loads(server_config.read_text())
        replacement = root / 'replacement'
        replacement.mkdir()
        (replacement / 'new.bin').write_bytes(payload)
        settings['services'][0]['root'] = 'replacement'
        server_config.write_text(json.dumps(settings))
        command(1, {'operation': 'services_reload'})
        assert command(1, {'operation': 'status'}) == status_before
        assert tokens[1].read_text() == token_before
        assert 'new.bin' in names() and 'data.bin' not in names()
        valid = server_config.read_text()
        for invalid in ['{broken', json.dumps({**settings, 'services': [{'type': 'files', 'root': 'missing', 'allowed_downloaders': [keys[0]]}]})]:
            server_config.write_text(invalid)
            try:
                command(1, {'operation': 'services_reload'})
                raise AssertionError('invalid reload accepted')
            except urllib.error.HTTPError as error:
                assert error.code == 400
            assert 'new.bin' in names()
        server_config.write_text(valid)
        settings['services'] = []
        server_config.write_text(json.dumps(settings))
        command(1, {'operation': 'services_reload'})
        try:
            listing()
            raise AssertionError('disabled file service accepted request')
        except urllib.error.HTTPError as error:
            assert error.code == 404
        settings['services'] = [{'type': 'files', 'root': 'replacement', 'allowed_downloaders': [keys[0]]}]
        server_config.write_text(json.dumps(settings))
        command(1, {'operation': 'services_reload'})
        assert download('new.bin') == payload
        command(1, {'operation': 'peer_remove', 'public_key': keys[0]})
        try:
            listing()
            raise AssertionError('revoked peer accepted request')
        except urllib.error.HTTPError as error:
            assert error.code == 502
        for i in range(2):
            command(i, {'operation': 'shutdown'})
            assert processes[i].wait(timeout=10) == 0
            assert not tokens[i].exists()
        print(f'PASS (direct): web assets, authenticated state, iroh identities, file API, token collision, unchanged upsert, request size, reload, invalid reload, disable/re-enable, revocation, clean shutdown')
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
