#!/usr/bin/env python3
"""Exercise two rootless runtimes, the local API, and userspace file transport."""
import json
import os
import pathlib
import socket
import subprocess
import tempfile
import time
import urllib.request

BASE = pathlib.Path(__file__).resolve().parents[2]
BIN = BASE / 'target' / 'debug'


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


with tempfile.TemporaryDirectory(prefix='portal-userspace-') as temporary:
    root = pathlib.Path(temporary)
    share = root / 'share'
    share.mkdir()
    payload = bytes(range(256)) * 1200
    (share / 'data.bin').write_bytes(payload)
    processes = []
    logs = []
    tokens = []
    apis = [free_port(socket.SOCK_STREAM) for _ in range(2)]
    udp = [free_port(socket.SOCK_DGRAM) for _ in range(2)]
    keys = []
    try:
        for i in range(2):
            key_file = root / f'key{i}'
            keys.append(subprocess.check_output([str(BIN / 'portal'), 'keygen', '--private-key-file', str(key_file)], text=True).strip().splitlines()[-1].removeprefix('public key: '))
            token = root / f'token{i}'
            tokens.append(token)
            log = (root / f'log{i}').open('w+')
            logs.append(log)
            settings = {
                'private_key_file': str(key_file),
                'listen': f'127.0.0.1:{udp[i]}',
                'dual_stack': False,
                'workers': 1,
                'api_listen': f'127.0.0.1:{apis[i]}',
                'api_token_file': str(token),
                'addresses': [f'10.152.0.{i+1}/32'],
            }
            if i == 1:
                settings['peer_http_listen'] = '10.152.0.2:8080'
                settings['files'] = {'root': str(share), 'allowed_downloaders': ['10.152.0.1']}
            config = root / f'config{i}.json'
            config.write_text(json.dumps(settings))
            command = [str(BIN / 'portal-runtime')]
            processes.append(subprocess.Popen(command, stdout=log, stderr=log, env={**os.environ, 'PORTAL_CONFIG': str(config)}))
        def command(i, body):
            request = urllib.request.Request(f'http://127.0.0.1:{apis[i]}/api/v1/command', data=json.dumps(body).encode(), headers={'Content-Type': 'application/json', 'Authorization': 'Bearer ' + tokens[i].read_text().strip()})
            with urllib.request.urlopen(request, timeout=10) as response:
                return json.load(response)
        deadline = time.monotonic() + 10
        for i in range(2):
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
        for i in range(2):
            command(i, {'operation': 'peer_upsert', 'public_key': keys[1-i], 'endpoint': f'127.0.0.1:{udp[1-i]}', 'allowed_ips': [f'10.152.0.{2-i}/32']})
        options = ['--peer', keys[1], '--api', f'http://127.0.0.1:{apis[0]}', '--api-token-file', str(tokens[0])]
        listing = subprocess.check_output([str(BIN / 'portal-files'), 'ls', *options], text=True, timeout=20)
        assert 'data.bin' in listing, listing
        output = root / 'download.bin'
        subprocess.run([str(BIN / 'portal-files'), 'download', *options, '--path', 'data.bin', '--output', str(output)], check=True, timeout=20)
        assert output.read_bytes() == payload
        for i in range(2):
            command(i, {'operation': 'shutdown'})
            assert processes[i].wait(timeout=8) == 0
            assert not tokens[i].exists()
            logs[i].seek(0)
            assert 'net=userspace' in logs[i].read()
        print('PASS: two runtimes, peer registration, browsing, 307200-byte download, clean shutdown')
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
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
        for log in logs:
            log.close()
