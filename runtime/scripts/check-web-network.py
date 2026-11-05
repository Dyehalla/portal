#!/usr/bin/env python3
"""Exercise web onboarding and restart with real HTTPS/TUN in isolated namespaces.

Build: cargo build -p portal-cli -p portal-coordinator
Run: unshare --user --map-root-user --net --mount python3 runtime/scripts/check-web-network.py
"""
import json
import os
from pathlib import Path
import subprocess
import ssl
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
assert os.geteuid() == 0 and Path('/proc/self/uid_map').read_text().split()[2] == '1', 'requires an isolated user, mount and network namespace'
subprocess.run(['mount', '--make-rprivate', '/'], check=True)
for directory in ['/etc', '/run']:
    subprocess.run(['mount', '-t', 'tmpfs', '-o', 'mode=755', 'tmpfs', directory], check=True)
Path('/etc/resolv.conf').write_text('nameserver 127.0.0.1\n')
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
processes = []


def wait(check, label):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                print('PASS:', label, flush=True)
                return result
        except (OSError, ValueError, urllib.error.URLError):
            pass
        time.sleep(.1)
    raise AssertionError(label)


def stop(process):
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def api(path, body=None):
    token = Path('/run/portal.token').read_text().strip()
    request = urllib.request.Request('http://127.0.0.1:51821/api/v1/' + path,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
    try:
        with opener.open(request, timeout=40) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise AssertionError(f'API HTTP {error.code}: {json.load(error).get("message")}') from None


with tempfile.TemporaryDirectory(prefix='portal-web-network-') as directory:
    state = Path(directory)
    os.chmod(state, 0o700)
    subprocess.run(['openssl', 'req', '-config', '/dev/null', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                    '-keyout', str(state / 'tls.key'), '-out', str(state / 'ca.pem'), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-addext', 'basicConstraints=critical,CA:FALSE'],
                   check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    config = {'listen': '127.0.0.1:8443', 'state_dir': str(state / 'server'),
              'tls': {'cert_file': str(state / 'ca.pem'), 'key_file': str(state / 'tls.key')}}
    (state / 'server.json').write_text(json.dumps(config))
    try:
        with (state / 'server.log').open('wb') as server_log, (state / 'agent.log').open('ab') as agent_log:
            server = subprocess.Popen([str(ROOT / 'target/debug/portal-coordinator'), '--config', str(state / 'server.json')], stdout=server_log, stderr=server_log)
            processes.append(server)
            wait(lambda: (state / 'server/admin.token').exists(), 'HTTPS coordinator started in isolated namespace')
            agent = subprocess.Popen([str(ROOT / 'target/debug/portal'), 'start'], stdout=agent_log, stderr=agent_log)
            processes.append(agent)
            wait(lambda: api('snapshot')['setup_available'], 'unenrolled client serves panel with traffic closed')
            key = api('snapshot')['interface']['public_key']
            account = api('account', {'address': '127.0.0.1:8443', 'user_name': 'web-owner', 'ca_pem': (state / 'ca.pem').read_text()})
            assert account['user']['name'] == 'web-owner' and account['needs_device']
            api('account/activate', {'name': 'web-laptop'})
            snapshot = wait(lambda: (value if (value := api('snapshot'))['mode'] == 'managed' else None), 'web enrollment applies real TUN configuration without restart')
            assert snapshot['interface']['public_key'] == key and snapshot['network']['lease_active']
            assert len(snapshot['interface']['addresses']) == 2
            account = api('account')
            assert len(account['devices']) == 1 and not account['needs_device']
            user_token = api('account/token', {})['message']
            assert user_token.startswith('usr_') and user_token not in json.dumps(snapshot)
            device_id = account['devices'][0]['id']
            stop(agent)
            agent = subprocess.Popen([str(ROOT / 'target/debug/portal'), 'start'], stdout=agent_log, stderr=agent_log)
            processes.append(agent)
            wait(lambda: api('snapshot')['mode'] == 'managed', 'saved profile restores VPN before browser login')
            assert api('snapshot')['interface']['public_key'] == key
            account = api('account', {'address': '127.0.0.1:8443', 'token': user_token})
            assert len(account['devices']) == 1 and account['devices'][0]['id'] == device_id
            print('PASS: repeated login preserves key, device ID and credentials', flush=True)
            policy = api('account/device', {'operation': 'policy', 'device_id': device_id})
            saved = api('account/device', {'operation': 'save_policy', 'device_id': device_id,
                                           'base_revision': policy['revision'], 'permissions': {}})
            wait(lambda: api('account/device', {'operation': 'policy', 'device_id': device_id})['applied_revision'] == saved['revision'], 'running agent acknowledges desired policy revision')
            # A second user can discover this device and ask its owner for TCP access.
            remote = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(state / 'ca.pem'))))
            def coordinator(path, token=None, body=None):
                headers = {'Content-Type':'application/json'}
                if token: headers['Authorization'] = 'Bearer ' + token
                request = urllib.request.Request('https://127.0.0.1:8443/api/v1/' + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
                return json.load(remote.open(request, timeout=10))
            colleague = coordinator('users', body={'name':'colleague'})
            generated = subprocess.check_output([str(ROOT / 'target/debug/portal'), 'keygen', '--private-key-file', str(state / 'foreign.key')], text=True)
            foreign_key = generated.split('public key: ')[1].strip()
            foreign = coordinator('devices', colleague['access_token'], {'name':'foreign-device','public_key':foreign_key})
            common = api('account')['devices']
            assert len(common) == 2 and any(d['id'] == foreign['device']['id'] for d in common)
            assert api('snapshot')['peers'] == [], 'visibility must not grant access'
            body = {'source_device_id':foreign['device']['id'],'target_device_id':device_id,'tcp':[443]}
            pending = coordinator('access-requests', colleague['access_token'], body)
            inbox = api('account')['access_requests']
            assert any(r['id'] == pending['id'] and r['status'] == 'pending' for r in inbox)
            rejected = api('account/device', {'operation':'decide_access','request_id':pending['id'],'accept':False})
            assert rejected['status'] == 'declined' and api('snapshot')['peers'] == []
            pending = coordinator('access-requests', colleague['access_token'], body)
            accepted = api('account/device', {'operation':'decide_access','request_id':pending['id'],'accept':True})
            wait(lambda: api('account/device', {'operation':'policy','device_id':device_id})['applied_revision'] == accepted['policy_revision'], 'accepted access request reaches the real destination agent and is acknowledged')
            foreign_map = coordinator('network-map', foreign['access_token'])
            assert foreign_map['peers'][0]['outgoing']['tcp'] == [443]
            outgoing = api('account/device', {'operation':'request_access','source_device_id':device_id,'target_device_id':foreign['device']['id'],'tcp':[22]})
            assert any(r['id'] == outgoing['id'] for r in coordinator('access-requests', colleague['access_token']))
            print('PASS: common registry, incoming decline/accept and outgoing access requests through local API and real HTTPS', flush=True)
            api('account/device', {'operation': 'revoke', 'device_id': device_id})
            wait(lambda: not api('snapshot')['network']['lease_active'], 'revoked device closes traffic while local API remains available')
            assert api('account')['user']['name'] == 'web-owner'
            print('PASS: user account remains manageable after device revocation', flush=True)
    except BaseException:
        for path in state.glob('*.log'):
            # Do not print logs: startup output contains the local session link.
            print('Diagnostic log retained only during test:', path.name, flush=True)
        raise
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                stop(process)
