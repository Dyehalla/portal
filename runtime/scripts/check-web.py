#!/usr/bin/env python3
"""Browser integration check against a controlled local API (no TUN or VPN).

Run: python3 runtime/scripts/check-web.py
Requires Firefox; uses its built-in Marionette protocol, no Python dependencies.
"""
import base64
import copy
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / 'runtime/web'
TOKEN = 'a' * 64  # Test-only credential; never reads the runtime token.
DATA = {
    'mode': 'managed', 'healthy': True,
    'interface': {'name': 'portal0', 'listen': '0.0.0.0:51820', 'public_key': 'b' * 64, 'addresses': ['10.20.0.1/32', 'fd00::1/128']},
    'network': {'device_id': 'local', 'device_name': 'Ноутбук', 'network_id': 'network', 'revision': 7, 'user_id': 'owner', 'user_name': 'Анна', 'policy_revision': 3, 'policy_pending': False, 'coordinator_connected': True, 'lease_active': True, 'lease_remaining_seconds': 600},
    'peers': [
        {'public_key': 'c' * 64, 'device_id': 'server', 'owned': True, 'name': 'Сервер <img src=x onerror=alert(1)>', 'endpoint': '192.0.2.1:51820', 'path': 'offline', 'allowed_ips': ['10.20.0.2/32'], 'keepalive_seconds': 25, 'incoming_tcp': [22], 'outgoing_tcp': [443], 'traffic': {'tx_bytes': 2048, 'rx_bytes': 1024, 'tx_packets': 2, 'rx_packets': 1}},
        {'public_key': 'd' * 64, 'device_id': 'incoming', 'owned': False, 'name': 'Только входящие', 'endpoint': None, 'path': 'probing', 'allowed_ips': ['10.20.0.3/32'], 'keepalive_seconds': None, 'incoming_tcp': [22], 'outgoing_tcp': [], 'traffic': None},
    ],
    'stats': {'received_udp_packets': 123, 'received_tun_packets': 42, 'dropped_packets': 3, 'udp_send_errors': 2, 'timer_send_errors': 1},
}
EMPTY_ACCOUNT = {'configured': False, 'address': None, 'user': None, 'devices': [], 'needs_device': False, 'device_name': ''}
state = {'account': copy.deepcopy(EMPTY_ACCOUNT), 'policy': {'revision': 0, 'applied_revision': 0, 'permissions': {}}, 'data': copy.deepcopy(DATA), 'http': 200, 'command_http': 200, 'delay': 0.3, 'commands': [], 'bulk_policies': {}, 'bulk_writes': [], 'policy_reads': 0}
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(WEB), **kwargs)

    def log_message(self, *_):
        pass

    def end_headers(self):
        self.send_header('Content-Security-Policy', CSP)
        self.send_header('Cache-Control', 'no-store')
        super().end_headers()

    def reply(self, code, data):
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        try:
            self.wfile.write(raw)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def authorized(self):
        return self.headers.get('Authorization') == 'Bearer ' + TOKEN

    def do_GET(self):
        if self.path.startswith('/api/'):
            if self.path == '/api/v1/account':
                if not self.authorized():
                    return self.reply(401, {'message': 'invalid token'})
                return self.reply(200, state['account'])
            assert self.path == '/api/v1/snapshot', self.path
            if not self.authorized():
                return self.reply(401, {'message': 'invalid token'})
            return self.reply(state['http'], state['data'] if state['http'] == 200 else {'message': 'test agent unavailable'})
        return super().do_GET()

    def do_POST(self):
        if not self.authorized():
            return self.reply(401, {'message': 'invalid token'})
        if self.path.startswith('/api/v1/account'):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path == '/api/v1/account':
                assert body.get('user_name') == 'Анна' and body['address'] == 'vpn.example.test:9443', body
                state['account'] = {'configured': True, 'address': 'https://vpn.example.test:9443', 'user': {'id': 'owner', 'name': 'Анна'}, 'devices': [], 'needs_device': True, 'device_name': 'device-auto'}
                return self.reply(200, state['account'])
            if self.path == '/api/v1/account/activate':
                assert body['name'] == 'Мой ноутбук'
                state['data'] = copy.deepcopy(DATA)
                state['account']['needs_device'] = False
                state['account']['devices'] = [
                    {'id':'local', 'owner_user_id':'owner', 'name':'Мой ноутбук', 'public_key':'b'*64, 'ipv4':'10.20.0.1', 'ipv6':'fd00::1'},
                    {'id':'isolated', 'owner_user_id':'owner', 'name':'Без разрешений', 'public_key':'e'*64, 'ipv4':'10.20.0.4', 'ipv6':'fd00::4'}]
                return self.reply(200, {'message': 'connected'})
            if self.path == '/api/v1/account/device':
                if body['operation'] == 'request_access':
                    assert body['source_device_id'] == 'local' and body['target_device_id'] == 'foreign-isolated'
                    assert body['tcp'] == [22, 443]
                    state['requested_access'] = body
                    return self.reply(200, {'status':'pending'})
                if body['operation'] == 'decide_access':
                    state['access_decisions'].append(body)
                    item = next(r for r in state['account']['access_requests'] if r['id'] == body['request_id'])
                    item['status'] = 'accepted' if body['accept'] else 'declined'
                    return self.reply(200, item)
                if body['operation'] == 'policy':
                    state['policy_reads'] += 1
                if state['bulk_policies']:
                    device_id = body['device_id']
                    if device_id == 'local' and body['operation'] == 'policy':
                        return self.reply(200, {'revision': 0, 'applied_revision': 0, 'permissions': {}})
                    assert device_id != 'local', 'source device must be excluded'
                    policy = state['bulk_policies'].get(device_id, {'revision': 0, 'applied_revision': 0, 'permissions': {}})
                    if body['operation'] == 'policy':
                        return self.reply(200, policy)
                    assert body['operation'] == 'save_policy'
                    state['bulk_writes'].append(body)
                    if body['base_revision'] != policy['revision']:
                        return self.reply(409, {'message': 'Конфликт изменений'})
                    policy['revision'] += 1
                    policy['permissions'] = body['permissions']
                    return self.reply(200, policy)
                if body['operation'] == 'policy' and body['device_id'] != 'isolated':
                    return self.reply(200, {'revision': 0, 'applied_revision': 0, 'permissions': {}})
                assert body['device_id'] == 'isolated' 
                if body['operation'] == 'policy':
                    return self.reply(200, state['policy'])
                assert body['operation'] == 'save_policy'
                if body['base_revision'] != state['policy']['revision']:
                    return self.reply(409, {'message':'Конфликт изменений. Поля сохранены.'})
                state['policy']['revision'] += 1
                state['policy']['permissions'] = body['permissions']
                return self.reply(200, state['policy'])
            raise AssertionError(self.path)
        assert self.path == '/api/v1/command'
        if not self.authorized():
            return self.reply(401, {'message': 'invalid token'})
        body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        assert body == {'operation': 'connect', 'peer_device_id': 'server'}, body
        state['commands'].append(body)
        time.sleep(state['delay'])
        if state['command_http'] == 200:
            state['data']['peers'][0]['path'] = 'direct'
        self.reply(state['command_http'], {'message': 'verified direct path' if state['command_http'] == 200 else 'P2P direct path timed out; background retries continue'})


class Browser:
    def __init__(self, sock):
        self.sock, self.seq = sock, 0
        self.receive()
        self.call('WebDriver:NewSession', {'capabilities': {'alwaysMatch': {}}})

    def receive(self):
        size = b''
        while (ch := self.sock.recv(1)) != b':':
            if not ch:
                raise RuntimeError('Firefox connection closed')
            size += ch
        data = b''
        while len(data) < int(size):
            data += self.sock.recv(int(size) - len(data))
        return json.loads(data)

    def call(self, name, args=None):
        self.seq += 1
        raw = json.dumps([0, self.seq, name, args or {}]).encode()
        self.sock.sendall(str(len(raw)).encode() + b':' + raw)
        result = self.receive()
        if result[2]:
            raise RuntimeError(result[2])
        return result[3]

    def js(self, script):
        return self.call('WebDriver:ExecuteScript', {'script': script, 'args': [], 'newSandbox': False, 'sandbox': 'default'})['value']

    def wait(self, expression, label):
        deadline = time.monotonic() + 8
        while not self.js('return ' + expression):
            if time.monotonic() > deadline:
                raise AssertionError(label)
            time.sleep(.05)
        print('PASS:', label, flush=True)


def run(browser, base):
    browser.call('WebDriver:Navigate', {'url': base})
    browser.wait("!document.getElementById('auth-view').hidden && document.getElementById('app').hidden", 'authentication required')
    browser.js("document.getElementById('token').value='f'.repeat(64);document.getElementById('auth-form').requestSubmit()")
    browser.wait("!document.getElementById('auth-error').hidden && !document.getElementById('sign-in').disabled", 'invalid token rejected')
    browser.call('WebDriver:Navigate', {'url': base + '/#token=' + TOKEN})
    browser.wait("!document.getElementById('app').hidden && location.hash === ''", 'token link login and fragment removal')
    browser.wait("document.getElementById('connection-status').textContent.includes('не подтверждён') && !document.getElementById('connect').disabled", 'endpoint does not imply a direct connection')
    browser.wait("document.getElementById('device-count').textContent === '3' && !document.querySelector('#app img')", 'merged page counts current device and peers without duplicates and escapes names')
    browser.js("location.hash='map'")
    browser.wait("document.getElementById('current-device').textContent.includes('Это устройство') && document.getElementById('device-list').textContent.includes('Чужое') && document.querySelectorAll('#map-list .x6-edge').length === 3 && !document.querySelector('#map-list .x6-edge-label')", 'ownership, local identity and arrows without port labels')
    Path('/tmp/portal-integrated-map.png').write_bytes(base64.b64decode(browser.call('WebDriver:TakeScreenshot', {'full': True})['value']))
    browser.js("location.hash='devices';document.querySelector('#device-list [data-device=\"'+'c'.repeat(64)+'\"]').click()")
    browser.wait("!document.querySelector('#devices .connection-card') && document.getElementById('details-dialog').contains(document.getElementById('connection-card')) && document.getElementById('details-dialog').open && document.getElementById('peer-detail-list').textContent.includes('443') && document.getElementById('peer-detail-list').textContent.includes('25 с')", 'real permissions, traffic and keepalive')
    browser.js("document.getElementById('close-details').click();document.getElementById('connect').click()")
    browser.wait("document.getElementById('connect').disabled", 'pending request disables duplicate submission')
    browser.wait("document.getElementById('connection-status').textContent.includes('Прямой') && !document.getElementById('connect').disabled", 'verified command refreshes runtime state')
    assert len(state['commands']) == 1
    browser.js("location.hash='devices';const q=document.getElementById('peer-search');q.value='10.20.0.3';q.dispatchEvent(new Event('input'))")
    browser.wait("!document.getElementById('devices').hidden && document.querySelectorAll('#device-list .device-row').length === 1", 'device search')
    browser.js("document.querySelector('#device-list .device-row').click()")
    browser.wait("document.getElementById('connect').hidden && document.getElementById('connection-caption').textContent.includes('входящие')", 'incoming-only peer cannot initiate P2P')
    browser.js("const q=document.getElementById('peer-search');q.value='';q.dispatchEvent(new Event('input'));document.querySelector('#device-list [data-device=\"'+'c'.repeat(64)+'\"]').click()")
    state['data']['network']['lease_remaining_seconds'] = 1
    browser.js("document.getElementById('refresh').click()")
    browser.wait("!document.getElementById('lease-warning').hidden && document.getElementById('connect').disabled && !document.getElementById('connection-card').classList.contains('connected')", 'lease expires between polls and blocks connecting')
    state['data'] = copy.deepcopy(DATA)
    state['http'] = 503
    browser.js("document.getElementById('refresh').click()")
    browser.wait("!document.getElementById('connection-error').hidden && document.getElementById('connect').disabled", 'stale snapshot cannot claim a current connection')
    state['http'] = 200
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connection-error').hidden && !document.getElementById('connect').disabled", 'agent recovery')
    state['data']['healthy'] = False
    browser.js("document.getElementById('refresh').click()")
    browser.wait("!document.getElementById('connection-error').hidden && document.getElementById('connect').disabled", 'unhealthy agent blocks P2P')
    state['data']['healthy'] = True
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connection-error').hidden && !document.getElementById('connect').disabled", 'healthy agent restored')
    state['command_http'] = 400
    browser.js("document.getElementById('connect').click()")
    browser.wait("document.getElementById('connection-caption').textContent.includes('timed out') && !document.getElementById('connect').disabled", 'P2P failure offers retry without synthetic success')
    state['data']['network']['coordinator_connected'] = False
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('lease-warning').textContent.includes('Координатор недоступен')", 'coordinator warning')
    state['data'] = copy.deepcopy(DATA)
    state['data']['mode'], state['data']['network'] = 'manual', None
    for peer in state['data']['peers']:
        peer['incoming_tcp'] = peer['outgoing_tcp'] = None
        peer['device_id'] = peer['name'] = None
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connect').hidden && document.getElementById('workspace-mode').textContent.includes('Ручной')", 'manual WireGuard has no P2P action')
    state['data']['peers'] = []
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connection-card').hidden && document.getElementById('device-count').textContent === '1' && document.getElementById('current-device').textContent.includes('Это устройство')", 'current device remains visible when there are no remote peers')
    state['data'] = copy.deepcopy(DATA)
    state['data']['peers'][0]['name'] = 'Очень длинное название устройства ' * 6
    browser.js("document.getElementById('refresh').click()")
    browser.wait("!document.getElementById('connection-card').hidden", 'peers restored')
    for width in [360, 390, 768, 1024, 1440]:
        browser.call('WebDriver:SetWindowRect', {'width': width, 'height': 1000})
        for page in ['devices', 'map', 'network', 'diagnostics']:
            browser.js(f"location.hash='{page}'")
            browser.wait(f"!document.getElementById('{page}').hidden && document.documentElement.scrollWidth <= window.innerWidth", f'no overflow: {page} at {width}px')
    browser.js("location.hash='overview'")
    browser.wait("location.hash === '#devices' && !document.getElementById('devices').hidden && document.querySelectorAll('[data-page]').length === 4 && !document.getElementById('overview') && !document.getElementById('quick-grid')", 'legacy overview link opens the single devices page without duplicate navigation or list')
    state['data']['peers'][0]['name'] = 'Домашний сервер'
    state['data']['peers'][0]['path'] = 'direct'
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connection-status').textContent.includes('Прямой')", 'snapshot reports background connection independently of the command')
    Path('/tmp/portal-live-redesign.png').write_bytes(base64.b64decode(browser.call('WebDriver:TakeScreenshot', {'full': True})['value']))
    browser.call('WebDriver:Refresh')
    browser.wait("!document.getElementById('app').hidden", 'session restored after reload')
    state['data']['peers'] = []
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connection-card').hidden", 'selected peer removed from latest map')
    state['data'] = copy.deepcopy(DATA)
    state['data']['peers'][0]['outgoing_tcp'] = []
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('connect').hidden", 'revoked outgoing access')
    state['http'] = 401
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('app').hidden && !sessionStorage.getItem('portal.local-api-token')", '401 clears session')
    state['http'], state['command_http'], state['delay'] = 200, 200, 1
    state['data'] = copy.deepcopy(DATA)
    browser.call('WebDriver:Navigate', {'url': base + '/#token=' + TOKEN})
    browser.wait("!document.getElementById('app').hidden", 'new login')
    browser.js("document.getElementById('connect').click();document.getElementById('sign-out').click()")
    time.sleep(1.3)
    browser.wait("document.getElementById('app').hidden && document.getElementById('toast').hidden && !sessionStorage.getItem('portal.local-api-token')", 'logout ignores pending command result')


def run_account(browser, base):
    state['data'] = copy.deepcopy(DATA)
    state['data'].update(mode='manual', network=None, peers=[], setup_available=True)
    browser.call('WebDriver:Navigate', {'url': base + '/#token=' + TOKEN})
    browser.wait("!document.getElementById('network').hidden", 'first launch opens network connection')
    browser.js("document.getElementById('coordinator').value='vpn.example.test:9443';document.getElementById('register-mode').click()")
    browser.wait("document.getElementById('coordinator').value === 'vpn.example.test:9443' && !document.getElementById('user-name-label').hidden && document.getElementById('user-token-label').hidden", 'registration keeps address and requests user name')
    browser.js("document.getElementById('user-name').value='Анна';document.getElementById('network-form').requestSubmit()")
    browser.wait("!document.getElementById('add-device-form').hidden && document.getElementById('device-name').value === 'device-auto' && document.getElementById('device-public-key').readOnly", 'agent supplies editable device name and read-only public key')
    browser.js("document.getElementById('device-name').value='Мой ноутбук';document.getElementById('add-device-form').requestSubmit()")
    browser.wait("!document.getElementById('devices').hidden", 'device added and network applied')
    # Reproduce a new account with only its current registered device.
    remote_peers = state['data']['peers']
    own_devices = state['account']['devices']
    state['data']['peers'] = []
    state['account']['devices'] = own_devices[:1]
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('device-count').textContent === '1' && document.querySelector('.nav-count').textContent === '1' && document.getElementById('current-device').textContent.includes('Мой ноутбук') && document.getElementById('current-device').textContent.includes('Это устройство') && !document.getElementById('connection-title').textContent.includes('Здесь будут')", 'first registered device appears on merged page and both counters')
    browser.wait("document.getElementById('connect').hidden && !document.getElementById('connection-card').classList.contains('connected')", 'current device does not imply a P2P connection to itself')
    browser.js("document.querySelector('#current-device button').click()")
    browser.wait("document.getElementById('details-dialog').open && !document.getElementById('owner-actions').hidden", 'current device opens management from the merged page')
    browser.js("document.getElementById('close-details').click()")
    state['data']['peers'] = remote_peers
    state['account']['devices'] = own_devices
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('device-list').textContent.includes('Без разрешений') && document.getElementById('map-list').textContent.replaceAll('\u00a0', ' ').includes('Без разрешений')", 'own isolated devices stay visible in registry and map')
    browser.wait("document.getElementById('device-count').textContent === '4' && document.getElementById('device-list').textContent.includes('Без разрешений') && document.querySelectorAll('#device-list [data-device=\"'+'b'.repeat(64)+'\"]').length === 0", 'own isolated device appears on merged page and current device is deduplicated')
    browser.js("location.hash='devices';document.querySelector('#device-list [data-device=\"'+'e'.repeat(64)+'\"]').click()")
    browser.wait("document.getElementById('details-dialog').open && !document.getElementById('owner-actions').hidden", 'own device offers management without network access')
    browser.js("document.getElementById('edit-permissions').click()")
    browser.wait("document.getElementById('policy-dialog').open && document.getElementById('policy-status').textContent.includes('Применено')", 'policy editor loads confirmed revision')
    browser.js("window.policyButtonChanges=[];window.policyButtonObserver=new MutationObserver(records => window.policyButtonChanges.push(...records.map(record=>record.target.id)));for(const id of ['save-policy','reload-policy']) window.policyButtonObserver.observe(document.getElementById(id),{attributes:true,attributeFilter:['disabled']})")
    reads = state['policy_reads']
    time.sleep(6)
    assert state['policy_reads'] > reads, 'coordinator policies must still refresh in the background'
    browser.wait("window.policyButtonChanges.length === 0 && !document.getElementById('save-policy').disabled && !document.getElementById('reload-policy').disabled", 'background policy refresh keeps editor buttons stable')
    browser.js("window.policyButtonObserver.disconnect()")
    browser.js("document.getElementById('add-rule').click()")
    browser.wait("!document.getElementById('policy-form').checkValidity()", 'source must be selected before saving')
    browser.wait("document.querySelector('.rule-source').tagName === 'SELECT' && !document.querySelector('.rule-source option[value=\"'+'e'.repeat(64)+'\"]') && document.querySelectorAll('.rule-source option[value=\"'+'b'.repeat(64)+'\"]').length === 1 && document.querySelector('.rule-source').textContent.includes('Мой ноутбук') && document.querySelector('.rule-source').textContent.includes('Только входящие')", 'source picker shows named devices, deduplicates current device and excludes target')
    browser.js("document.querySelector('.rule-source').value='b'.repeat(64);document.querySelector('.rule-source').dispatchEvent(new Event('change'));document.querySelector('.service-checkbox[value=\"22\"]').click();document.querySelector('.service-checkbox[value=\"443\"]').click();document.querySelector('.rule-ports').value='8080, 8080';document.querySelector('.rule-ports').dispatchEvent(new Event('input'))")
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.querySelector('.rule-ports').value === '8080, 8080' && document.getElementById('policy-status').textContent.includes('несохранённые')", 'background refresh preserves unsaved editor')
    state['policy']['revision'] = 1
    browser.js("document.getElementById('policy-form').requestSubmit()")
    browser.wait("document.getElementById('policy-error').textContent.includes('Конфликт') && document.querySelector('.rule-ports').value === '8080, 8080'", 'revision conflict preserves draft')
    state['policy']['revision'] = 0
    browser.js("document.getElementById('policy-form').requestSubmit()")
    browser.wait("document.getElementById('policy-status').textContent.includes('ожидает устройства')", 'saved policy is pending until device acknowledgement')
    browser.wait("!!document.querySelector('#map-list .x6-edge path[stroke-dasharray=\"5 4\"]')", 'unacknowledged permission has a dashed arrow')
    assert state['policy']['permissions'] == {'b'*64: {'tcp': [22, 443, 8080]}}, 'checkboxes and custom ports are merged, sorted and deduplicated'
    state['policy']['applied_revision'] = 1
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('policy-status').textContent.includes('Применено')", 'device acknowledgement confirms exact revision')
    browser.wait("!document.querySelector('#map-list .x6-edge path[stroke-dasharray=\"5 4\"]')", 'acknowledged permission has a solid arrow')
    browser.call('WebDriver:SetWindowRect', {'width':360,'height':1000})
    browser.wait("document.documentElement.scrollWidth <= window.innerWidth", 'policy editor fits narrow viewport')
    browser.wait("getComputedStyle(document.querySelector('.service-option')).display === 'flex'", 'service checkboxes align with their labels on mobile')
    Path('/tmp/portal-permission-services.png').write_bytes(base64.b64decode(browser.call('WebDriver:TakeScreenshot', {'full': True})['value']))
    browser.wait("!document.getElementById('token-reminder') && !document.getElementById('app').textContent.includes('Сохраните токен входа') && !!document.getElementById('save-user-token')", 'token reminder removed while export remains available')
    browser.js("document.getElementById('close-policy').click();document.getElementById('close-details').click();location.hash='map'")
    browser.wait("document.querySelector('#map-list [data-device=\"'+'b'.repeat(64)+'\"]').textContent.replaceAll('\u00a0', ' ').includes('Это устройство')", 'map keeps current isolated node')
    browser.js("document.querySelector('#map-list [data-device=\"'+'e'.repeat(64)+'\"]').dispatchEvent(new KeyboardEvent('keydown', {key:'Enter', bubbles:true}))")
    browser.wait("document.getElementById('details-dialog').open && document.getElementById('peer-detail-list').textContent.includes('Применено')", 'map opens device details and known policy state')
    browser.js("document.getElementById('edit-permissions').click()")
    browser.wait("document.querySelector('.rule-source') !== null", 'saved rule restored for bulk preview')
    browser.wait("document.querySelector('.service-checkbox[value=\"22\"]').checked && document.querySelector('.service-checkbox[value=\"443\"]').checked && document.querySelector('.rule-ports').value === '8080'", 'saved services restore as checkboxes and extra ports remain editable')
    browser.js("document.querySelector('.service-checkbox[value=\"22\"]').click()")
    state['account']['devices'].append({'id': 'other', 'owner_user_id': 'owner', 'name': 'Другой сервер', 'public_key': 'f'*64, 'ipv4': '10.20.0.5', 'ipv6': 'fd00::5'})
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('device-list').textContent.includes('Другой сервер')", 'new own target loaded')
    state['bulk_policies'] = {
        'isolated': copy.deepcopy(state['policy']),
        'other': {'revision': 4, 'applied_revision': 4, 'permissions': {'d'*64: {'tcp': [22]}}}}
    browser.js("document.querySelector('.rule-ports').value='0, 65536';document.querySelector('.policy-rule button:last-child').click()")
    browser.wait("!document.getElementById('bulk-dialog').open && document.getElementById('policy-error').textContent.includes('65535')", 'invalid ports cannot start bulk operation')
    browser.js("document.querySelector('.rule-ports').value='443, 8443';document.querySelector('.rule-ports').dispatchEvent(new Event('input'));document.querySelector('.policy-rule button:last-child').click()")
    browser.wait("document.getElementById('bulk-dialog').open && !document.getElementById('confirm-bulk').disabled", 'bulk requires explicit preview and confirmation')
    assert not state['bulk_writes'], 'preview must not save'
    browser.wait("document.querySelectorAll('#bulk-results .bulk-result').length === 2 && !document.getElementById('bulk-results').textContent.includes('Мой ноутбук')", 'bulk lists all own targets except source')
    browser.wait("document.documentElement.scrollWidth <= window.innerWidth", 'bulk preview fits narrow viewport')
    # A concurrent writer changes one target after preview.
    state['bulk_policies']['isolated']['revision'] += 1
    browser.js("document.getElementById('confirm-bulk').click();document.getElementById('confirm-bulk').click()")
    browser.wait("document.getElementById('bulk-results').textContent.includes('Конфликт') && document.getElementById('bulk-results').textContent.includes('ожидает устройства')", 'bulk reports partial conflict and pending success independently')
    assert len(state['bulk_writes']) == 2, state['bulk_writes']
    assert state['bulk_policies']['other']['permissions'] == {'d'*64: {'tcp': [22]}, 'b'*64: {'tcp': [443, 8443]}}, 'bulk must preserve other sources'
    browser.wait("document.querySelector('.rule-ports').value === '443, 8443' && document.getElementById('policy-status').textContent.includes('несохранённые')", 'bulk does not overwrite editor draft')
    state['bulk_policies']['other']['applied_revision'] = 5
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('bulk-results').textContent.includes('Применено')", 'bulk waits for exact device acknowledgement')
    state['account']['devices'].append({'id': 'late', 'owner_user_id': 'owner', 'name': 'Добавлен позже', 'public_key': '9'*64, 'ipv4': '10.20.0.6', 'ipv6': 'fd00::6'})
    browser.wait("document.getElementById('device-list').textContent.includes('Добавлен позже') && !document.getElementById('bulk-results').textContent.includes('Добавлен позже')", 'future devices do not inherit bulk permission')
    assert len(state['bulk_writes']) == 2, 'refresh must not repeat bulk mutations'
    browser.wait("!!document.querySelector('#map-list [data-device=\"'+'9'.repeat(64)+'\"]')", 'coordinator registry updates graph without reloading')
    Path('/tmp/portal-bulk-permissions.png').write_bytes(base64.b64decode(browser.call('WebDriver:TakeScreenshot', {'full': True})['value']))
    browser.js("document.getElementById('sign-out').click()")
    browser.wait("!document.getElementById('auth-view').hidden && !document.querySelector('#policy-rules input') && !document.getElementById('bulk-dialog').open && !document.getElementById('bulk-results').textContent", 'logout clears account editor and bulk results')


def run_shared_registry(browser):
    browser.js("document.getElementById('token').value='a'.repeat(64);document.getElementById('auth-form').requestSubmit()")
    browser.wait("!document.getElementById('app').hidden", 'login for shared registry')
    browser.js("for(const dialog of document.querySelectorAll('dialog[open]')) dialog.close()")
    foreign = {'id':'foreign-isolated','owner_user_id':'colleague','name':'Сервер коллеги','public_key':'8'*64,'ipv4':'10.20.0.9','ipv6':'fd00::9'}
    state['account']['devices'].append(foreign)
    state['access_decisions'] = []
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.getElementById('device-list').textContent.includes('Сервер коллеги') && document.getElementById('map-list').textContent.replaceAll('\u00a0', ' ').includes('Сервер коллеги')", 'foreign device is visible without traffic permission')
    browser.js("document.querySelector('#device-list [data-device=\"'+'8'.repeat(64)+'\"]').click()")
    browser.wait("document.getElementById('details-dialog').open && document.getElementById('owner-actions').hidden && !document.getElementById('request-access-form').hidden && document.getElementById('connect').hidden", 'foreign device offers access request and never owner actions')
    browser.js("document.getElementById('request-ports').value='22, 443';document.getElementById('request-access-form').requestSubmit()")
    browser.wait("!document.getElementById('request-access-submit').disabled", 'request submitted')
    assert state['requested_access']['tcp'] == [22,443]
    browser.js("document.getElementById('close-details').click()")
    current = state['account']['devices'][0]
    state['account']['access_requests'] = [dict(id='req-'+str(i),source=foreign,target=current,requester_name='Коллега',tcp=[22],status='pending',created_at=int(time.time()),expires_at=int(time.time())+86400,policy_revision=None) for i in range(2)]
    browser.js("document.getElementById('refresh').click()")
    browser.wait("document.querySelectorAll('#access-request-list button').length === 4 && !document.getElementById('access-notifications').hidden", 'incoming notifications offer accept and decline')
    browser.js("document.querySelector('#access-request-list article button').click()")
    browser.wait("document.querySelectorAll('#access-request-list button').length === 2", 'accepted request is updated')
    browser.js("document.querySelectorAll('#access-request-list button')[1].click()")
    browser.wait("document.querySelectorAll('#access-request-list button').length === 0 && document.getElementById('access-request-list').textContent.includes('отклонил')", 'declined request is updated')
    assert [r['accept'] for r in state['access_decisions']] == [True,False]
    print('PASS: common registry shows foreign devices without access; browser sends access request and receives actionable notifications')


def main():
    firefox = os.environ.get('FIREFOX') or shutil.which('firefox')
    if not firefox:
        raise SystemExit('Firefox is required (or set FIREFOX to its executable).')
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with tempfile.TemporaryDirectory(prefix='portal-web-check-') as profile, tempfile.TemporaryFile() as log:
        with socket.socket() as probe:
            probe.bind(('127.0.0.1', 0))
            port = probe.getsockname()[1]
        Path(profile, 'user.js').write_text(f'user_pref("marionette.port", {port});\n')
        process = subprocess.Popen([firefox, '--headless', '--no-remote', '--marionette', '--profile', profile, 'about:blank'], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 15
            while True:
                try:
                    sock = socket.create_connection(('127.0.0.1', port), timeout=10)
                    break
                except ConnectionRefusedError:
                    if process.poll() is not None or time.monotonic() > deadline:
                        log.seek(0)
                        raise RuntimeError(log.read().decode())
                    time.sleep(.1)
            with sock:
                browser = Browser(sock)
                run(browser, f'http://127.0.0.1:{server.server_port}')
                run_account(browser, f'http://127.0.0.1:{server.server_port}')
                run_shared_registry(browser)
                browser.call('WebDriver:DeleteSession')
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            server.shutdown()
    print('PASS: browser integration checks completed; no real VPN changes')


if __name__ == '__main__':
    main()
