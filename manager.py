#!/usr/bin/env python3
"""One sing-box/Tailscale identity per proxy, on one VPS. No host VPN routes."""
import copy
import fcntl
import getpass
import grp
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

ETC = Path('/etc/tailscale-proxy')
DATA = Path('/var/lib/tailscale-proxy')
ENGINE = '/opt/tailscale-proxy/sing-box'
STATE = ETC / 'state.json'
BYPASS = '45.88.89.23/32'
DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query'
ADMIN = 'https://login.tailscale.com/admin/machines'
METHODS = ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305',
           '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
           '2022-blake3-chacha20-poly1305']


def run(args, *, check=True, timeout=30, **kwargs):
    return subprocess.run([str(x) for x in args], text=True, capture_output=True,
                          check=check, timeout=timeout, **kwargs)


def read_state():
    if not STATE.exists():
        return {'schema': 1, 'exits': []}
    value = json.loads(STATE.read_text())
    if value.get('schema') != 1 or not isinstance(value.get('exits'), list):
        raise ValueError('Unsupported registry schema. Installation was not changed.')
    return value


def atomic_json(path, value, mode=0o600, group=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix='.pending-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        if group is not None:
            os.chown(name, 0, group)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def slugify(label):
    slug = re.sub('[^a-z0-9]+', '-', label.lower()).strip('-')[:40].strip('-')
    if not slug:
        raise ValueError('Use at least one letter or number in the country label.')
    return slug


def valid_host(host):
    host = host.strip().strip('[]')
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not host or len(host) > 253 or any(not re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', p)
                                          for p in host.rstrip('.').split('.')):
        raise ValueError('Enter a hostname or IP address, without a URL or port.')
    return host


def doh_server(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.fragment):
        raise ValueError('DNS must be a full HTTPS DoH URL without login credentials or a fragment.')
    host = valid_host(parsed.hostname)
    return {'type': 'https', 'tag': 'exit-dns', 'server': host,
            'server_port': parsed.port or 443,
            'path': (parsed.path or '/dns-query') + (('?' + parsed.query) if parsed.query else ''),
            'tls': {'enabled': True, 'server_name': host},
            'domain_resolver': 'bootstrap', 'detour': 'proxy'}


def make_config(entry, state_root=DATA):
    """Direct is reachable only by the exact destination bypass rule.

    Infrastructure DNS bootstraps Tailscale and upstream hostnames. Client DNS
    (including native exit-node peer DNS) uses DoH THROUGH the selected proxy.
    """
    outbound = {'type': entry['type'], 'tag': 'proxy', 'server': entry['server'],
                'server_port': entry['port'], 'domain_resolver': 'bootstrap'}
    if entry['type'] == 'socks':
        outbound['version'] = '5'
    if entry['type'] in ('http', 'socks') and entry.get('username'):
        outbound['username'] = entry['username']
    if entry.get('password'):
        outbound['password'] = entry['password']
    if entry['type'] == 'shadowsocks':
        outbound['method'] = entry['method']
    if entry['type'] in ('socks', 'shadowsocks') and not entry['udp']:
        outbound['network'] = 'tcp'
    rules = [
        {'ip_cidr': [BYPASS], 'action': 'route', 'outbound': 'direct'},
        # Prevent tailnet connections to this node from reaching local VPS services.
        {'ip_is_private': True, 'action': 'reject'},
    ]
    if not entry['udp']:
        rules.append({'network': 'udp', 'action': 'reject'})
    rules.append({'network': 'icmp', 'action': 'reject'})
    node = Path(state_root) / 'nodes' / entry['slug']
    return {
        'log': {'level': 'info', 'timestamp': True, 'disabled': False},
        'endpoints': [{'type': 'tailscale', 'tag': 'tailscale',
                       'hostname': entry['hostname'],
                       'state_directory': str(node / 'tailscale'),
                       'taildrop_directory': str(node / 'taildrop'),
                       'ephemeral': False, 'accept_routes': False,
                       'advertise_exit_node': True, 'system_interface': False,
                       'listen_port': entry['ts_port'], 'domain_resolver': 'bootstrap'}],
        'inbounds': [{'type': 'mixed', 'tag': 'probe', 'listen': '127.0.0.1',
                      'listen_port': entry['probe_port'],
                      'users': [{'username': 'probe', 'password': entry['probe_secret']}]}],
        'services': [{'type': 'api', 'listen': '127.0.0.1',
                      'listen_port': entry['api_port'], 'secret': entry['api_secret'],
                      'dashboard': False}],
        'dns': {'servers': [{'type': 'local', 'tag': 'bootstrap'},
                            doh_server(entry['doh'])],
                'rules': [{'inbound': ['tailscale', 'probe'], 'server': 'exit-dns'}],
                'final': 'bootstrap'},
        'outbounds': [outbound, {'type': 'direct', 'tag': 'direct'}],
        'route': {'rules': rules, 'final': 'proxy',
                  'default_domain_resolver': 'exit-dns'},
    }


def unit(entry):
    return 'tailscale-proxy@' + entry['slug'] + '.service'


def api(entry, *command):
    env = dict(os.environ, BOX_API_URL='http://127.0.0.1:' + str(entry['api_port']),
               BOX_API_SECRET=entry['api_secret'])
    return run([ENGINE, 'api', 'tailscale', *command], env=env, timeout=8)


def status(entry):
    try:
        output = api(entry, 'status').stdout
        state = re.search(r'^\s*State:\s+(\S+)', output, re.M)
        url = re.search(r'https://login\.tailscale\.com/[^\s\x1b]+', output)
        return state.group(1) if state else 'Unknown', url.group(0) if url else None
    except (subprocess.SubprocessError, OSError):
        return 'Unavailable', None


def ready(entry):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if status(entry)[0] != 'Unavailable':
            return
        time.sleep(0.5)
    raise RuntimeError('Exit did not start. Check: journalctl -u ' + unit(entry) + ' -n 40')


def configure(entry):
    gid = grp.getgrnam('tailscale-proxy').gr_gid
    uid = pwd.getpwnam('tailscale-proxy').pw_uid
    node = DATA / 'nodes' / entry['slug']
    node.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chown(node, uid, gid)
    os.chmod(node, 0o700)
    cfg = ETC / 'exits' / (entry['slug'] + '.json')
    # Validate in a temporary file before changing the live config.
    fd, name = tempfile.mkstemp(dir=ETC / 'exits', suffix='.json')
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(make_config(entry), stream)
        run([ENGINE, 'check', '-c', name])
    finally:
        os.unlink(name)
    atomic_json(cfg, make_config(entry), 0o640, gid)


def save_exit(state, entry, previous=None):
    old = copy.deepcopy(state)
    try:
        configure(entry)
        run(['systemctl', 'reset-failed', unit(entry)], check=False)
        run(['systemctl', 'enable', unit(entry)])
        run(['systemctl', 'restart', unit(entry)])
        ready(entry)
        state['exits'] = [e for e in state['exits'] if e['slug'] != entry['slug']] + [entry]
        atomic_json(STATE, state)
    except Exception:
        state.clear()
        state.update(old)
        if previous:
            configure(previous)
            run(['systemctl', 'restart', unit(previous)], check=False)
        else:
            run(['systemctl', 'disable', '--now', unit(entry)], check=False)
            (ETC / 'exits' / (entry['slug'] + '.json')).unlink(missing_ok=True)
        raise


def ask(prompt, default=None, *, secret=False):
    suffix = (' [' + str(default) + ']') if default is not None else ''
    value = (getpass.getpass if secret else input)(prompt + suffix + ': ')
    if not secret:
        value = value.strip()
    if not value and default is not None:
        return default
    return value


def yes(prompt, default=False):
    value = ask(prompt, 'Y/n' if default else 'y/N').lower()
    return value in ('y', 'yes') or (value == 'y/n' and default)


def port_available(port, kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        try:
            sock.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False


def new_identity(state, label):
    base = slugify(label)
    slug = base
    n = 2
    existing = {e['slug'] for e in state['exits']}
    while slug in existing or (DATA / 'nodes' / slug).exists():
        slug = base + '-' + str(n)
        n += 1
    used = {e['id'] for e in state['exits']}
    for number in range(1, 1000):
        if number not in used and all(port_available(p, kind) for p, kind in (
                (20000 + number, socket.SOCK_STREAM),
                (22000 + number, socket.SOCK_STREAM),
                (41640 + number, socket.SOCK_DGRAM))):
            return {'id': number, 'slug': slug, 'hostname': 'proxy-' + slug,
                    'probe_port': 20000 + number, 'api_port': 22000 + number,
                    'ts_port': 41640 + number, 'probe_secret': secrets.token_hex(24),
                    'api_secret': secrets.token_hex(32)}
    raise ValueError('No free exit slot or local ports.')


def proxy_details(entry=None):
    old = entry or {}
    print('1) HTTP\n2) SOCKS5\n3) Shadowsocks')
    selected = ask('Proxy type', {'http': '1', 'socks': '2', 'shadowsocks': '3'}.get(old.get('type'), '1'))
    kinds = {'1': 'http', '2': 'socks', '3': 'shadowsocks'}
    if selected not in kinds:
        raise ValueError('Choose 1, 2 or 3.')
    kind = kinds[selected]
    same = kind == old.get('type')
    host = valid_host(ask('Proxy host', old.get('server')))
    port = int(ask('Proxy port', old.get('port')))
    if not 1 <= port <= 65535:
        raise ValueError('Port must be between 1 and 65535.')
    result = {'type': kind, 'server': host, 'port': port, 'username': '',
              'password': '', 'method': '', 'udp': False}
    if kind in ('http', 'socks'):
        if yes('Proxy requires username/password?', bool(old.get('username')) if same else kind == 'http'):
            result['username'] = ask('Username', old.get('username') if same else None)
            if not result['username']:
                raise ValueError('Username cannot be empty when authentication is enabled.')
            password = ask('Password (Enter keeps existing)' if same and old.get('password') else 'Password', secret=True)
            result['password'] = password or (old.get('password', '') if same else '')
            if not result['password']:
                raise ValueError('Password cannot be empty.')
    if kind == 'shadowsocks':
        print('\n'.join(str(i) + ') ' + method for i, method in enumerate(METHODS, 1)))
        default_method = old.get('method') if same else None
        method = ask('Cipher name or number', default_method or METHODS[2])
        if method.isdecimal() and 1 <= int(method) <= len(METHODS):
            method = METHODS[int(method) - 1]
        if method not in METHODS:
            raise ValueError('Choose a listed supported cipher.')
        result['method'] = method
        result['password'] = ask('Password/key (Enter keeps existing)' if same else 'Password/key', secret=True) or (old.get('password', '') if same else '')
        if not result['password']:
            raise ValueError('Password/key cannot be empty.')
    if kind in ('socks', 'shadowsocks'):
        result['udp'] = yes('Provider supports UDP relay?', old.get('udp', False) if same else False)
    result['doh'] = ask('Exit DNS DoH URL (optional)', old.get('doh', DEFAULT_DOH))
    doh_server(result['doh'])
    return result


def select_exit(state, selector=None):
    entries = sorted(state['exits'], key=lambda e: e['id'])
    if not entries:
        raise ValueError('No exits yet. Run: sudo tailscale-proxy add')
    if selector:
        matches = [e for e in entries if selector in (e['slug'], e['hostname'])]
        if len(matches) == 1:
            return matches[0]
        raise ValueError('Unknown exit: ' + selector)
    for i, entry in enumerate(entries, 1):
        print(str(i) + ') ' + entry['label'] + ' (' + entry['hostname'] + ')')
    choice = int(ask('Exit number'))
    if not 1 <= choice <= len(entries):
        raise ValueError('Invalid exit number.')
    return entries[choice - 1]


def login(entry):
    deadline = time.monotonic() + 40
    state, url = status(entry)
    while not url and state not in ('Running', 'NeedsMachineAuth') and time.monotonic() < deadline:
        time.sleep(1)
        state, url = status(entry)
    print('\nTailscale node: ' + entry['hostname'])
    if url:
        print('Open this sign-in link:\n' + url)
    elif state == 'Running':
        print('Signed in to Tailscale.')
    else:
        print('Tailscale state: ' + state)
        print('Retrieve a fresh link: sudo tailscale-proxy login ' + entry['slug'])
    print('Exit-node advertising: ON automatically.')
    print('If not auto-approved: ' + ADMIN)
    print('Select ' + entry['hostname'] + ' > Edit route settings > Use as exit node.')
    print('Or run: sudo tailscale-proxy approve ' + entry['slug'])
    print('Apple TV / iPhone: Tailscale > Exit Node > ' + entry['hostname'])


def add(state):
    label = ask('Country / exit name')
    if not label:
        raise ValueError('Country label cannot be empty.')
    entry = new_identity(state, label)
    entry['label'] = label
    entry.update(proxy_details())
    save_exit(state, entry)
    if shutil.which('ufw'):
        current = run(['ufw', 'status'], check=False)
        if 'Status: active' in current.stdout:
            opened = run(['ufw', 'allow', str(entry['ts_port']) + '/udp'], check=False)
            if opened.returncode:
                print('UFW rule was not added; permit UDP ' + str(entry['ts_port']) + ' for direct connections.')
    print('\nSaved ' + entry['label'] + '. UDP port: ' + str(entry['ts_port']))
    print('For IP-allowlisted proxies, allowlist the VPS public IP with your provider.')
    login(entry)


def benchmark(entry):
    # Credentials go over stdin, never in a process argument or public listener.
    config = 'proxy = "http://127.0.0.1:' + str(entry['probe_port']) + '"\n'
    config += 'proxy-user = "probe:' + entry['probe_secret'] + '"\n'
    config += 'noproxy = ""\n'
    result = run(['curl', '--config', '-', '--fail', '--silent', '--show-error',
                  '--connect-timeout', '10', '--max-time', '30',
                  'https://ipinfo.io/json', '--write-out', '\n%{time_total}'],
                 input=config, timeout=35)
    payload, duration = result.stdout.rsplit('\n', 1)
    data = json.loads(payload)
    if not data.get('ip'):
        raise ValueError('Exit identity service returned no IP.')
    return data, float(duration)


def bench(state, selector=None):
    entries = [select_exit(state, selector)] if selector else sorted(state['exits'], key=lambda e: e['id'])
    if not entries:
        raise ValueError('No exits yet.')
    failed = False
    for entry in entries:
        print('\n' + entry['label'] + ' (' + entry['hostname'] + ')')
        try:
            data, duration = benchmark(entry)
            print('Exit IP - ' + data['ip'])
            print('Location - ' + ', '.join(str(data.get(k, '?')) for k in ('city', 'country')))
            print('Provider - ' + str(data.get('org', '?')))
            print('HTTPS request - ' + str(round(duration * 1000)) + ' ms')
        except (subprocess.SubprocessError, ValueError, OSError) as exc:
            print('Proxy check FAILED - ' + safe_error(exc))
            failed = True
    print('\nChecks the VPS proxy path. Verify Tailscale client IP/DNS separately.')
    if failed:
        raise RuntimeError('One or more proxy checks failed.')


def check(state):
    if not state['exits']:
        print('No exits yet. Run: sudo tailscale-proxy add')
    for entry in sorted(state['exits'], key=lambda e: e['id']):
        current, _ = status(entry)
        print(entry['hostname'] + ' - ' + current + ' | exit advertising ON | UDP ' + str(entry['ts_port']))
    print('45.88.89.23 - DIRECT through VPS')
    print('Other client traffic - selected proxy; no direct fallback')
    print('Exit approval / device key expiry: ' + ADMIN)


def approve(entry):
    """Optional Tailscale API approval; token is used in memory and never saved."""
    print('Optional: approve this exit using a Tailscale API access token.')
    print('Create a token at https://login.tailscale.com/admin/settings/keys')
    token = getpass.getpass('Tailscale API access token (not an auth key; not saved): ').strip()
    if not token:
        raise ValueError('No token entered. Approve in the admin console instead: ' + ADMIN)

    def request(path, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request('https://api.tailscale.com/api/v2/' + path, body,
                                     {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=30) as response:
            content = response.read()
            return json.loads(content) if content else {}
    devices = request('tailnet/-/devices')['devices']
    matches = [d for d in devices if d.get('hostname') == entry['hostname']]
    if len(matches) != 1:
        raise ValueError('Could not uniquely identify the signed-in node. Use the admin console.')
    path = 'device/' + urllib.parse.quote(matches[0]['id'], safe='') + '/routes'
    routes = request(path)
    defaults = {'0.0.0.0/0', '::/0'}
    if not defaults.issubset(set(routes.get('advertisedRoutes', []))):
        raise ValueError('Node is not advertising both exit routes yet. Finish sign-in first.')
    enabled = sorted(set(routes.get('enabledRoutes', [])) | defaults)
    request(path, {'routes': enabled})
    result = request(path)
    if not defaults.issubset(set(result.get('enabledRoutes', []))):
        raise RuntimeError('Tailscale did not confirm exit-route approval.')
    print(entry['hostname'] + ' - exit routes approved.')


def manage(state):
    print('1) List exits\n2) Add exit\n3) Edit proxy / DNS\n4) Sign-in link\n5) Restart exit\n6) Remove exit\n7) Approve exit node')
    choice = ask('Choice')
    if choice == '1':
        check(state)
        return
    if choice == '2':
        add(state)
        return
    entry = select_exit(state)
    if choice == '3':
        updated = copy.deepcopy(entry)
        updated.update(proxy_details(entry))
        save_exit(state, updated, entry)
        print('Updated. Existing Tailscale identity and country selection were preserved.')
    elif choice == '4':
        login(entry)
    elif choice == '5':
        run(['systemctl', 'reset-failed', unit(entry)], check=False)
        run(['systemctl', 'restart', unit(entry)])
        ready(entry)
        print('Restarted ' + entry['hostname'])
    elif choice == '6':
        if not yes('Remove ' + entry['hostname'] + '?'):
            return
        run(['systemctl', 'disable', '--now', unit(entry)])
        state['exits'] = [e for e in state['exits'] if e['slug'] != entry['slug']]
        atomic_json(STATE, state)
        (ETC / 'exits' / (entry['slug'] + '.json')).unlink(missing_ok=True)
        shutil.rmtree(DATA / 'nodes' / entry['slug'], ignore_errors=True)
        if shutil.which('ufw'):
            run(['ufw', '--force', 'delete', 'allow', str(entry['ts_port']) + '/udp'], check=False)
        print('Removed locally. Delete the offline node from Tailscale: ' + ADMIN)
    elif choice == '7':
        approve(entry)
    else:
        raise ValueError('Invalid choice.')


def safe_error(exc):
    if isinstance(exc, subprocess.CalledProcessError):
        # Do not print argv, environment, registry contents or proxy credentials.
        return (exc.stderr or 'Command failed.').strip()[:800]
    return str(exc)


def main():
    if os.geteuid() != 0:
        raise ValueError('Run with sudo.')
    os.umask(0o077)
    action = sys.argv[1] if len(sys.argv) > 1 else 'manage'
    selector = sys.argv[2] if len(sys.argv) > 2 else None
    with open('/run/lock/tailscale-proxy.lock', 'w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = read_state()
        if action == 'add':
            add(state)
        elif action == 'manage':
            manage(state)
        elif action == 'bench':
            bench(state, selector)
        elif action == 'check':
            check(state)
        elif action == 'login':
            login(select_exit(state, selector))
        elif action == 'approve':
            approve(select_exit(state, selector))
        elif action == 'restart-all':
            for entry in state['exits']:
                configure(entry)
                run(['systemctl', 'reset-failed', unit(entry)], check=False)
                run(['systemctl', 'restart', unit(entry)])
                ready(entry)
        else:
            raise ValueError('Commands: add | manage | bench | check | login [exit] | approve [exit]')


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr)
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print('Error: ' + safe_error(exc), file=sys.stderr)
        sys.exit(1)
