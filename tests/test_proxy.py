"""Run with SING_BOX_BIN=/path/to/sing-box python3 -m unittest discover -s tests -v."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('manager', Path(__file__).resolve().parents[1] / 'manager.py')
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
BIN = os.environ.get('SING_BOX_BIN')


def example(kind='http', udp=False):
    return {'id': 1, 'slug': 'usa', 'label': 'USA', 'hostname': 'proxy-usa',
            'type': kind, 'server': '127.0.0.1', 'port': 1080,
            'username': 'user', 'password': 'secret', 'udp': udp,
            'method': 'aes-128-gcm', 'probe_port': 20001, 'probe_secret': 'probe-secret',
            'api_port': 22001, 'api_secret': 'api-secret', 'ts_port': 41641,
            'doh': m.DEFAULT_DOH}


class ConfigTests(unittest.TestCase):
    def test_unique_identities_and_ports(self):
        with tempfile.TemporaryDirectory() as root, patch.object(m, 'DATA', Path(root)), patch.object(m, 'port_available', return_value=True):
            state = {'schema': 1, 'exits': []}
            a = m.new_identity(state, 'USA')
            state['exits'].append(a)
            b = m.new_identity(state, 'USA')
            self.assertEqual((a['hostname'], b['hostname']), ('proxy-usa', 'proxy-usa-2'))
            for field in ('ts_port', 'api_port', 'probe_port', 'api_secret', 'probe_secret'):
                self.assertNotEqual(a[field], b[field])

    def test_only_exact_bypass_can_go_direct(self):
        for kind in ('http', 'socks', 'shadowsocks'):
            config = m.make_config(example(kind))
            self.assertEqual(config['route']['final'], 'proxy')
            direct = [r for r in config['route']['rules'] if r.get('outbound') == 'direct']
            self.assertEqual(direct, [{'ip_cidr': ['45.88.89.23/32'], 'action': 'route', 'outbound': 'direct'}])
            ep = config['endpoints'][0]
            self.assertTrue(ep['advertise_exit_node'])
            self.assertFalse(ep['system_interface'])
            self.assertFalse(ep['ephemeral'])
            self.assertFalse(ep['accept_routes'])

    def test_dns_client_queries_use_proxy(self):
        e = example()
        e['doh'] = 'https://dns.controld.com/TEST-ONLY'
        config = m.make_config(e)
        doh = config['dns']['servers'][1]
        self.assertEqual(doh['detour'], 'proxy')
        self.assertEqual(doh['path'], '/TEST-ONLY')
        self.assertIn({'inbound': ['tailscale', 'probe'], 'server': 'exit-dns'}, config['dns']['rules'])
        self.assertEqual(config['outbounds'][0]['domain_resolver'], 'bootstrap')
        self.assertEqual(config['endpoints'][0]['domain_resolver'], 'bootstrap')

    def test_unsupported_udp_rejected_after_bypass(self):
        config = m.make_config(example())
        self.assertEqual(config['route']['rules'][0]['outbound'], 'direct')
        self.assertIn({'network': 'udp', 'action': 'reject'}, config['route']['rules'])
        udp = m.make_config(example('socks', True))
        self.assertNotIn({'network': 'udp', 'action': 'reject'}, udp['route']['rules'])

    def test_invalid_input_rejected(self):
        for host in ('https://example.com', 'host:8080', 'hello world', 'x;sh'):
            with self.assertRaises(ValueError):
                m.valid_host(host)
        for url in ('http://dns.controld.com/a', 'https://user:pass@host/a', 'https:///a'):
            with self.assertRaises(ValueError):
                m.doh_server(url)

    def test_failed_edit_restores_registry_and_previous_config(self):
        state = {'schema': 1, 'exits': [example()]}
        old = copy.deepcopy(state)
        updated = copy.deepcopy(state['exits'][0])
        updated['server'] = 'broken.example'
        with patch.object(m, 'configure') as configure, patch.object(m, 'run'), patch.object(m, 'ready', side_effect=RuntimeError('startup failed')):
            with self.assertRaises(RuntimeError):
                m.save_exit(state, updated, old['exits'][0])
            self.assertEqual(state, old)
            self.assertEqual(configure.call_args_list[-1].args[0], old['exits'][0])

    @unittest.skipUnless(BIN, 'Set SING_BOX_BIN to validate against the real engine')
    def test_real_engine_accepts_all_proxy_configs(self):
        with tempfile.TemporaryDirectory() as root:
            for kind, auth, udp in [('http', True, False), ('http', False, False),
                                    ('socks', True, False), ('socks', False, True),
                                    ('shadowsocks', True, False), ('shadowsocks', True, True)]:
                entry = example(kind, udp)
                if not auth:
                    entry['username'] = entry['password'] = ''
                config = Path(root) / 'config.json'
                config.write_text(json.dumps(m.make_config(entry, Path(root))))
                result = subprocess.run([BIN, 'check', '-c', str(config)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Proxy(socketserver.StreamRequestHandler):
    destinations = []

    def handle(self):
        first = self.rfile.readline().decode().strip()
        headers = []
        while True:
            line = self.rfile.readline()
            if line in (b'\r\n', b'\n', b''):
                break
            headers.append(line.decode().strip())
        if not first.startswith('CONNECT '):
            self.wfile.write(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
            return
        Proxy.destinations.append(first.split()[1])
        self.wfile.write(b'HTTP/1.1 200 Connection Established\r\n\r\n')
        self.wfile.flush()
        self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        body = b'VIA-PROXY'
        self.wfile.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 9\r\n\r\n' + body)


class Direct(socketserver.StreamRequestHandler):
    def handle(self):
        self.rfile.readline()
        while self.rfile.readline() not in (b'\r\n', b'\n', b''):
            pass
        self.wfile.write(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 10\r\n\r\nVIA-DIRECT')


@unittest.skipUnless(BIN, 'Set SING_BOX_BIN to run real routing integration tests')
class DataPlaneTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('RUN_TAILSCALE_SMOKE') == '1', 'Enable RUN_TAILSCALE_SMOKE for network-dependent authentication-link test')
    def test_native_tailscale_auth_link_and_api(self):
        with tempfile.TemporaryDirectory() as root:
            with patch.object(m, 'DATA', Path(root)):
                entry = example()
                entry.update(m.new_identity({'schema': 1, 'exits': []}, 'build-smoke'))
            config = m.make_config(entry, Path(root))
            path = Path(root) / 'config.json'
            path.write_text(json.dumps(config))
            logfile = Path(root) / 'engine.log'
            with open(logfile, 'w') as log:
                process = subprocess.Popen([BIN, 'run', '-c', str(path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 45
                    state, url = 'Unavailable', None
                    with patch.object(m, 'ENGINE', BIN):
                        while time.monotonic() < deadline and process.poll() is None:
                            state, url = m.status(entry)
                            if url:
                                break
                            time.sleep(0.5)
                    self.assertIn(state, ('NeedsLogin', 'NoState'))
                    self.assertTrue(url and url.startswith('https://login.tailscale.com/'), 'Native Tailscale sign-in URL was not returned')
                finally:
                    process.terminate()
                    process.wait(timeout=10)

    def test_proxy_bypass_and_failure_isolation(self):
        # Replace only the Tailscale transport with the existing local probe inbound.
        # This tests the real sing-box route engine without authenticating a tailnet.
        with tempfile.TemporaryDirectory() as root, Server(('127.0.0.1', 0), Proxy) as proxy, Server(('127.0.0.1', 0), Direct) as direct:
            Proxy.destinations = []
            for server in (proxy, direct):
                threading.Thread(target=server.serve_forever, daemon=True).start()
            entry = example()
            entry['port'] = proxy.server_address[1]
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                entry['probe_port'] = sock.getsockname()[1]
            config = m.make_config(entry, Path(root))
            config.pop('endpoints')
            config.pop('services')
            # Rewrite only the direct destination for a local fixture. The exact
            # 45.88.89.23/32 rule predicate is unchanged and tested above too.
            config['route']['rules'][0].update(override_address='127.0.0.1', override_port=direct.server_address[1])
            path = Path(root) / 'config.json'
            path.write_text(json.dumps(config))
            with open(Path(root) / 'engine.log', 'w') as log:
                process = subprocess.Popen([BIN, 'run', '-c', str(path)], stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 8
                    while time.monotonic() < deadline:
                        try:
                            with socket.create_connection(('127.0.0.1', entry['probe_port']), timeout=0.2):
                                break
                        except OSError:
                            time.sleep(0.1)
                    def get(ip):
                        return subprocess.run(['curl', '--fail', '--silent', '--show-error', '--max-time', '3', '--noproxy', '',
                                               '--proxy', 'http://127.0.0.1:' + str(entry['probe_port']),
                                               '--proxy-user', 'probe:probe-secret', 'http://' + ip + '/'],
                                              capture_output=True, text=True)
                    if process.poll() is not None:
                        error = (Path(root) / 'engine.log').read_text()
                        if os.environ.get('ALLOW_NETLINK_SKIP') == '1' and 'create netlink socket: operation not permitted' in error:
                            self.skipTest('This execution environment denies netlink sockets; run on Ubuntu/Debian.')
                        self.fail(error)
                    proxied = get('93.184.216.34')
                    self.assertEqual(proxied.stdout, 'VIA-PROXY', proxied.stderr)
                    self.assertIn('93.184.216.34:80', Proxy.destinations)
                    bypass = get('45.88.89.23')
                    self.assertEqual(bypass.stdout, 'VIA-DIRECT', bypass.stderr)
                    self.assertNotIn('45.88.89.23:80', Proxy.destinations)
                    # Same VPS address must not make other destinations go direct.
                    proxy.shutdown()
                    proxy.server_close()
                    failed = get('93.184.216.34')
                    self.assertNotEqual(failed.returncode, 0)
                    self.assertNotEqual(failed.stdout, 'VIA-DIRECT')
                    self.assertEqual(get('45.88.89.23').stdout, 'VIA-DIRECT')
                finally:
                    process.terminate()
                    process.wait(timeout=10)
                    direct.shutdown()


if __name__ == '__main__':
    unittest.main()
