"""Installer/systemd smoke test. Run only on a disposable GitHub Actions runner."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import time

if os.environ.get('GITHUB_ACTIONS') != 'true' or os.geteuid() != 0:
    raise SystemExit('This test requires root on a disposable GitHub Actions runner.')
spec = importlib.util.spec_from_file_location('manager', '/opt/tailscale-proxy/manager.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
state = m.read_state()
if state['exits']:
    raise SystemExit('Refusing to run against an existing registry.')
entry = m.new_identity(state, 'service-smoke')
entry.update(label='service-smoke', type='http', server='example.com', port=8080,
             username='', password='', method='', udp=False, doh=m.DEFAULT_DOH)
try:
    m.save_exit(state, entry)
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        backend, url = m.status(entry)
        if backend == 'NeedsLogin' and url:
            break
        time.sleep(1)
    else:
        raise AssertionError('Systemd exit did not return a Tailscale authentication link.')
    # Reapplying setup must preserve node state, config and advertising.
    subprocess.run(['/usr/local/bin/tailscale-proxy', 'restart-all'], check=True)
    assert m.status(entry)[0] in ('NoState', 'NeedsLogin', 'Running')
    print('Installer, restricted systemd service, API and sign-in link: PASS')
    print('Persistent identity preserved across service restart: PASS')
finally:
    subprocess.run(['systemctl', 'disable', '--now', m.unit(entry)], check=False,
                   capture_output=True)
    m.atomic_json(m.STATE, {'schema': 1, 'exits': []})
    (m.ETC / 'exits' / (entry['slug'] + '.json')).unlink(missing_ok=True)
    shutil.rmtree(m.DATA / 'nodes' / entry['slug'], ignore_errors=True)
