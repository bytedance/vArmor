#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Maintainer TLS/TCP E2E using curl clients, a BusyBox backend and a TLS Envoy fixture."""
import argparse
import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('smoke_cluster.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
a = smoke.advisor

TCP_SERVER = r'''cat > /tmp/respondtcp <<'SH'
#!/bin/sh
IFS= read -r line
printf '%s\n' "$line" >> /tmp/tcp-hits
printf 'tcp-ok\n'
SH
chmod +x /tmp/respondtcp
touch /tmp/tcp-hits
exec busybox nc -lk -p 9090 -e /tmp/respondtcp
'''


def tls_config():
    return {'static_resources': {
        'listeners': [{'name': 'tls', 'address': {'socket_address': {'address': '0.0.0.0', 'port_value': 8443}},
            'filter_chains': [{'transport_socket': {'name': 'envoy.transport_sockets.tls', 'typed_config': {
                '@type': 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
                'common_tls_context': {'alpn_protocols': ['http/1.1'], 'tls_certificates': [{
                    'certificate_chain': {'filename': '/fixture/tls.crt'}, 'private_key': {'filename': '/fixture/tls.key'}}]}}},
                'filters': [{'name': 'envoy.filters.network.http_connection_manager', 'typed_config': {
                    '@type': 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                    'stat_prefix': 'fixture', 'route_config': {'name': 'local', 'virtual_hosts': [{'name': 'all',
                        'domains': ['*'], 'routes': [{'match': {'prefix': '/'}, 'route': {'cluster': 'backend'}}]}]},
                    'http_filters': [{'name': 'envoy.filters.http.router', 'typed_config': {
                        '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'}}]}}]}]}],
        'clusters': [{'name': 'backend', 'type': 'STATIC', 'connect_timeout': '2s',
            'load_assignment': {'cluster_name': 'backend', 'endpoints': [{'lb_endpoints': [{'endpoint': {
                'address': {'socket_address': {'address': '127.0.0.1', 'port_value': 8080}}}}]}]}}]}}


def fixture_certificate(context, namespace, profile, names, secret_reader=None):
    # Only the CA of THIS test's freshly-created policy is read. Never print or persist its key as evidence.
    secret = (secret_reader() if secret_reader else a.get(context, 'secret', namespace, profile))['data']
    with tempfile.TemporaryDirectory(prefix='np-advisor-cert-') as folder:
        root = Path(folder)
        os.chmod(root, 0o700)
        for filename in ('mitm-ca.crt', 'mitm-ca.key'):
            p = root / filename
            p.write_bytes(base64.b64decode(secret[filename]))
            p.chmod(0o600)
        ext = root / 'ext.cnf'
        ext.write_text('subjectAltName=' + ','.join('DNS:' + n for n in names) + '\n')
        def openssl(*args):
            result = subprocess.run(['openssl', *args], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Fixture certificate generation failed: ' + result.stderr)
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + names[0],
                '-keyout', str(root/'key.pem'), '-out', str(root/'request.pem'))
        openssl('x509', '-req', '-in', str(root/'request.pem'), '-CA', str(root/'mitm-ca.crt'),
                '-CAkey', str(root/'mitm-ca.key'), '-set_serial', '1', '-days', '1', '-extfile', str(ext),
                '-out', str(root/'cert.pem'))
        return {'tls.crt': base64.b64encode((root/'cert.pem').read_bytes()).decode(),
                'tls.key': base64.b64encode((root/'key.pem').read_bytes()).decode()}


def run(args):
    spec = importlib.util.spec_from_file_location('bounded_tls_tcp', Path(__file__).with_name('smoke_tls_tcp_run.py'))
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner.run(args)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--context', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--image', required=True, help='approved curl image with sh, cat and BusyBox nc')
    p.add_argument('--skill-dir', help='Extracted distribution Skill directory; source default')
    sys.exit(run(p.parse_args()))
