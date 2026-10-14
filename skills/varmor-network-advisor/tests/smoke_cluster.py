#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Owned HTTP smoke test: observe -> real normalized audits -> draft -> enforce -> negative controls."""
import argparse
import contextlib
import importlib.util
import json
from pathlib import Path
import sys
import time
import uuid

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/advisor.py'
spec = importlib.util.spec_from_file_location('advisor', SCRIPT)
advisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(advisor)

SERVER = r'''
cat > /tmp/respond <<'SH'
#!/bin/sh
read -r method path protocol
authority=''
while IFS= read -r line; do
    line=$(printf '%s' "$line" | tr -d '\r')
    [ -z "$line" ] && break
    case "$line" in [Hh][Oo][Ss][Tt]:*) authority=${line#*:}; authority=${authority# };; esac
done
printf '%s\t%s\t%s\n' "$method" "$path" "$authority" >> /tmp/hits.tsv
body="$method $path"
printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#body}" "$body"
SH
chmod +x /tmp/respond
touch /tmp/hits.tsv
exec busybox nc -lk -p 8080 -e /tmp/respond
'''


def workload(namespace, name, image, command):
    labels = {'sandbox.varmor.org/enable': 'true'} if name == 'client' else {}
    return {'apiVersion': 'apps/v1', 'kind': 'Deployment', 'metadata': {'name': name, 'namespace': namespace, 'labels': labels},
            'spec': {'replicas': 1, 'selector': {'matchLabels': {'app': name}},
                     'template': {'metadata': {'labels': {'app': name, **labels}},
                                  'spec': {'automountServiceAccountToken': False,
                                           'containers': [{'name': 'app', 'image': image, 'command': command}]}}}}


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    report = {'at': advisor.now(), 'context': args.context, 'status': 'running', 'scope': 'owned-http-smoke',
              'image': args.image,
              'limitations': ['HTTP only; does not verify TLS MITM, SNI passthrough, UDP or long-running convergence.']}
    namespace = 'np-advisor-smoke-' + uuid.uuid4().hex[:8]
    report['namespace'] = namespace
    created = False
    try:
        doctor = argparse.Namespace(context=args.context, output=str(output / 'preflight.json'))
        if advisor.doctor(doctor):
            raise RuntimeError('Cluster preflight failed; no workload or reader Pods created')
        session = output / 'session'
        if session.exists():
            raise ValueError('smoke session already exists; use a fresh --output')
        advisor.kube(args.context, 'create', 'namespace', namespace)
        created = True
        obs = advisor.parser().parse_args(['observe', '--session', str(session), '--context', args.context,
               '--namespace', namespace, '--name', 'observe-client', '--workload', 'client', '--observe', 'both'])
        advisor.observe(obs)
        advisor.kube(args.context, 'apply', '--dry-run=server', '-f', str(session / 'observe.yaml'))
        advisor.kube(args.context, 'apply', '-f', str(session / 'observe.yaml'))
        advisor.kube(args.context, 'wait', '-n', namespace, '--for=condition=Ready',
                     'varmorpolicy/observe-client', '--timeout=60s')
        items = [workload(namespace, 'backend', args.image, ['sh', '-c', SERVER]),
                 {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'backend', 'namespace': namespace},
                  'spec': {'selector': {'app': 'backend'}, 'ports': [{'port': 8080, 'targetPort': 8080}]}},
                 workload(namespace, 'client', args.image, ['sleep', '3600'])]
        advisor.write(output / 'workloads.yaml', {'apiVersion': 'v1', 'kind': 'List', 'items': items})
        advisor.kube(args.context, 'apply', '-f', str(output / 'workloads.yaml'))
        for name in ('backend', 'client'):
            advisor.kube(args.context, 'rollout', 'status', '-n', namespace, 'deploy/' + name, '--timeout=60s')
        state = advisor.load(session / 'session.json')
        pods, _ = advisor.live_inventory(state, advisor.load(session / 'observe.yaml'))
        client_pods = [p for p in pods if p['metadata'].get('labels', {}).get('app') == 'client']
        if len(client_pods) != 1:
            raise RuntimeError('Expected one injected owned client Pod')
        client = client_pods[0]
        client_name = client['metadata']['name']
        report['clientPodUID'] = client['metadata']['uid']
        hostname = f'backend.{namespace}.svc.cluster.local'

        def request(method, path, authority=''):
            command = ['curl', '--noproxy', '*', '--silent', '--show-error', '--max-time', '8',
                       '-X', method, '-w', '\n%{http_code}', f'http://{hostname}:8080{path}']
            if authority:
                command += ['-H', 'Host: ' + authority]
            raw = advisor.kube(args.context, 'exec', '-n', namespace, client_name, '-c', 'app', '--',
                               *command)
            body, status = raw.rstrip('\n').rsplit('\n', 1)
            return {'status': int(status), 'body': body}

        report['observationRequests'] = [request('GET', '/read'), request('POST', '/write')]
        if any(x['status'] != 200 for x in report['observationRequests']):
            raise RuntimeError('Observation traffic did not reach the owned backend')
        cli = ['collect', '--session', str(session), '--source', args.source, '--reader-image', args.reader_image]
        for option, value in (('--agent-selector', args.agent_selector), ('--agent-container', args.agent_container)):
            if value:
                cli += [option, value]
        if args.create_readers:
            cli.append('--create-readers')
        collect_args = advisor.parser().parse_args(cli)
        # Poll audit delivery with a bounded attempt count; never re-send traffic to manufacture coverage.
        for _ in range(6):
            if advisor.collect(collect_args):
                raise RuntimeError('Normalized audit collection reported malformed or unverified events')
            if advisor.analyze(advisor.parser().parse_args(['analyze', '--session', str(session)])) == 0:
                analysis = advisor.load(session / 'analysis.json')
                if analysis['candidateRules'] >= 2:
                    break
            time.sleep(2)
        else:
            raise RuntimeError('Expected GET /read and POST /write audit evidence not received')
        report['analysis'] = advisor.load(session / 'analysis.json')
        candidate = session / 'candidate.yaml'
        advisor.kube(args.context, 'apply', '--dry-run=server', '-f', str(candidate))
        # This enforcement applies only to this script's ephemeral client.
        advisor.kube(args.context, 'apply', '-f', str(candidate))
        expected = {'read': 200, 'write': 200, 'wrongMethod': 403, 'unknownPath': 403, 'unknownHost': 403}
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if request('GET', '/config-probe-unlisted')['status'] == 403:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Proxy did not enforce all expected positive/negative controls within bounded wait')
        responses = {'read': request('GET', '/read'), 'write': request('POST', '/write'),
                     'wrongMethod': request('POST', '/read'), 'unknownPath': request('GET', '/read-neighbor'),
                     'unknownHost': request('GET', '/read', 'unlisted.invalid:8080')}
        report['enforcementRequests'] = responses
        if not all(responses[k]['status'] == v for k, v in expected.items()):
            raise RuntimeError('Expected positive/negative controls failed after config propagation')
        if responses['read']['body'] != 'GET /read' or responses['write']['body'] != 'POST /write':
            raise RuntimeError('Allowed responses do not match the owned backend')
        backend = advisor.kube(args.context, 'exec', '-n', namespace, 'deploy/backend', '-c', 'app',
                               '--', 'cat', '/tmp/hits.tsv')
        (output / 'backend.log').write_text(backend)
        backend_hits = []
        for line in backend.splitlines():
            try:
                method, path, authority = line.split('\t')
                hit = {'method': method, 'path': path, 'authority': authority}
            except ValueError:
                continue
            backend_hits.append(hit)
            if hit.get('path') == '/read-neighbor' or (hit.get('path') == '/read' and hit.get('method') == 'POST') or \
               hit.get('authority') == 'unlisted.invalid:8080':
                raise RuntimeError('Denied control reached the backend')
        for method, path in (('GET', '/read'), ('POST', '/write')):
            if not any(h == {'method': method, 'path': path, 'authority': hostname + ':8080'}
                       for h in backend_hits):
                raise RuntimeError('Backend receipts must preserve allowed Host before validating unknown Host absence')
        # Read without assuming the live policy is still an observation policy.
        pods, _ = advisor.live_inventory(state)
        audit_seen = set()
        audits = []
        for _ in range(6):
            audits = []
            for _, raw in advisor.sources(state, collect_args, pods):
                for line in raw.splitlines():
                    try:
                        r = json.loads(line)
                    except ValueError:
                        continue
                    if r.get('enforcer') != 'NetworkProxy' or r.get('podUID') != client['metadata']['uid'] or \
                       r.get('profileName') != state['profile'] or r.get('podNamespace') != namespace:
                        continue
                    audits.append(r)
                    e = r.get('event', {})
                    if r.get('action') == 'DENIED':
                        audit_seen.add((e.get('authority'), e.get('method'), e.get('path')))
            needed = {(hostname + ':8080', 'POST', '/read'), (hostname + ':8080', 'GET', '/read-neighbor'),
                      ('unlisted.invalid:8080', 'GET', '/read')}
            if needed <= audit_seen:
                break
            time.sleep(2)
        else:
            raise RuntimeError('Expected DENIED normalized audit records not received')
        report['deniedAuditControls'] = sorted(audit_seen)
        advisor.write(output / 'normalized-audits.json', audits)
        report['status'] = 'passed'
        return 0
    except (RuntimeError, ValueError, OSError, KeyError, advisor.subprocess.TimeoutExpired) as exc:
        report.update({'status': 'blocked-or-failed', 'error': str(exc)})
        return 2
    finally:
        cleanup_failed = False
        if created and not args.keep:
            try:
                advisor.kube(args.context, 'delete', 'namespace', namespace, '--wait=false')
                advisor.kube(args.context, 'wait', '--for=delete', 'namespace/' + namespace, '--timeout=45s')
                report['cleanup'] = 'owned namespace deletion confirmed'
            except Exception as exc:
                report['cleanupError'] = str(exc)
                report['testStatus'] = report['status']
                report['status'] = 'cleanup-incomplete'
                cleanup_failed = True
        elif created:
            report['cleanup'] = 'retained by --keep'
        else:
            report['cleanup'] = 'no cluster resources created'
        advisor.write(output / 'result.json', report)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        if cleanup_failed:
            return 2


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--context', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--image', required=True,
                   help='approved image containing curl, sh, cat and BusyBox nc with -e')
    p.add_argument('--source', choices=['auto', 'agent', 'nodes', 'sidecar'], default='auto')
    p.add_argument('--agent-selector')
    p.add_argument('--agent-container')
    p.add_argument('--create-readers', action='store_true')
    p.add_argument('--reader-image', default='busybox:1.36')
    p.add_argument('--keep', action='store_true')
    return run(p.parse_args())


if __name__ == '__main__':
    sys.exit(main())
