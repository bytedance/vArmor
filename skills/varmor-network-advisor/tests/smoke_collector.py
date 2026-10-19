#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Maintainer-owned collector test: Pod evidence and acknowledged live deadline changes."""
import argparse
import contextlib
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
import uuid

from smoke_cluster import advisor as a, workload, SERVER, SCRIPT


def wait_for(predicate, seconds, message, process=None):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if predicate():
            return
        if process and process.poll() is not None:
            raise RuntimeError('Collector exited before ' + message)
        time.sleep(0.5)
    raise RuntimeError('Timed out waiting for ' + message)


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    session = output / 'session'
    if session.exists():
        raise ValueError('Use a fresh output directory')
    ns = 'np-advisor-collector-' + uuid.uuid4().hex[:8]
    report = {'context': args.context, 'namespace': ns, 'image': args.image, 'status': 'running',
              'scope': 'owned-live-collector', 'limitations': ['No shared Agent log mutation; rotation/loss injection is covered by local regression tests.']}
    process, created = None, False
    try:
        a.kube(args.context, 'create', 'namespace', ns)
        created = True
        a.observe(a.parser().parse_args(['observe', '--session', str(session), '--context', args.context,
            '--namespace', ns, '--name', 'observe-client', '--kind', 'Pod', '--selector', 'app=client']))
        a.kube(args.context, 'apply', '--dry-run=server', '-f', str(session / 'observe.yaml'))
        a.kube(args.context, 'apply', '-f', str(session / 'observe.yaml'))
        a.kube(args.context, 'wait', '-n', ns, '--for=condition=Ready', 'varmorpolicy/observe-client', '--timeout=60s')
        backend = workload(ns, 'backend', args.image, ['sh', '-c', SERVER])
        old = workload(ns, 'client', args.image, ['sleep', '3600'])
        service = {'apiVersion': 'v1', 'kind': 'Service', 'metadata': {'name': 'backend', 'namespace': ns},
                   'spec': {'selector': {'app': 'backend'}, 'ports': [{'port': 8080, 'targetPort': 8080}]}}
        a.write(output / 'fixtures.yaml', {'apiVersion': 'v1', 'kind': 'List', 'items': [backend, service, old]})
        a.kube(args.context, 'apply', '-f', str(output / 'fixtures.yaml'))
        for name in ('backend', 'client'):
            a.kube(args.context, 'rollout', 'status', '-n', ns, 'deploy/' + name, '--timeout=60s')
        state = a.load(session / 'session.json')
        pods, _ = a.live_inventory(state, a.load(session / 'observe.yaml'))
        old_pod = pods[0]
        with open(output / 'collector-output.log', 'w') as logfile:
            process = subprocess.Popen([sys.executable, str(SCRIPT), 'monitor', '--session', str(session),
                '--duration', '240', '--interval', '2', '--discovery-interval', '1', '--analysis-interval', '60'],
                stdout=logfile, stderr=subprocess.STDOUT)
            progress = session / 'collector.json'
            wait_for(lambda: progress.exists() and a.load(progress).get('phase') in ('ready', 'observing'),
                     90, 'collector readiness', process)
            initial_progress = a.load(progress)

            def reschedule(seconds, reason):
                result = subprocess.run([sys.executable, str(SCRIPT), 'reschedule', '--session', str(session),
                    '--duration', str(seconds), '--reason', reason], capture_output=True, text=True, timeout=40)
                if result.returncode:
                    raise RuntimeError('Deadline change submission failed: ' + result.stderr)
                receipt = json.loads(result.stdout)
                wait_for(lambda: a.load(progress).get('lastDeadlineChange', {}).get('requestId') == receipt['requestId'],
                         45, 'deadline change acknowledgement', process)
                accepted = a.load(progress)
                if accepted['lastDeadlineChange']['status'] != 'applied' or accepted['plan']['until'] != receipt['until']:
                    raise RuntimeError('Collector rejected deadline change')
                if accepted['processId'] != initial_progress['processId'] or accepted['readyAt'] != initial_progress['readyAt']:
                    raise RuntimeError('Deadline change restarted or reset the collector')
                return accepted

            extended = reschedule(300, 'Maintainer fixture requested a longer observation window')
            if extended['plan']['until'] <= initial_progress['plan']['until']:
                raise RuntimeError('Fixture did not extend the observation deadline')
            hostname = 'backend.' + ns + '.svc.cluster.local'

            def request(pod_name, path):
                return a.kube(args.context, 'exec', '-n', ns, pod_name, '-c', 'app', '--',
                    'curl', '--noproxy', '*', '-fsS', '--max-time', '8', 'http://' + hostname + ':8080' + path)

            request(old_pod['metadata']['name'], '/old-after-ready')
            new = workload(ns, 'client', args.image, ['sh', '-c',
                'curl --noproxy "*" -fsS --retry 4 --retry-all-errors --retry-delay 1 --max-time 8 http://' + hostname + ':8080/startup-new || exit 1; exec sleep 3600'])
            a.write(output / 'new-client.yaml', new)
            a.kube(args.context, 'apply', '-f', str(output / 'new-client.yaml'))
            a.kube(args.context, 'rollout', 'status', '-n', ns, 'deploy/client', '--timeout=60s')
            pods = a.get(args.context, 'pods', ns)['items']
            new_pod = next(p for p in pods if p['metadata'].get('labels', {}).get('app') == 'client'
                           and p['metadata']['uid'] != old_pod['metadata']['uid'])
            request(new_pod['metadata']['name'], '/business-new')
            short = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'name': 'short-client', 'namespace': ns,
                'labels': {'app': 'client', 'sandbox.varmor.org/enable': 'true'}},
                'spec': {'restartPolicy': 'Never', 'automountServiceAccountToken': False,
                    'containers': [{'name': 'app', 'image': args.image, 'command': ['sh', '-c',
                        'curl --noproxy "*" -fsS --retry 4 --retry-all-errors --retry-delay 1 --max-time 8 http://' + hostname + ':8080/short-lived || exit 1; sleep 3']}]}}
            a.write(output / 'short-client.yaml', short)
            a.kube(args.context, 'apply', '-f', str(output / 'short-client.yaml'))
            wait_for(lambda: any(cs.get('state', {}).get('terminated') is not None for cs in
                a.get(args.context, 'pods', ns, 'short-client').get('status', {}).get('containerStatuses', [])
                if cs['name'] == 'app'), 60, 'short application completion', process)
            short_uid = a.get(args.context, 'pods', ns, 'short-client')['metadata']['uid']
            short_status = a.get(args.context, 'pods', ns, 'short-client')['status']
            if next(cs['state']['terminated']['exitCode'] for cs in short_status['containerStatuses'] if cs['name'] == 'app') != 0:
                raise RuntimeError('Short-lived fixture request failed; no collector coverage claim')
            backend_hits = a.kube(args.context, 'exec', '-n', ns, 'deploy/backend', '-c', 'app', '--', 'cat', '/tmp/hits.tsv')
            (output / 'backend.log').write_text(backend_hits)
            if not all(path in backend_hits for path in ('/old-after-ready', '/startup-new', '/business-new', '/short-lived')):
                raise RuntimeError('Expected fixture traffic did not reach backend')
            a.kube(args.context, 'delete', 'pod', '-n', ns, 'short-client', '--wait=false')

            def audits_arrived():
                if not (session / 'events.sqlite').exists():
                    return False
                with contextlib.closing(sqlite3.connect(session / 'events.sqlite')) as con:
                    paths = {json.loads(row[0])['event'].get('path') for row in con.execute('SELECT record FROM events')}
                return {'/startup-new', '/business-new', '/short-lived'} <= paths

            wait_for(audits_arrived, 90, 'startup/business/deleted Pod audit evidence', process)
            shortened = reschedule(10, 'Maintainer fixture requested an earlier end after evidence arrived')
            if shortened['plan']['until'] >= extended['plan']['until']:
                raise RuntimeError('Fixture did not shorten the observation deadline')
            code = process.wait(timeout=60)
            if code:
                raise RuntimeError('Collector exited with ' + str(code))
        report['analysis'] = a.load(session / 'analysis.json')
        report['collector'] = a.load(session / 'collector.json')
        state = a.load(session / 'session.json')
        paths = {row['path'] for row in report['analysis']['inventory']}
        if '/old-after-ready' in paths or report['analysis']['baselinePodExcluded'] < 1:
            raise RuntimeError('Old Pod audit exclusion did not work')
        if old_pod['metadata']['uid'] not in state['baselinePodUIDs'] or short_uid not in state['podUIDs']:
            raise RuntimeError('Baseline/deleted Pod identities were not persisted')
        if report['collector']['stopReason'] != 'deadline' or report['collector'].get('planRevision') != 2:
            raise RuntimeError('Revised deadline was not honored')
        if [change['status'] for change in report['collector'].get('deadlineChanges', [])] != ['applied', 'applied']:
            raise RuntimeError('Expected both deadline changes to be acknowledged')
        if report['collector']['collectionHealth']['status'] != 'no-detected-gap':
            raise RuntimeError('Collector reported a gap; inspect evidence instead of claiming complete validation')
        report.update(status='passed', oldPodUID=old_pod['metadata']['uid'],
                      newPodUID=new_pod['metadata']['uid'], deletedPodUID=short_uid)
        return 0
    except (RuntimeError, ValueError, OSError, KeyError, subprocess.TimeoutExpired) as exc:
        report.update(status='blocked-or-failed', error=str(exc))
        return 2
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        if created:
            try:
                a.kube(args.context, 'delete', 'namespace', ns, '--wait=false')
                a.kube(args.context, 'wait', '--for=delete', 'namespace/' + ns, '--timeout=45s')
                report['cleanup'] = 'owned namespace deletion confirmed'
            except Exception as exc:
                report.update(testStatus=report['status'], status='cleanup-incomplete', cleanupError=str(exc))
        a.write(output / 'result.json', report)
        print(json.dumps(report, ensure_ascii=False, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--context', required=True)
    parser.add_argument('--image', required=True, help='user-approved curl image with sh and BusyBox nc')
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    code = run(args)
    return 2 if a.load(Path(args.output) / 'result.json')['status'] != 'passed' else code


if __name__ == '__main__':
    sys.exit(main())
