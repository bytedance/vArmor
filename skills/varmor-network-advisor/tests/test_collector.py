# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import tempfile
import time
import subprocess
import sys
import unittest
from unittest.mock import patch

from test_advisor import advisor as a, event, state

c = a.collector_module()


def pod(uid, name='client', node='node-1'):
    return {'metadata': {'uid': uid, 'name': name,
                        'annotations': {'pod.networkproxy.security.beta.varmor.org': 'localhost/varmor-demo-learn'}},
            'spec': {'nodeName': node, 'containers': [{'name': 'varmor-network-proxy'}],
                     'volumes': [{'name': 'varmor-network-proxy-audit-als', 'hostPath': {'path': '/run/varmor'}}]}}


def raw_event(uid='pod-1', **changes):
    rec = event()
    rec.update(podUID=uid, eventTimestamp=int(time.time()))
    rec['event'].update(dstAddress='10.0.0.8:80', filterChain='http_chain', sni='')
    rec['event'].update(changes)
    return json.dumps(rec, ensure_ascii=False).encode() + b'\n'


class MemoryReader:
    def __init__(self, files=None):
        self.api = {'ingest': a.ingest}
        self.files = files or {}

    def manifest(self, endpoint):
        return {identity: {'path': path, 'size': len(raw)} for identity, (path, raw) in self.files.items()}

    def read(self, endpoint, path, offset, length):
        return next(raw[offset:offset + length] for _, (name, raw) in self.files.items() if name == path)


class IncrementalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.con = a.database(self.tmp.name)
        self.addCleanup(self.con.close)
        c.schema(self.con)
        self.state = state()
        self.endpoint = {'id': 'node/node-1'}
        self.path = '/var/log/varmor/violations.log'

    def scan(self, reader, budget=4 * 1024 * 1024, initialize=False):
        with self.con:
            return c.scan(self.con, self.state, reader, self.endpoint, budget, initialize)[0]

    def count(self):
        return self.con.execute('SELECT count(*) FROM events').fetchone()[0]

    def cursor(self, identity='1:1'):
        return json.loads(self.con.execute('SELECT value FROM cursors WHERE identity=?', (identity,)).fetchone()[0])

    def test_baseline_exclusion_even_for_events_after_epoch(self):
        self.state['baselinePodUIDs'] = ['old']
        self.state['podUIDs'] += ['old']
        reader = MemoryReader({'1:1': (self.path, raw_event('old') + raw_event())})
        stats = self.scan(reader)
        self.assertEqual(stats['baselinePodExcluded'], 1)
        self.assertEqual(self.count(), 1)

    def test_initial_tail_then_append_and_rotation_preserve_identical_events(self):
        record = raw_event()
        reader = MemoryReader({'1:1': (self.path, record)})
        self.scan(reader, initialize=True)
        self.assertEqual(self.count(), 0)
        reader.files['1:1'] = (self.path, record * 3)
        self.scan(reader)
        self.assertEqual(self.count(), 2)
        reader.files = {'1:1': ('/var/log/varmor/violations-old.log', record * 3), '1:2': (self.path, record)}
        self.scan(reader)
        self.scan(reader)
        self.assertEqual(self.count(), 3)
        self.assertEqual(c.health(self.con)['status'], 'no-detected-gap')

    def test_partial_utf8_and_query_do_not_enter_cursor_or_database(self):
        record = raw_event(path='/中文?token=secret-canary')
        reader = MemoryReader({'1:1': (self.path, record[:-2])})
        stats = self.scan(reader)
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.cursor()['offset'], 0)
        self.assertNotIn('secret-canary', str(self.cursor()))
        reader.files['1:1'] = (self.path, record)
        self.scan(reader)
        stored = self.con.execute('SELECT record FROM events').fetchone()[0]
        self.assertNotIn('secret-canary', stored)
        self.assertEqual(json.loads(stored)['event']['path'], '/中文')
        self.assertEqual(stats['backlogBytes'], len(record) - 2)

    def test_preflight_partial_old_line_is_discarded_when_completed(self):
        record = raw_event()
        reader = MemoryReader({'1:1': (self.path, record[:90])})
        self.scan(reader, initialize=True)
        reader.files['1:1'] = (self.path, record + record)
        self.scan(reader)
        self.assertEqual(self.count(), 1)

    def test_unread_file_disappearance_is_confirmed_source_gap(self):
        reader = MemoryReader({'1:1': (self.path, raw_event())})
        self.scan(reader, budget=0)
        size = self.cursor()['lastSize']
        reader.files = {}
        self.scan(reader)
        health = c.health(self.con)
        self.assertEqual(health['status'], 'confirmed-gap')
        self.assertEqual(health['issues'][0]['knownUnreadBytes'], size)
        self.assertIn('target event loss/count may be unknown', health['scope'])

    def test_fully_read_retained_file_expiry_is_normal(self):
        reader = MemoryReader({'1:1': ('/var/log/varmor/violations-old.log', raw_event())})
        self.scan(reader)
        reader.files = {}
        self.scan(reader)
        self.assertEqual(c.health(self.con)['status'], 'no-detected-gap')

    def test_active_inode_lost_at_eof_is_suspected_not_confirmed(self):
        reader = MemoryReader({'1:1': (self.path, raw_event())})
        self.scan(reader)
        reader.files = {'1:2': (self.path, b'')}
        self.scan(reader)
        self.assertEqual(c.health(self.con)['status'], 'suspected-gap')

    def test_copytruncate_and_regrowth_detected_by_anchor(self):
        reader = MemoryReader({'1:1': (self.path, raw_event(path='/old'))})
        self.scan(reader)
        generation = self.cursor()['generation']
        reader.files['1:1'] = (self.path, raw_event(path='/new-longer-path'))
        self.scan(reader)
        self.assertEqual(self.count(), 2)
        self.assertNotEqual(self.cursor()['generation'], generation)
        self.assertEqual(c.health(self.con)['status'], 'suspected-gap')

    def test_unknown_pod_waits_for_watch_identity_without_retaining_query(self):
        reader = MemoryReader({'1:1': (self.path, raw_event('short-lived', path='/request?token=private'))})
        self.scan(reader)
        self.assertEqual(self.count(), 0)
        self.assertEqual(c.health(self.con)['status'], 'identity-incomplete')
        stored = self.con.execute('SELECT record FROM pending_pods').fetchone()[0]
        self.assertNotIn('private', stored)
        c.register_pod(self.state, pod('short-lived'))
        with self.con:
            c.resolve_pending(self.con, self.state, {'ingest': a.ingest})
        self.assertEqual(self.count(), 1)
        self.assertEqual(c.health(self.con)['unresolvedPodEvents'], 0)
        self.assertEqual(self.state['podHistory']['short-lived']['node'], 'node-1')

    def test_events_and_offsets_rollback_as_one_transaction(self):
        reader = MemoryReader({'1:1': (self.path, raw_event())})
        with self.assertRaisesRegex(RuntimeError, 'interrupted'):
            with self.con:
                c.scan(self.con, self.state, reader, self.endpoint, 4096)
                raise RuntimeError('interrupted')
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.con.execute('SELECT count(*) FROM cursors').fetchone()[0], 0)
        self.scan(reader)
        self.assertEqual(self.count(), 1)

    def test_blank_lines_do_not_change_event_offset_identity(self):
        record = raw_event()
        reader = MemoryReader({'1:1': (self.path, b'\n' + record + b'\n' + record)})
        self.scan(reader)
        self.scan(reader)
        self.assertEqual(self.count(), 2)

    def test_oversized_incomplete_line_is_explicitly_accounted_for(self):
        reader = MemoryReader({'1:1': (self.path, b'x' * (c.MAX_LINE + 1))})
        self.scan(reader)
        health = c.health(self.con)
        self.assertEqual(health['status'], 'confirmed-gap')
        self.assertEqual(health['issues'][0]['kind'], 'oversized-line')
        reader.files['1:1'] = (self.path, b'x' * (c.MAX_LINE + 1) + b'\n' + raw_event())
        self.scan(reader)
        self.assertEqual(self.count(), 1)

    def test_manifest_rejects_injected_path_and_deduplicates_inode_alias(self):
        files = c.parse_manifest(self.path + '\t1:1 20\n/var/log/varmor/violations-old.log\t1:1 20', '/var/log/varmor')
        self.assertEqual(len(files), 1)
        self.assertEqual(files['1:1']['path'], self.path)
        with self.assertRaises(ValueError):
            c.parse_manifest('/tmp/private\t1:1 20', '/var/log/varmor')

    def test_sidecar_name_reuse_does_not_read_another_pods_logs(self):
        reader = c.Reader({'get': lambda *unused: {'metadata': {'uid': 'replacement'}}}, self.state)
        with self.assertRaisesRegex(RuntimeError, 'different UID'):
            reader.manifest({'id': 'pod/old', 'podUID': 'old', 'podName': 'client'})

    def test_delayed_watch_of_pre_epoch_pod_is_not_promoted_to_new_identity(self):
        self.state['observationEpoch'] = '2026-10-10T00:00:00+00:00'
        self.state['startedAt'] = 1791590400
        old = pod('late-old')
        old['metadata']['creationTimestamp'] = '2026-10-09T23:59:00Z'
        c.register_pod(self.state, old)
        self.assertIn('late-old', self.state['baselinePodUIDs'])
        self.assertNotIn('late-old', self.state['podUIDs'])

    def test_real_shell_batch_protocol_handles_block_boundaries_and_rotation(self):
        root = Path(self.tmp.name)
        tools = root / 'tools'
        tools.mkdir()
        stat = tools / 'stat'
        stat.write_text('#!' + sys.executable + '\nimport os,sys\ns=os.stat(sys.argv[-1])\nprint(str(s.st_dev)+":"+str(s.st_ino)+" "+str(s.st_size))\n')
        stat.chmod(0o755)
        logs = root / 'logs with spaces'
        logs.mkdir()
        active = logs / 'violations.log'
        active.write_bytes(b'x' * (c.BLOCK + 9) + b'\n')
        calls = []

        def local_kube(context, *args, binary=False):
            command = args[args.index('--') + 1:]
            calls.append(command)
            result = subprocess.run(command, capture_output=True, check=True,
                env={**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH']})
            return result.stdout if binary else result.stdout.decode()

        reader = c.Reader({'kube': local_kube, 'ingest': a.ingest}, self.state)
        endpoint = {'id': 'node/local', 'directory': str(logs), 'prefix': ['exec', '-n', 'test', 'fake']}
        with self.con:
            errors, grants = c.prefetch(self.con, reader, [endpoint], 0, initialize=True)
            self.assertFalse(errors)
            c.scan(self.con, self.state, reader, endpoint, 0, initialize=True)
        self.assertEqual(len(calls), 1)  # Metadata and anchor in a single remote command.
        active.write_bytes(active.read_bytes() + raw_event() * 2)
        with self.con:
            errors, grants = c.prefetch(self.con, reader, [endpoint], 4 * 1024 * 1024)
            self.assertFalse(errors)
            c.scan(self.con, self.state, reader, endpoint, grants[endpoint['id']])
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.count(), 2)
        active.rename(logs / 'violations-old.log')
        active.write_bytes(raw_event())
        with self.con:
            errors, grants = c.prefetch(self.con, reader, [endpoint], 4 * 1024 * 1024)
            self.assertFalse(errors)
            c.scan(self.con, self.state, reader, endpoint, grants[endpoint['id']])
        self.assertEqual(self.count(), 3)
        self.assertEqual(c.health(self.con)['status'], 'no-detected-gap')

    def test_snapshot_transport_failure_retries_in_chunks_without_cluster_mutation(self):
        record = raw_event()
        reader = MemoryReader({'1:1': (self.path, record)})
        args = a.parser().parse_args(['collect', '--session', '/unused', '--source', 'sidecar'])
        target = pod('pod-1')
        target['metadata']['name'] = 'client'
        with patch.object(a, 'kube', side_effect=RuntimeError('error reading from error stream: read message: nil')), \
             patch.object(c, 'Reader', return_value=reader), patch.object(a, 'collector_module', return_value=c):
            streams = a.sources(self.state, args, [target])
        self.assertEqual(json.loads(streams[0][1])['podUID'], 'pod-1')
        reader.files = {}
        with patch.object(a, 'kube', side_effect=RuntimeError('error reading from error stream')), \
             patch.object(c, 'Reader', return_value=reader), patch.object(a, 'collector_module', return_value=c), \
             self.assertRaisesRegex(RuntimeError, 'do not interpret this as no events'):
            a.sources(self.state, args, [target])


class MonitorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', str(self.root), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
        self.policy = a.load(self.root / 'observe.yaml')
        self.policy['metadata']['uid'] = 'policy-uid'
        self.policy['status'] = {'ready': True}
        self.reader = MemoryReader({'1:1': ('/var/log/varmor/violations.log', b'')})
        self.arguments = a.parser().parse_args(['monitor', '--session', str(self.root), '--duration', '1',
                                               '--interval', '1', '--analysis-interval', '1'])
        self.stop_after_handoff = False
        self.handoff_action = None
        self.change_policy = False
        test = self

        class Watch:
            def __init__(self, *unused):
                self.delivered = False
                self.deadline = unused[-1]

            def start(self):
                pass

            def close(self):
                pass

            def drain(self):
                path = test.root / 'collector.json'
                if not self.delivered and path.exists() and a.load(path).get('phase') in ('ready', 'observing'):
                    self.delivered = True
                    test.reader.files['1:1'] = ('/var/log/varmor/violations.log', raw_event('old') + raw_event('short-lived'))
                    if test.stop_after_handoff:
                        a.write(test.root / 'stop-request.json', {})
                    if test.handoff_action:
                        test.handoff_action()
                    return [('pod', pod('short-lived', 'already-deleted'))]
                return []

        self.Watch = Watch

    def get(self, context, resource, namespace=None, name=None):
        if resource == 'varmorpolicies':
            if self.change_policy and (self.root / 'collector.json').exists() and a.load(self.root / 'collector.json').get('phase') == 'ready':
                result = json.loads(json.dumps(self.policy))
                a.network_rules(result['spec']['policy'])['egress']['defaultAction'] = 'deny'
                return result
            return self.policy
        return {'metadata': {'resourceVersion': '100'}, 'items': [pod('old')]}

    def kube(self, context, *args, **unused):
        if args[:3] == ('auth', 'can-i', 'watch'):
            return 'yes'
        return json.dumps({'items': [{'metadata': {'name': 'agent'}, 'spec': {'nodeName': 'node-1',
                           'containers': [{'name': 'agent', 'command': ['/varmor', '--agent']}]}}]})

    def run_monitor(self):
        api = {**vars(a), 'get': self.get, 'kube': self.kube}
        with patch.object(a, 'get', self.get), patch.object(c, 'PodWatch', self.Watch), \
             patch.object(c, 'Reader', lambda api, state: self.reader), contextlib.redirect_stdout(io.StringIO()):
            return c.monitor(self.arguments, api)

    def test_bounded_handoff_excludes_old_pod_and_captures_deleted_new_pod(self):
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        session = a.load(self.root / 'session.json')
        report = a.load(self.root / 'analysis.json')
        self.assertEqual(progress['stopReason'], 'deadline')
        self.assertEqual(session['baselinePodUIDs'], ['old'])
        self.assertEqual(session['podUIDs'], ['short-lived'])
        self.assertEqual(report['events'], 1)
        self.assertEqual(report['baselinePodExcluded'], 1)
        self.assertEqual(report['collectionHealth']['status'], 'no-detected-gap')
        self.assertEqual(report['observation']['phase'], 'stopped')
        self.assertFalse(a.load(self.root / 'candidate.yaml')['spec']['updateExistingWorkloads'])

    def test_user_stop_leaves_policy_and_fixed_deadline_unchanged(self):
        self.arguments.duration = 10
        self.stop_after_handoff = True
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertEqual(progress['stopReason'], 'user-stop')
        self.assertLess(progress['elapsedSeconds'], 5)
        self.assertEqual(a.load(self.root / 'observe.yaml')['spec'], self.policy['spec'])

    def test_running_collector_shortens_deadline_without_resetting_evidence(self):
        self.arguments.duration = 30
        self.handoff_action = lambda: c.reschedule(a.parser().parse_args(
            ['reschedule', '--session', str(self.root), '--duration', '1']), vars(a))
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertLess(progress['elapsedSeconds'], 5)
        self.assertEqual(progress['stopReason'], 'deadline')
        self.assertEqual(progress['lastDeadlineChange']['status'], 'applied')
        self.assertEqual(a.load(self.root / 'analysis.json')['events'], 1)
        self.assertEqual(a.load(self.root / 'session.json')['baselinePodUIDs'], ['old'])
        self.assertEqual(a.load(self.root / 'observe.yaml')['spec'], self.policy['spec'])

    def test_running_collector_extends_beyond_original_deadline(self):
        self.handoff_action = lambda: c.reschedule(a.parser().parse_args(
            ['reschedule', '--session', str(self.root), '--duration', '2']), vars(a))
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertGreater(progress['elapsedSeconds'], 1.8)
        self.assertEqual(progress['stopReason'], 'deadline')
        self.assertEqual(progress['lastDeadlineChange']['status'], 'applied')
        self.assertEqual(a.load(self.root / 'analysis.json')['observation']['plan'], progress['plan'])
        self.assertEqual(progress['collectionHealth']['status'], 'no-detected-gap')

    def test_stop_takes_priority_over_pending_extension(self):
        self.arguments.duration = 30

        def change_then_stop():
            c.reschedule(a.parser().parse_args(['reschedule', '--session', str(self.root), '--duration', '60']), vars(a))
            c.stop(a.parser().parse_args(['stop', '--session', str(self.root)]), vars(a))

        self.handoff_action = change_then_stop
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertEqual(progress['stopReason'], 'user-stop')
        self.assertEqual(progress['lastDeadlineChange']['status'], 'rejected')
        self.assertNotIn('planRevision', progress)
        self.assertLess(progress['elapsedSeconds'], 5)

    def test_policy_change_ends_observation_with_failure_report(self):
        self.change_policy = True
        self.assertEqual(self.run_monitor(), 2)
        progress = a.load(self.root / 'collector.json')
        self.assertEqual(progress['stopReason'], 'failure')
        self.assertIn('Live policy differs', progress['error'])
        self.assertEqual(progress['collectionHealth']['status'], 'suspected-gap')

    def test_storage_threshold_stops_without_deleting_evidence(self):
        self.arguments.max_session_mb = 1
        marker = self.root / 'keep-evidence'
        marker.write_bytes(b'x' * 1024 * 1024)
        self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(a.load(self.root / 'collector.json')['stopReason'], 'storage-limit')
        self.assertTrue(marker.exists())

    def test_busy_collector_cannot_overwrite_progress(self):
        a.write(self.root / 'collector.json', {'phase': 'observing', 'processId': 'existing'})
        lease = self.root / '.collector.lock'
        lease.mkdir()
        with a.locked(lease), self.assertRaisesRegex(RuntimeError, 'busy'):
            self.run_monitor()
        self.assertEqual(a.load(self.root / 'collector.json')['processId'], 'existing')

    def test_invalid_or_ended_deadline_does_not_contact_cluster(self):
        self.arguments.until = '2020-01-01T00:00:00+08:00'
        self.assertEqual(self.run_monitor(), 2)
        self.assertFalse((self.root / 'collector.json').exists())
        self.arguments.until = '2030-01-01T00:00:00'
        with self.assertRaises(ValueError):
            c.plan(self.arguments)

    def test_default_plan_is_bounded_and_recovery_preserves_settings(self):
        self.arguments.duration = None
        planned = c.plan(self.arguments)
        self.assertEqual(planned['intervalSeconds'], 1)
        self.assertLessEqual((dt.datetime.fromisoformat(planned['until']) - dt.datetime.now(dt.timezone.utc)).total_seconds(), 3600)
        self.arguments.until = '2030-01-01T00:00:00+08:00'
        self.assertIs(c.plan(self.arguments, planned), planned)

    def test_crash_recovery_does_not_reset_baseline_or_extend_deadline(self):
        initial = a.load(self.root / 'session.json')
        initial.update(collectionMode='live-incremental', baselinePodUIDs=['old'], podUIDs=[], podHistory={})
        a.write(self.root / 'session.json', initial)
        original = c.plan(self.arguments)
        a.write(self.root / 'collector.json', {'phase': 'observing', 'readyAt': a.now(),
            'startedAt': a.now(), 'plan': original, 'lastSuccessfulCollection': a.now()})
        self.arguments.duration = 600
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertEqual(progress['plan'], original)
        self.assertEqual(a.load(self.root / 'session.json')['baselinePodUIDs'], ['old'])
        self.assertEqual(progress['collectionHealth']['status'], 'suspected-gap')
        self.assertIn('collector-restarted', [g['kind'] for g in progress['collectionHealth']['issues']])

    def test_expired_recovery_performs_only_local_finalization(self):
        initial = a.load(self.root / 'session.json')
        initial.update(collectionMode='live-incremental', baselinePodUIDs=['old'])
        a.write(self.root / 'session.json', initial)
        original = c.plan(self.arguments)
        original['until'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        a.write(self.root / 'collector.json', {'phase': 'observing', 'readyAt': a.now(),
            'startedAt': a.now(), 'plan': original})
        with patch.object(self, 'get', side_effect=AssertionError('No cluster reads after deadline')):
            self.assertEqual(self.run_monitor(), 0)
        self.assertEqual(a.load(self.root / 'collector.json')['stopReason'], 'deadline')
        self.assertEqual(a.load(self.root / 'analysis.json')['observation']['phase'], 'stopped')

    def test_recovery_rejects_unacknowledged_extension(self):
        initial = a.load(self.root / 'session.json')
        initial.update(collectionMode='live-incremental', baselinePodUIDs=['old'], podUIDs=[], podHistory={})
        a.write(self.root / 'session.json', initial)
        original = c.plan(self.arguments)
        a.write(self.root / 'collector.json', {'phase': 'observing', 'readyAt': a.now(),
            'startedAt': a.now(), 'plan': original})
        a.write(self.root / 'deadline-request.json', {'requestId': 'pending-before-crash', 'requestedAt': a.now(),
            'until': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)).isoformat(),
            'expectedRevision': 0, 'requestedReason': 'Extend'})
        self.assertEqual(self.run_monitor(), 0)
        progress = a.load(self.root / 'collector.json')
        self.assertEqual(progress['plan'], original)
        self.assertEqual(progress['lastDeadlineChange']['status'], 'rejected')
        self.assertIn('restarted', progress['lastDeadlineChange']['reason'])

    def test_kubernetes_reads_use_remaining_deadline_and_binary_output(self):
        original = a.KUBE_DEADLINE
        self.addCleanup(setattr, a, 'KUBE_DEADLINE', original)
        a.KUBE_DEADLINE = time.monotonic() + 0.5
        with patch.object(a.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, b'bytes', b'')) as call:
            self.assertEqual(a.kube('test', 'exec', binary=True), b'bytes')
            self.assertLessEqual(call.call_args.kwargs['timeout'], 0.5)
        a.KUBE_DEADLINE = time.monotonic() - 1
        with patch.object(a.subprocess, 'run') as call, self.assertRaises(TimeoutError):
            a.kube('test', 'get', 'pods')
        call.assert_not_called()


class DeadlineControlTests(unittest.TestCase):
    def test_pending_extension_cannot_revive_expired_absolute_window(self):
        self.progress['plan']['until'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        a.write(self.root / 'deadline-request.json', {'requestId': 'before-suspension', 'requestedAt': a.now(),
            'until': (dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=60)).isoformat(),
            'expectedRevision': 0, 'requestedReason': 'Requested before suspension'})
        self.assertFalse(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertEqual(self.progress['lastDeadlineChange']['status'], 'rejected')
        self.assertIn('Original deadline', self.progress['lastDeadlineChange']['reason'])

    def setUp(self):
        self.addCleanup(setattr, a, 'KUBE_WALL_DEADLINE', a.KUBE_WALL_DEADLINE)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        args = a.parser().parse_args(['monitor', '--session', str(self.root), '--duration', '30'])
        self.progress = {'phase': 'observing', 'plan': c.plan(args)}
        a.write(self.root / 'collector.json', self.progress)
        self.api = vars(a)
        self.lease = self.root / '.collector.lock'
        self.lease.mkdir()
        previous = a.KUBE_DEADLINE
        self.addCleanup(setattr, a, 'KUBE_DEADLINE', previous)
        a.KUBE_DEADLINE = time.monotonic() + 30
        self.watch = type('Watch', (), {'deadline': a.KUBE_DEADLINE})()

    def request(self, *options):
        args = a.parser().parse_args(['reschedule', '--session', str(self.root), *options])
        out = io.StringIO()
        with a.locked(self.lease), contextlib.redirect_stdout(out):
            self.assertEqual(c.reschedule(args, self.api), 0)
        return json.loads(out.getvalue())

    def test_submission_is_not_application_and_shorten_updates_watch(self):
        original = a.load(self.root / 'collector.json')
        receipt = self.request('--duration', '10', '--reason', 'User asked to shorten')
        self.assertEqual(receipt['status'], 'deadline-change-requested')
        self.assertEqual(a.load(self.root / 'collector.json'), original)
        self.assertTrue(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        applied = a.load(self.root / 'collector.json')
        self.assertEqual(applied['lastDeadlineChange']['requestId'], receipt['requestId'])
        self.assertEqual(applied['lastDeadlineChange']['status'], 'applied')
        self.assertEqual(applied['lastDeadlineChange']['previousUntil'], original['plan']['until'])
        self.assertEqual(applied['plan']['until'], receipt['until'])
        self.assertEqual(applied['planRevision'], 1)
        self.assertLessEqual(a.KUBE_DEADLINE - time.monotonic(), 10)
        self.assertEqual(self.watch.deadline, a.KUBE_DEADLINE)
        for key in original['plan'].keys() - {'until'}:
            self.assertEqual(applied['plan'][key], original['plan'][key])
        self.assertFalse(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertEqual(len(self.progress['deadlineChanges']), 1)

    def test_extend_uses_request_time_and_preserves_other_settings(self):
        original = a.KUBE_DEADLINE
        receipt = self.request('--duration', '120')
        self.assertLessEqual((dt.datetime.fromisoformat(receipt['until']) - dt.datetime.now(dt.timezone.utc)).total_seconds(), 120)
        self.assertTrue(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertGreater(a.KUBE_DEADLINE, original + 80)

    def test_pending_request_cannot_be_overwritten_then_second_can_apply(self):
        first = self.request('--duration', '10')
        with self.assertRaisesRegex(ValueError, 'pending'):
            self.request('--duration', '20')
        self.assertEqual(a.load(self.root / 'deadline-request.json')['requestId'], first['requestId'])
        c.apply_deadline_request(self.api, self.root, self.progress, self.watch)
        second = self.request('--duration', '20')
        c.apply_deadline_request(self.api, self.root, self.progress, self.watch)
        self.assertEqual(self.progress['planRevision'], 2)
        self.assertEqual(self.progress['lastDeadlineChange']['requestId'], second['requestId'])
        self.assertEqual(len(self.progress['deadlineChanges']), 2)

    def test_extension_acknowledgement_after_original_deadline_is_rejected(self):
        self.request('--duration', '120')
        a.KUBE_DEADLINE = time.monotonic() - 1
        original = a.KUBE_DEADLINE
        self.assertFalse(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertEqual(self.progress['lastDeadlineChange']['status'], 'rejected')
        self.assertEqual(a.KUBE_DEADLINE, original)
        self.assertNotIn('planRevision', self.progress)

    def test_short_deadline_elapsed_during_round_stops_after_acknowledgement(self):
        self.request('--duration', '1')
        time.sleep(1.05)
        self.assertTrue(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertLessEqual(a.KUBE_DEADLINE, time.monotonic())
        with patch.object(a.subprocess, 'run') as execute, self.assertRaises(TimeoutError):
            a.kube('test', 'get', 'pods')
        execute.assert_not_called()

    def test_stale_revision_is_rejected(self):
        self.request('--duration', '120')
        self.progress['planRevision'] = 1
        self.assertFalse(c.apply_deadline_request(self.api, self.root, self.progress, self.watch))
        self.assertEqual(self.progress['lastDeadlineChange']['status'], 'rejected')
        self.assertIn('plan changed', self.progress['lastDeadlineChange']['reason'])

    def test_dead_ended_initializing_or_stopping_collector_cannot_be_rescheduled(self):
        with self.assertRaisesRegex(ValueError, 'not running'), contextlib.redirect_stdout(io.StringIO()):
            c.reschedule(a.parser().parse_args(['reschedule', '--session', str(self.root), '--duration', '10']), self.api)
        for phase in ('initializing', 'stopped'):
            self.progress['phase'] = phase
            a.write(self.root / 'collector.json', self.progress)
            with self.subTest(phase=phase), self.assertRaisesRegex(ValueError, 'running, ready'):
                self.request('--duration', '10')
        self.progress['phase'] = 'observing'
        a.write(self.root / 'collector.json', self.progress)
        a.write(self.root / 'stop-request.json', {})
        with self.assertRaisesRegex(ValueError, 'stopping'):
            self.request('--duration', '10')
        self.assertFalse((self.root / 'deadline-request.json').exists())

    def test_expired_plan_or_invalid_requested_time_does_not_create_request(self):
        for options in [('--until', '2030-01-01T00:00:00'), ('--until', '2020-01-01T00:00:00+08:00'),
                        ('--duration', '0'), ('--duration', '-1'), ('--duration', str(10**30))]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.request(*options)
        self.progress['plan']['until'] = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1)).isoformat()
        a.write(self.root / 'collector.json', self.progress)
        with self.assertRaisesRegex(ValueError, 'already reached'):
            self.request('--duration', '10')
        self.assertFalse((self.root / 'deadline-request.json').exists())


if __name__ == '__main__':
    unittest.main()
