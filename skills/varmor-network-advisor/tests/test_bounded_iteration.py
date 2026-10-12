# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_advisor import advisor as a, event, state
from test_collector import c, MemoryReader, pod
from test_optimization import v


KUBE_DEADLINE = None


class ResourceTests(unittest.TestCase):
    def test_rolling_quota_persists_across_phases_and_does_not_refill_early(self):
        with tempfile.TemporaryDirectory() as folder:
            t = [100.0]
            ledger = Path(folder) / 'usage.json'
            budget = c.ResourceBudget(8192, ledger, vars(a), clock=lambda: t[0])
            key, size = budget.reserve(20000, time.monotonic() + 1)
            self.assertEqual(size, 8192)
            budget.finish(key, 8192)
            resumed = c.ResourceBudget(8192, ledger, vars(a), clock=lambda: t[0])
            with self.assertRaises(c.ResourceLimit):
                resumed.reserve(4096, time.monotonic() + 1)
            t[0] = 159
            with self.assertRaises(c.ResourceLimit):
                resumed.reserve(4096, time.monotonic() + 1)
            t[0] = 160
            key, _ = resumed.reserve(4096, time.monotonic() + 1)
            resumed.finish(key)  # Unknown failed transfer is charged conservatively.
            self.assertEqual(resumed.snapshot()['windowBytes'], 4096)
            self.assertEqual(resumed.snapshot()['totalBytes'], 12288)

    def test_real_shell_includes_overlap_and_framing_in_transport_cap(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); tools = root/'tools'; tools.mkdir()
            stat = tools/'stat'
            stat.write_text('#!' + sys.executable + '\nimport os,sys\ns=os.stat(sys.argv[-1]);print(str(s.st_dev)+":"+str(s.st_ino)+" "+str(s.st_size))\n')
            stat.chmod(0o755)
            logs = root/'logs'; logs.mkdir(); active = logs/'violations.log'
            active.write_bytes(b'old\n')
            transferred = []
            def local_kube(context, *args, binary=False):
                command = args[args.index('--')+1:]
                r = subprocess.run(command, capture_output=True, check=True,
                    env={**os.environ, 'PATH': str(tools) + os.pathsep + os.environ['PATH']})
                transferred.append(len(r.stdout))
                return r.stdout if binary else r.stdout.decode()
            s = state(); s['startedAt'] = 100
            reader = c.Reader({'kube': local_kube, 'ingest': a.ingest}, s)
            reader.resource_budget = c.ResourceBudget(8192)
            endpoint = {'id': 'node/one', 'directory': str(logs), 'prefix': []}
            (root/'db').mkdir()
            # Local test paths must still be validated by the batch manifest.
            with contextlib.closing(a.database(root/'db')) as con, con:
                c.schema(con)
                errors, grants = c.prefetch(con, reader, [endpoint], 0, True)
                self.assertEqual(errors, {})
                c.scan(con, s, reader, endpoint, 0, True)
                active.write_bytes(b'old\n' + (json.dumps(event()).encode()+b'\n')*100)
                errors, grants = c.prefetch(con, reader, [endpoint], 2*1024*1024)
                self.assertEqual(errors, {})
                stats, _ = c.scan(con, s, reader, endpoint, grants[endpoint['id']])
                self.assertGreater(stats['newEvents'], 0)
                self.assertGreater(stats['backlogBytes'], 0)
                before = len(transferred)
                errors, _ = c.prefetch(con, reader, [endpoint], 2*1024*1024)
                self.assertIsInstance(errors[endpoint['id']], c.ResourceLimit)
                self.assertEqual(len(transferred), before)
                self.assertLessEqual(sum(transferred), 8192)
                self.assertEqual(c.health(con)['status'], 'no-detected-gap')

    def test_invalid_caps_and_backlog_floor(self):
        args = a.parser().parse_args(['monitor', '--session', '/tmp/not-read', '--duration', '60'])
        plan = c.plan(args)
        self.assertEqual(plan['minIntervalSeconds'], 5)
        self.assertEqual(plan['maxConcurrentReads'], 2)
        for name, value in [('min_interval', 0), ('max_transfer_mb_per_minute', float('nan')),
                            ('max_concurrent_reads', 0), ('max_round_seconds', 121)]:
            bad = copy.copy(args); setattr(bad, name, value)
            with self.subTest(name=name), self.assertRaises(ValueError): c.plan(bad)


    def test_failed_bounded_initialization_cannot_fall_back_to_unbounded_collect(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'obs'
            with contextlib.redirect_stdout(io.StringIO()):
                a.observe(a.parser().parse_args(['observe', '--session', str(root), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
            a.write(root/'collector.json', {'phase': 'stopped', 'stopReason': 'failure',
                'plan': {'maxTransferMiBPerMinute': 0.125}})
            args = a.parser().parse_args(['collect', '--session', str(root)])
            with patch.object(a, 'kube') as kube, self.assertRaisesRegex(ValueError, 'resource limits'):
                a.collect(args)
            kube.assert_not_called()

    def test_round_timeout_is_failure_before_the_phase_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)/'obs'
            with contextlib.redirect_stdout(io.StringIO()):
                a.observe(a.parser().parse_args(['observe', '--session', str(root), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
            def timed_inventory(*args, **kwargs):
                time.sleep(1.05)
                raise subprocess.TimeoutExpired('kubectl inventory', 1)
            args = a.parser().parse_args(['monitor', '--session', str(root), '--duration', '4',
                '--max-round-seconds', '1'])
            with patch.object(a, 'live_inventory', timed_inventory), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(a.monitor(args), 2)
            progress = a.load(root/'collector.json')
            self.assertEqual(progress['stopReason'], 'failure')
            self.assertIn('timed out', progress['error'])

    def test_stop_does_not_claim_policy_mode_or_rollback(self):
        with tempfile.TemporaryDirectory() as folder:
            a.write(Path(folder)/'collector.json', {'phase': 'observing'})
            args = a.parser().parse_args(['stop', '--session', folder])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(a.stop(args), 0)
            self.assertIn('does not change', json.loads(out.getvalue())['note'])


class IterationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'obs'
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', str(self.root), '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--mitm-domain', 'api.example.com']))
        self.s = state(); self.s['policyUID'] = 'policy-1'
        a.write(self.root/'session.json', self.s)
        with contextlib.closing(a.database(self.root)) as con, con:
            a.ingest(con, self.s, [('source', json.dumps(event()))])
        self.analyze()
        self.observed_db = (self.root/'events.sqlite').read_bytes()
        self.r = a.refinement_module()

    def analyze(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return a.analyze(a.parser().parse_args(['analyze', '--session', str(self.root)]))

    def receipt(self, rec):
        root = Path(self.tmp.name)/'verify'; root.mkdir(exist_ok=True)
        data = [rec]
        report = {'kind': 'NetworkProxyVerification', 'observationSession': str(self.root.resolve()),
            'candidateHash': self.r.fingerprint(a.load(self.root/'candidate.yaml')),
            'policy': {'uid': 'policy-1'}, 'eventsHash': self.r.fingerprint(data),
            'since': '1970-01-01T00:01:40Z', 'until': '1970-01-01T00:01:42Z'}
        a.write(root/'events.json', data); a.write(root/'verification.json', report)
        return root/'verification.json'

    def refine(self, choices, receipt=None):
        path = Path(self.tmp.name)/'decisions.json'; a.write(path, choices)
        argv = ['refine', '--session', str(self.root), '--decisions', str(path)]
        if receipt: argv += ['--verification', str(receipt)]
        with contextlib.redirect_stdout(io.StringIO()): return a.refine(a.parser().parse_args(argv))

    def denied(self, **changes):
        r = event(**{'path':'/rare/refresh', 'method':'POST', 'responseCode':403,
                  'reason':'rbac_access_denied_matched_policy[none]', **changes})
        r['action'] = 'DENIED'; return r

    def test_silent_approval_preserves_authorization_and_must_be_explicit(self):
        old = a.load(self.root/'candidate.yaml')
        rule = a.load(self.root/'analysis.json')['permissions'][0]
        with self.assertRaisesRegex(ValueError, 'approval'):
            self.refine({'silentRuleIds': [rule['id']]})
        self.refine({'silentRuleIds': [rule['id']], 'approvalEvidence': 'User approved exact GET permission and silent audit'})
        new = a.load(self.root/'candidate.yaml')
        old_rule = a.network_rules(old['spec']['policy'])['egress']['httpRules'][0]
        new_rule = a.network_rules(new['spec']['policy'])['egress']['httpRules'][0]
        self.assertEqual(old_rule['match'], new_rule['match'])
        self.assertEqual(new_rule['qualifiers'], ['allow'])
        self.assertEqual(a.load(self.root/'analysis.json')['ruleChanges']['added'], [])
        self.assertEqual((self.root/'events.sqlite').read_bytes(), self.observed_db)

    def test_denied_pending_rejected_then_explicit_approval_adds_only_exact_rule(self):
        rec = self.denied(); receipt = self.receipt(rec)
        item = self.r.denied_items([rec], self.s, vars(a))[0]
        base = {'id': item['id'], 'reason': 'Needed for the monthly refresh', 'approvalEvidence': 'User confirmed this POST only'}
        self.refine({'decisions': [{**base, 'decision': 'reject'}]}, receipt)
        self.assertEqual(len(a.load(self.root/'analysis.json')['permissions']), 1)
        self.refine({'decisions': [{**base, 'decision': 'approve'}]}, receipt)
        result = a.load(self.root/'analysis.json')
        self.assertEqual(len(result['permissions']), 2)
        self.assertEqual(result['events'], 1)
        self.assertFalse(result['refinement']['decisions'][item['id']]['observedSuccess'])
        self.assertTrue(a.replay_match(rec, result['generatedEgress'], self.s))
        self.assertFalse(a.replay_match(self.denied(path='/rare/admin'), result['generatedEgress'], self.s))
        self.assertEqual((self.root/'events.sqlite').read_bytes(), self.observed_db)

    def test_tampered_stale_cross_policy_and_incomplete_denial_rejected(self):
        rec = self.denied(); receipt = self.receipt(rec)
        item = self.r.denied_items([rec], self.s, vars(a))[0]
        decision = {'decisions': [{'id': item['id'], 'decision': 'approve', 'reason': 'Business', 'approvalEvidence': 'User approval'}]}
        data = a.load(receipt); data['policy']['uid'] = 'another'; a.write(receipt, data)
        with self.assertRaisesRegex(ValueError, 'another'): self.refine(decision, receipt)
        receipt = self.receipt(rec); a.write(receipt.parent/'events.json', [])
        with self.assertRaisesRegex(ValueError, 'changed'): self.refine(decision, receipt)
        suspicious = self.denied(sni='different.example.com')
        self.assertFalse(self.r.denied_items([suspicious], self.s, vars(a))[0]['reviewable'])

    def test_rejected_denials_keep_review_annotation_but_approval_is_not_automatic(self):
        rec = self.denied(); item = self.r.denied_items([rec], self.s, vars(a))[0]
        s = {**self.s, 'observationSession': str(self.root)}
        saved = {'decisions': {item['id']: {'decision': 'reject', 'approvalEvidence': 'Explicit user rejection'}}}
        a.write(self.root/'refinement.json', saved)
        annotated = self.r.denied_items([rec], s, vars(a))[0]
        self.assertEqual(annotated['decision'], 'reject')
        saved['decisions'][item['id']]['decision'] = 'approve'; a.write(self.root/'refinement.json', saved)
        annotated = self.r.denied_items([rec], s, vars(a))[0]
        self.assertEqual(annotated['decision'], 'pending')
        self.assertEqual(annotated['previousDecision'], 'approve')

    def test_current_candidate_checks_are_separate_from_denial_provenance(self):
        rec = self.denied(); item = self.r.denied_items([rec], self.s, vars(a))[0]
        saved = {'decisions': {item['id']: {**item, 'decision': 'approve', 'verification': 'not-assessed'}}}
        check = {'id': 'refresh-quiet', 'layer': 'L7', 'destination': '10.0.0.8:443',
                 'authority': 'api.example.com', 'method': 'POST', 'path': '/rare/refresh',
                 'expected': 'allow', 'result': 'confirmed'}
        receipt = {'currentCandidate': True, 'checks': [check]}
        report = self.r.annotated_verification(saved, receipt, self.s, vars(a))['decisions'][item['id']]
        self.assertEqual(report['currentCandidateVerification'], 'confirmed')
        self.assertEqual(report['currentCandidateCheckIds'], ['refresh-quiet'])
        self.assertFalse(report['observedSuccess'])
        self.assertNotIn('currentCandidateVerification', saved['decisions'][item['id']])
        for change in [{'currentCandidate': False}, {'checks': [{**check, 'path': '/rare/admin'}]}]:
            report = self.r.annotated_verification(saved, {**receipt, **change}, self.s, vars(a))['decisions'][item['id']]
            self.assertEqual(report['currentCandidateVerification'], 'not-assessed')

    def test_tls_and_tcp_denials_keep_their_real_granularity(self):
        tls = event('L4', sni='download.example.com', reason='rbac_access_denied_matched_policy[none]'); tls['action']='DENIED'
        tcp = event('L4', reason='rbac_access_denied_matched_policy[none]'); tcp['action']='DENIED'
        items = self.r.denied_items([tls, tcp], self.s, vars(a))
        self.assertNotIn('paths', items[0]['rule']['match'])
        self.assertEqual(items[1]['rule']['ip'], '10.0.0.8')

    def test_silent_verification_requires_effective_configuration_and_complete_read(self):
        policy = a.load(self.root/'candidate.yaml')
        a.network_rules(policy['spec']['policy'])['egress']['httpRules'][0]['qualifiers'] = ['allow']
        check = {'id':'quiet', 'layer':'L7', 'destination':'10.0.0.8:443', 'authority':'api.example.com',
                 'method':'GET', 'path':'/v1/users/1', 'expected':'allow',
                 'clientConfirmed':True, 'backendConfirmed':True, 'configurationConfirmed':True}
        self.assertEqual(v.check_results([check], [], vars(a), policy, self.s)[0]['result'], 'confirmed')
        self.assertEqual(v.check_results([check], [], vars(a), policy, self.s, False)[0]['result'], 'insufficient')
        missing = dict(check); missing.pop('configurationConfirmed')
        self.assertEqual(v.check_results([missing], [], vars(a), policy, self.s)[0]['result'], 'insufficient')
        self.assertEqual(v.check_results([check], [event()], vars(a), policy, self.s)[0]['result'], 'contradicted')


class IndependentBoundaryTests(unittest.TestCase):
    """Regression cases found by the independent bounded-workflow review."""

    def test_inventory_and_ingest_keep_frozen_verification_uids(self):
        s = state()
        s.update(purpose='verification', verifiedPodUIDs=['pod-1'],
                 baselinePodUIDs=[], policyUID='policy-1')
        policy = {'metadata': {'uid': 'policy-1'},
                  'spec': {'updateExistingWorkloads': False}}

        def local_get(context, resource, namespace=None, name=None):
            return copy.deepcopy(policy) if resource == 'varmorpolicies' else {
                'items': [pod('pod-1'), pod('pod-2')]}

        with patch.object(a, 'get', local_get):
            matched, _ = a.live_inventory(s)
        self.assertEqual(s['podUIDs'], ['pod-1'])
        self.assertEqual([p['metadata']['uid'] for p in matched], ['pod-1'])
        with tempfile.TemporaryDirectory() as folder, contextlib.closing(a.database(folder)) as con, con:
            extra = event(); extra['podUID'] = 'pod-2'; extra['action'] = 'DENIED'
            stats = a.ingest(con, s, [('node/source', json.dumps(extra))], identities=['extra'])
            self.assertEqual(stats.get('newEvents', 0), 0)
            self.assertEqual(con.execute('SELECT count(*) FROM pending_pods').fetchone()[0], 0)

    def test_malformed_scan_cannot_confirm_quiet_bounded_verification(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); obs = base/'obs'; phase = base/'phase'; phase.mkdir()
            with contextlib.redirect_stdout(io.StringIO()):
                a.observe(a.parser().parse_args(['observe', '--session', str(obs), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client',
                    '--mitm-domain', 'api.example.com']))
            s = state(); s.update(policyUID='policy-1', baselinePodUIDs=[])
            a.write(obs/'session.json', s)
            with contextlib.closing(a.database(obs)) as con, con:
                a.ingest(con, s, [('source', json.dumps(event()))])
            with contextlib.redirect_stdout(io.StringIO()):
                a.analyze(a.parser().parse_args(['analyze', '--session', str(obs)]))
            policy = a.load(obs/'candidate.yaml')
            a.network_rules(policy['spec']['policy'])['egress']['httpRules'][0]['qualifiers'] = ['allow']
            a.write(obs/'candidate.yaml', policy)
            pin = {'uid': 'policy-1', 'generation': 1, 'specHash': a.refinement_module().fingerprint(policy['spec'])}
            phase_state = copy.deepcopy(s)
            phase_state.update(purpose='verification', observationSession=str(obs.resolve()), pinnedPolicy=pin,
                verifiedPodUIDs=['pod-1'], podHistory={'pod-1': {'regular': True, 'node': 'node-1'}},
                collectionMode='live-incremental')
            a.write(phase/'session.json', phase_state); a.write(phase/'observe.yaml', policy)
            reader = MemoryReader({'1:1': ('/var/log/varmor/violations.log', b'')})
            endpoint = {'id': 'node/node-1'}
            with contextlib.closing(a.database(phase)) as con, con:
                c.schema(con); c.scan(con, phase_state, reader, endpoint, 0, True)
                reader.files['1:1'] = ('/var/log/varmor/violations.log', b'{corrupted audit event}\n')
                stats, _ = c.scan(con, phase_state, reader, endpoint, 4096)
                self.assertEqual(stats['malformed'], 1)
                con.execute('INSERT INTO rounds(time,summary) VALUES (?,?)',
                            ('1970-01-01T00:01:43Z', json.dumps(stats)))
            a.write(phase/'collector.json', {'phase': 'stopped', 'stopReason': 'user-stop',
                'lastSuccessfulCollection': '1970-01-01T00:01:43Z', 'backlogBytes': 0, 'resourcePressure': False,
                'plan': {}, 'readyAt': '1970-01-01T00:01:40Z', 'stoppedAt': '1970-01-01T00:01:44Z',
                'sourceCapturedAt': {'node/node-1': '1970-01-01T00:01:43Z'}})
            a.refinement_module().collection_report(a.parser().parse_args(['analyze', '--session', str(phase)]), vars(a))
            self.assertFalse(a.load(phase/'enforcement-collection.json')['completeRead'])
            check = {'id': 'quiet', 'layer': 'L7', 'destination': '10.0.0.8:443', 'authority': 'api.example.com',
                'method': 'GET', 'path': '/v1/users/1', 'expected': 'allow', 'clientConfirmed': True,
                'backendConfirmed': True, 'configurationConfirmed': True}
            checks = base/'checks.json'; a.write(checks, {'checks': [check]})
            args = a.parser().parse_args(['verify', '--session', str(base/'verify'), '--observation-session', str(obs),
                '--collection-session', str(phase), '--policy-file', str(obs/'candidate.yaml'), '--pod-uid', 'pod-1',
                '--since', '1970-01-01T00:01:41Z', '--until', '1970-01-01T00:01:42Z', '--checks', str(checks)])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(v.verify(args, vars(a)), 2)
            result = a.load(base/'verify/verification.json')
            self.assertFalse(result['quietReadComplete'])
            self.assertEqual(result['checks'][0]['result'], 'insufficient')

    def test_monitor_honors_discovery_round_caps_and_full_phase_watch(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with contextlib.redirect_stdout(io.StringIO()):
                a.observe(a.parser().parse_args(['observe', '--session', str(root), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
            policy = a.load(root/'observe.yaml'); policy['metadata']['uid'] = 'policy-1'; policy['status'] = {'ready': True}
            calls, watches = [], []

            class Watch:
                def __init__(self, *args): watches.append(args[-1])
                def start(self): pass
                def close(self): pass
                def drain(self): return []

            class StoppingReader(MemoryReader):
                scans = 0
                def manifest(self, endpoint):
                    self.scans += 1
                    if self.scans == 3: a.write(root/'stop-request.json', {})
                    return super().manifest(endpoint)

            def local_process(argv, **kwargs):
                self.assertEqual(argv[0], 'kubectl')
                phase = a.load(root/'collector.json').get('phase')
                calls.append((phase, argv, kwargs['timeout']))
                if 'varmorpolicies' in argv:
                    output = policy
                elif 'auth' in argv:
                    return SimpleNamespace(returncode=0, stdout='yes', stderr='')
                elif 'varmor' in argv:
                    output = {'items': [{'metadata': {'name': 'agent'}, 'spec': {'nodeName': 'node-1',
                        'containers': [{'name': 'agent', 'command': ['/varmor', '--agent']}]}}]}
                else:
                    output = {'metadata': {'resourceVersion': '100'}, 'items': [pod('old')]}
                return SimpleNamespace(returncode=0, stdout=json.dumps(output), stderr='')

            args = a.parser().parse_args(['monitor', '--session', str(root), '--duration', '4', '--interval', '1',
                                         '--discovery-interval', '30', '--max-round-seconds', '1'])
            started = time.monotonic()
            with patch.object(a.subprocess, 'run', local_process), patch.object(c, 'PodWatch', Watch), \
                 patch.object(c, 'Reader', lambda api, state: StoppingReader({'1:1': ('/var/log/varmor/violations.log', b'')})), \
                 contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(c.monitor(args, vars(a)), 0)
            inventories = [x for x in calls if x[0] in ('ready', 'observing') and 'varmorpolicies' in x[1]]
            self.assertEqual(len(inventories), 1)
            self.assertTrue(all(0 < x[2] <= 1.05 for x in calls), calls)
            self.assertGreater(watches[0] - started, 3)
            self.assertEqual(a.load(root/'collector.json')['rounds'], 2)


if __name__ == '__main__': unittest.main()
