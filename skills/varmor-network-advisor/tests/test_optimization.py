# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_advisor import advisor as a, event, state

spec = importlib.util.spec_from_file_location('verification_tests', Path(a.__file__).with_name('verification.py'))
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)


class ScopedReviewTests(unittest.TestCase):
    def decision(self):
        return {'host': 'api.example.com', 'port': 443, 'method': 'GET',
                'pathPrefix': '/api/orders/', 'path': 'prefix', 'depth': 2}

    def test_only_reviewed_family_generalizes(self):
        records = [event(path='/api/orders/1'), event(path='/api/orders/2'),
                   event(path='/admin/users/1'), event(path='/api/orders/1', method='POST'),
                   event(path='/api/orders/1', dstAddress='10.0.0.8:8443', authority='api.example.com:8443')]
        rules, _, _ = a.propose(records, state(), {'requests': [self.decision()]})
        self.assertTrue(a.replay_match(event(path='/api/orders/3003'), rules, state()))
        self.assertFalse(a.replay_match(event(path='/admin/users/2'), rules, state()))
        self.assertFalse(a.replay_match(event(path='/api/orders/3003', method='POST'), rules, state()))
        self.assertFalse(a.replay_match(event(path='/api/orders/3003', dstAddress='10.0.0.8:8443', authority='api.example.com:8443'), rules, state()))

    def test_ambiguous_scopes_and_ancestor_generalization_rejected(self):
        d = self.decision()
        with self.assertRaisesRegex(RuntimeError, 'overlapping'):
            a.propose([event(path='/api/orders/1')], state(), {'requests': [d, d]})
        for invalid in ({**d, 'depth': 1}, {**d, 'pathPrefix': '/api/orders'},
                        {**d, 'pathPrefix': '/api/orders/?token=x'}, {**d, 'port': True}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                a.options_check({'requests': [invalid]})

    def test_missing_declared_tcp_requires_explicit_approval(self):
        declaration = {'destination': '10.0.0.8:9000', 'reason': 'Order queue', 'approved': False}
        config = {'declaredTcp': [declaration]}
        rules, _, pending = a.propose([], state(), config)
        self.assertNotIn('rules', rules)
        self.assertEqual(pending[0]['origin'], 'user-declared')
        self.assertFalse(pending[0]['observed'])
        declaration['approved'] = True
        rules, _, pending = a.propose([], state(), config)
        self.assertEqual(rules['rules'][0]['ip'], '10.0.0.8')
        self.assertEqual(pending, [])
        self.assertEqual(a.declared_tcp_status([], config)[0]['verification'], 'not-assessed')

    def test_no_evidence_legacy_approval_is_visible_not_silently_lost(self):
        rules, _, pending = a.propose([], state(), {'approvedTcp': ['10.0.0.8:9000']})
        self.assertNotIn('rules', rules)
        self.assertEqual(pending[0]['origin'], 'approvedTcp')

    def test_declared_conflicts_rejected(self):
        declaration = {'destination': '10.0.0.8:9000', 'reason': 'queue', 'approved': True}
        with self.assertRaises(ValueError):
            a.options_check({'declaredTcp': [declaration], 'excludedTcp': ['10.0.0.8:9000']})

    def test_saved_review_regenerates_single_candidate_and_chinese_report(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', folder, '--context', 'test', '--namespace', 'demo',
                                            '--name', 'learn', '--workload', 'client', '--language', 'zh-CN']))
            root = Path(folder)
            a.write(root/'review-input.json', {'declaredTcp': [{'destination': '10.0.0.8:9000', 'reason': 'queue', 'approved': True}]})
            a.analyze(a.parser().parse_args(['analyze', '--session', folder, '--review', str(root/'review-input.json')]))
            candidate = (root/'candidate.yaml').read_bytes()
            a.analyze(a.parser().parse_args(['analyze', '--session', folder]))
            self.assertEqual(candidate, (root/'candidate.yaml').read_bytes())
            report = (root/'report.md').read_text()
            self.assertIn('用户业务声明', report)
            self.assertIn('尚未验证', report)
            self.assertNotIn('```json', report)
            self.assertIs(a.load(root/'candidate.yaml')['spec']['updateExistingWorkloads'], False)


class VerificationTests(unittest.TestCase):
    def test_association_is_persisted_and_becomes_stale_after_rule_change(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            root = Path(folder)/'obs'
            a.observe(a.parser().parse_args(['observe', '--session', str(root), '--context', 'test', '--namespace', 'demo',
                '--name', 'learn', '--workload', 'client', '--language', 'zh-CN']))
            review = {'declaredTcp': [{'destination': '10.0.0.8:9000', 'reason': 'queue', 'approved': True}]}
            a.write(root/'review.json', review)
            args = a.parser().parse_args(['analyze', '--session', str(root)])
            a.analyze(args)
            verification = {'kind': 'NetworkProxyVerification', 'observationSession': str(root.resolve()),
                'candidateHash': a.load(root/'analysis.json')['candidateHash'],
                'checks': [{'layer': 'L4', 'destination': '10.0.0.8:9000', 'expected': 'allow', 'result': 'confirmed'}],
                'summary': {'confirmed': 1}}
            pointer = Path(folder)/'verification.json'; a.write(pointer, verification)
            a.analyze(a.parser().parse_args(['analyze', '--session', str(root), '--verification', str(pointer)]))
            self.assertEqual(a.load(root/'analysis.json')['tcpRequirements'][0]['verification'], 'confirmed')
            self.assertEqual(a.load(root/'analysis.json')['events'], 0)
            review['declaredTcp'].append({'destination': '10.0.0.9:9000', 'reason': 'second queue', 'approved': True})
            a.write(root/'review.json', review); a.analyze(args)
            report = a.load(root/'analysis.json')
            self.assertFalse(report['verification']['currentCandidate'])
            self.assertEqual(report['tcpRequirements'][0]['verification'], 'not-assessed')
            self.assertEqual(report['stableDataRounds'], 0)
            self.assertIn('旧验证不能证明当前版本', (root/'report.md').read_text())

    def check(self, **changes):
        return {'id': 'orders', 'layer': 'L7', 'destination': '10.0.0.8:443',
                'authority': 'api.example.com', 'method': 'GET', 'path': '/v1/users/1',
                'expected': 'allow', **changes}

    def test_matching_audit_alone_is_insufficient(self):
        result = v.check_results([self.check()], [event()], vars(a))[0]
        self.assertEqual(result['result'], 'insufficient')
        self.assertIn('client-result', result['missing'])

    def test_client_backend_and_audit_confirm_or_contradict(self):
        check = self.check(clientConfirmed=True, backendConfirmed=True)
        self.assertEqual(v.check_results([check], [event()], vars(a))[0]['result'], 'confirmed')
        denied = event(); denied['action'] = 'DENIED'
        self.assertEqual(v.check_results([check], [denied], vars(a))[0]['result'], 'contradicted')
        check['expected'] = 'deny'
        self.assertEqual(v.check_results([check], [denied], vars(a))[0]['result'], 'confirmed')
        self.assertEqual(v.check_results([check], [], vars(a))[0]['result'], 'insufficient')

    def test_tcp_empty_output_without_denied_audit_is_not_proof(self):
        check = {'id': 'tcp', 'layer': 'L4', 'destination': '10.0.0.8:9000', 'expected': 'deny', 'clientConfirmed': True}
        self.assertEqual(v.check_results([check], [], vars(a))[0]['result'], 'insufficient')
        rec = event('L4', dstAddress='10.0.0.8:9000'); rec['action'] = 'DENIED'
        self.assertEqual(v.check_results([check], [rec], vars(a))[0]['result'], 'confirmed')

    def test_upstream_http_details_are_not_tcp_termination_errors(self):
        check = self.check(clientConfirmed=True, backendConfirmed=True)
        for code in (200, 403):
            with self.subTest(code=code):
                rec = event(reason='via_upstream', responseCode=code)
                self.assertEqual(v.check_results([check], [rec], vars(a))[0]['result'], 'confirmed')
        for rec in (event(reason='upstream_connection_failure'),
                    event(reason='via_upstream', responseCode=0)):
            self.assertEqual(v.check_results([check], [rec], vars(a))[0]['result'], 'insufficient')
        tcp_check = {'id': 'tcp', 'layer': 'L4', 'destination': '10.0.0.8:9000',
                     'expected': 'allow', 'clientConfirmed': True}
        tcp = event('L4', dstAddress='10.0.0.8:9000', reason='via_upstream')
        self.assertEqual(v.check_results([tcp_check], [tcp], vars(a))[0]['result'], 'insufficient')

    def test_upper_window_and_uid_exclusion(self):
        s = {**state(), 'endedAt': 102}
        early, good, late, wrong = event(), event(), event(), event()
        early['eventTimestamp'] = 99; late['eventTimestamp'] = 103; wrong['podUID'] = 'old'
        with tempfile.TemporaryDirectory() as folder, contextlib.closing(a.database(folder)) as con:
            stats = a.ingest(con, s, [('node', '\n'.join(map(json.dumps, [early, good, late, wrong])))])
            self.assertEqual(stats['newEvents'], 1)
            self.assertEqual(stats['afterWindow'], 1)
            self.assertEqual(stats['unknownPod'], 1)

    def test_verify_reuses_observation_pod_without_cluster_writes(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            obs, out = Path(folder)/'obs', Path(folder)/'verify'
            a.observe(a.parser().parse_args(['observe', '--session', str(obs), '--context', 'test', '--namespace', 'demo',
                                            '--name', 'learn', '--workload', 'client', '--since', '100']))
            session_state = a.load(obs/'session.json')
            session_state.update(baselinePodUIDs=['pre-observation-pod'], podUIDs=['pod-1'])
            a.write(obs/'session.json', session_state)
            policy = a.load(obs/'observe.yaml')
            a.network_rules(policy['spec']['policy'])['egress'] = {'defaultAction': 'deny'}
            a.write(obs/'candidate.yaml', policy)
            live = copy.deepcopy(policy); live['metadata'].update(uid='policy-1', generation=2)
            pod = {'metadata': {'uid': 'pod-1', 'name': 'new'}, 'spec': {}}
            args = a.parser().parse_args(['verify', '--session', str(out), '--observation-session', str(obs),
                                         '--policy-file', str(obs/'candidate.yaml'), '--pod-uid', 'pod-1',
                                         '--since', '1970-01-01T00:01:40Z', '--until', '1970-01-01T00:01:42Z'])
            originals = {p.name: p.read_bytes() for p in obs.iterdir()}
            with patch.object(a, 'live_inventory', return_value=([pod], live)), \
                 patch.object(a, 'sources', return_value=[('node', json.dumps(event()))]), \
                 patch.object(a, 'get', return_value=live), patch.object(a, 'kube') as calls:
                self.assertEqual(v.verify(args, vars(a)), 2)
                calls.assert_not_called()
            self.assertEqual(originals, {p.name: p.read_bytes() for p in obs.iterdir()})
            self.assertEqual(a.load(out/'verification.json')['events'], 1)
            with self.assertRaisesRegex(ValueError, 'separate'):
                args.session = str(obs); v.verify(args, vars(a))

    def test_policy_change_aborts_before_persisting(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()):
            obs, out = Path(folder)/'obs', Path(folder)/'verify'
            a.observe(a.parser().parse_args(['observe', '--session', str(obs), '--context', 'test', '--namespace', 'demo',
                '--name', 'learn', '--workload', 'client', '--since', '100']))
            policy = a.load(obs/'observe.yaml'); a.network_rules(policy['spec']['policy'])['egress'] = {'defaultAction': 'deny'}
            a.write(obs/'candidate.yaml', policy)
            live = copy.deepcopy(policy); live['metadata'].update(uid='policy-1', generation=2)
            changed = copy.deepcopy(live); changed['metadata']['generation'] = 3
            args = a.parser().parse_args(['verify', '--session', str(out), '--observation-session', str(obs),
                '--policy-file', str(obs/'candidate.yaml'), '--pod-uid', 'pod-1',
                '--since', '1970-01-01T00:01:40Z', '--until', '1970-01-01T00:01:42Z'])
            with patch.object(a, 'live_inventory', return_value=([{'metadata': {'uid': 'pod-1'}}], live)), \
                 patch.object(a, 'sources', return_value=[]), patch.object(a, 'get', return_value=changed):
                with self.assertRaisesRegex(RuntimeError, 'changed'):
                    v.verify(args, vars(a))
            self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
