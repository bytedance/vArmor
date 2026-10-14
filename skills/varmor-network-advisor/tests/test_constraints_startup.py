# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from test_advisor import advisor as a, event, state
from test_collector import c, MemoryReader, pod
from test_optimization import v

KUBE_DEADLINE = None


class ConstraintTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'obs'
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', str(self.root), '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app']))
        self.s = {**state(), 'mitmDomains': [], 'policyUID': 'policy-1'}
        a.write(self.root/'session.json', self.s)
        with contextlib.closing(a.database(self.root)) as con, con:
            a.ingest(con, self.s, [('src', json.dumps(event(sni='', filterChain='http_chain')))])
        self.analyze()
        self.db = (self.root/'events.sqlite').read_bytes()
        self.rule = {'qualifiers': ['deny', 'audit'], 'match': {'hosts': ['api.example.com'],
            'ports': [{'port': 443}], 'paths': [{'exact': '/debug'}]}}
        self.choice = {'layer': 'HTTP/SNI', 'rule': self.rule, 'reason': 'Debug and TLS are not needed',
                       'approvalEvidence': 'User approved this exact deny and its whole-SNI effect'}

    def analyze(self, language=None):
        argv = ['analyze', '--session', str(self.root)]
        if language: argv += ['--language', language]
        with contextlib.redirect_stdout(io.StringIO()):
            return a.analyze(a.parser().parse_args(argv))

    def refine(self, choices):
        path = self.root.parent/'choices.json'; a.write(path, choices)
        with contextlib.redirect_stdout(io.StringIO()):
            return a.refine(a.parser().parse_args(['refine', '--session', str(self.root), '--decisions', str(path)]))

    def test_deny_survives_regeneration_language_quiet_and_withdrawal(self):
        self.refine({'denyRules': [self.choice]})
        first = a.load(self.root/'analysis.json')
        self.assertEqual(first['ruleChanges']['added'][0]['action'], 'deny')
        grant = first['permissions'][0]['id']; deny = first['denyConstraints'][0]['id']
        self.assertNotEqual(grant, deny)
        self.refine({'silentRuleIds': [grant], 'approvalEvidence': 'User wants normal grant silent'})
        self.analyze('zh-CN'); self.analyze('en')
        eg = a.network_rules(a.load(self.root/'candidate.yaml')['spec']['policy'])['egress']
        self.assertEqual(eg['httpRules'][0], self.rule)
        self.assertEqual(eg['httpRules'][1]['qualifiers'], ['allow'])
        self.assertFalse(a.replay_match(event(layer='L4', sni='api.example.com'), eg, self.s))
        self.assertTrue(a.replay_match(event(sni=''), eg, self.s))
        self.refine({'revokeRuleIds': [grant], 'reason': 'Retired', 'approvalEvidence': 'Withdraw grant only'})
        eg = a.load(self.root/'analysis.json')['generatedEgress']
        self.assertEqual(eg['httpRules'], [self.rule])
        self.assertEqual((self.root/'events.sqlite').read_bytes(), self.db)

    def test_explicit_constraint_removal_is_reported_and_requires_approval(self):
        self.refine({'denyRules': [self.choice]})
        key = a.load(self.root/'analysis.json')['denyConstraints'][0]['id']
        before = (self.root/'candidate.yaml').read_bytes()
        with self.assertRaises(ValueError): self.refine({'removeDenyRuleIds': [key]})
        self.assertEqual((self.root/'candidate.yaml').read_bytes(), before)
        self.refine({'removeDenyRuleIds': [key], 'reason': 'TLS now needed', 'approvalEvidence': 'User accepted SNI scope'})
        report = a.load(self.root/'analysis.json')
        self.assertEqual(report['ruleChanges']['removed'][0]['action'], 'deny')
        self.assertEqual(report['denyConstraints'], [])
        self.assertTrue(a.replay_match(event(layer='L4', sni='api.example.com'), report['generatedEgress'], self.s))

    def test_manual_guard_cannot_be_overwritten_until_explicitly_registered(self):
        policy = a.load(self.root/'candidate.yaml')
        a.network_rules(policy['spec']['policy'])['egress']['httpRules'].insert(0, self.rule)
        a.write(self.root/'candidate.yaml', policy); original = (self.root/'candidate.yaml').read_bytes()
        with self.assertRaisesRegex(ValueError, 'edited'): self.analyze('zh-CN')
        self.assertEqual((self.root/'candidate.yaml').read_bytes(), original)
        self.refine({'denyRules': [self.choice]})
        self.analyze()
        self.assertEqual(a.load(self.root/'analysis.json')['denyConstraints'][0]['rule'], self.rule)

    def test_rejected_or_unsafe_constraints_never_change_candidate(self):
        before = (self.root/'candidate.yaml').read_bytes()
        for rule in ({**self.rule, 'qualifiers': ['allow', 'deny']},
                     {**self.rule, 'match': {**self.rule['match'], 'hosts': ['*']}},
                     {**self.rule, 'match': {**self.rule['match'], 'paths': [{'exact': '/bad\npath'}]}}):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                self.refine({'denyRules': [{**self.choice, 'rule': rule}]})
        with self.assertRaises(ValueError): self.refine({'denyRules': [{**self.choice, 'approvalEvidence': ''}]})
        self.assertEqual((self.root/'candidate.yaml').read_bytes(), before)

    def test_deny_alone_does_not_create_an_implicit_deny_all(self):
        with contextlib.closing(a.database(self.root)) as con, con:
            con.execute('DELETE FROM events')
        self.analyze()
        self.assertEqual(self.refine({'denyRules': [self.choice]}), 2)
        self.assertFalse((self.root/'candidate.yaml').exists())

    def test_intentional_denial_is_not_a_pending_grant_or_allow_check(self):
        self.refine({'denyRules': [self.choice]})
        rec = event(layer='L4', sni='api.example.com'); rec['action'] = 'DENIED'
        rec['event']['reason'] = 'rbac_access_denied_matched_policy[none]'
        items = a.refinement_module().denied_items([rec],
            {**self.s, 'observationSession': str(self.root)}, vars(a))
        self.assertEqual(items[0]['authorizationState'], 'explicit-deny')
        self.assertFalse(items[0]['reviewable'])
        self.assertEqual(items[0]['decision'], 'reject')
        check = {'id': 'TLS', 'layer': 'L4', 'expected': 'allow', 'destination': rec['event']['dstAddress'],
                 'sni': rec['event']['sni']}
        with self.assertRaisesRegex(ValueError, 'not covered'):
            v.check_results([check], [], vars(a), a.load(self.root/'candidate.yaml'), self.s)


class StartupTests(unittest.TestCase):
    def startup_state(self):
        return {**state(), 'purpose': 'verification', 'verificationMode': 'new-pods',
            'verificationTarget': {'kind': 'Pod', 'selector': {'matchLabels': {'app': 'orders'}}},
            'observationEpoch': '1970-01-01T00:01:40Z', 'verifiedPodUIDs': [], 'podUIDs': [],
            'baselinePodUIDs': ['old'], 'podHistory': {}}

    def new_pod(self, uid='new', labels=None):
        p = pod(uid)
        p['metadata'].update(namespace='demo', creationTimestamp='1970-01-01T00:01:41Z',
                             labels=labels if labels is not None else {'app': 'orders'})
        p['status'] = {'phase': 'Failed', 'conditions': [{'type': 'Ready', 'status': 'False'}]}
        return p

    def test_early_denied_is_quarantined_then_verified_even_when_pod_failed(self):
        s = self.startup_state(); rec = event(); rec.update(podUID='new', action='DENIED')
        rec['event'].update(path='/bootstrap', responseCode=403, reason='rbac_access_denied_matched_policy[none]')
        with tempfile.TemporaryDirectory() as folder, contextlib.closing(a.database(folder)) as con, con:
            c.schema(con)
            a.ingest(con, s, [('node/x', json.dumps(rec))], identities=['file:x:1:0'])
            self.assertEqual(con.execute('SELECT count(*) FROM pending_pods').fetchone()[0], 1)
            c.register_pod(s, self.new_pod())
            c.resolve_pending(con, s, vars(a)); c.resolve_pending(con, s, vars(a))
            self.assertEqual(con.execute('SELECT count(*) FROM events').fetchone()[0], 1)
            self.assertEqual(s['verifiedPodUIDs'], ['new'])
            self.assertEqual(con.execute('SELECT count(*) FROM pending_pods').fetchone()[0], 0)
            self.assertEqual(a.refinement_module().denied_items([rec], s, vars(a))[0]['decision'], 'pending')

    def test_baseline_wrong_target_and_missing_injection_are_not_enrolled(self):
        s = self.startup_state()
        for p in (self.new_pod('old'), self.new_pod(labels={'app': 'other'})):
            c.register_pod(s, p)
        p = self.new_pod(); p['spec']['containers'] = [{'name': 'app'}]; c.register_pod(s, p)
        self.assertEqual(s['verifiedPodUIDs'], [])
        fixed = {**s, 'verificationMode': 'existing-pods', 'verifiedPodUIDs': ['selected']}
        c.register_pod(fixed, self.new_pod())
        self.assertEqual(fixed['verifiedPodUIDs'], ['selected'])

    def test_deployment_ownership_is_resolved_and_uid_checked(self):
        s = self.startup_state(); s['verificationTarget'] = {'kind': 'Deployment', 'name': 'orders'}
        p = self.new_pod(); p['metadata']['ownerReferences'] = [{'kind': 'ReplicaSet', 'name': 'rs', 'uid': 'rs-1', 'controller': True}]
        rs = {'metadata': {'uid': 'rs-1', 'ownerReferences': [{'kind': 'Deployment', 'name': 'orders', 'uid': 'd-1', 'controller': True}]}}
        dep = {'metadata': {'name': 'orders', 'uid': 'd-1'}}
        api = {'get': lambda ctx, resource, ns, name: copy.deepcopy(rs if resource == 'replicasets' else dep)}
        c.register_pod(s, p, api); self.assertEqual(s['verifiedPodUIDs'], ['new'])
        s = self.startup_state(); s['verificationTarget'] = {'kind': 'Deployment', 'name': 'orders'}
        rs['metadata']['uid'] = 'reused-name'
        c.register_pod(s, p, api); self.assertEqual(s['verifiedPodUIDs'], [])

    def test_new_sidecar_source_reads_startup_from_beginning_with_budget(self):
        s = self.startup_state(); p = self.new_pod(); p['spec']['volumes'] = []
        c.register_pod(s, p)
        rec = event(); rec['podUID'] = 'new'
        raw = (json.dumps(rec)+'\n').encode()
        reader = MemoryReader({'1:2': ('/var/log/varmor/violations.log', raw)})
        with tempfile.TemporaryDirectory() as folder, contextlib.closing(a.database(folder)) as con, con:
            c.schema(con)
            result, _ = c.scan(con, s, reader, {'id': 'pod/new'}, len(raw))
            self.assertEqual(result['newEvents'], 1)
            self.assertEqual(result['bytesRead'], len(raw))

    def monitor_fixture(self, kind='Pod', deny_controller=False, shorten=False):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder); obs = base/'obs'; phase = base/'phase'
            with contextlib.redirect_stdout(io.StringIO()):
                a.observe(a.parser().parse_args(['observe', '--session', str(obs), '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--kind', kind, '--selector', 'app=orders']))
            candidate = a.load(obs/'observe.yaml')
            a.network_rules(candidate['spec']['policy'])['egress'] = {'defaultAction': 'deny'}
            candidate['metadata'].update(uid='policy-1', generation=1); candidate['status'] = {'ready': True}
            a.write(base/'candidate.yaml', candidate)
            a.write(obs/'collector.json', {'plan': c.plan(a.parser().parse_args(['monitor', '--session', str(obs), '--duration', '60']))})
            old = self.new_pod('old'); files = {'1:1': ('/var/log/varmor/violations.log', b'')}
            query_deadlines = []
            class Watch:
                def __init__(self, *args): self.turn = 0
                def start(self): pass
                def close(self): pass
                def drain(inner):
                    inner.turn += 1
                    if inner.turn != 2 and not (shorten and inner.turn == 3): return []
                    p = self.new_pod('late' if inner.turn == 3 else 'new'); p['metadata']['creationTimestamp'] = a.now()
                    if kind == 'Deployment':
                        p['metadata']['ownerReferences'] = [{'kind': 'ReplicaSet', 'name': 'rs', 'uid': 'rs-1', 'controller': True}]
                    if inner.turn == 3: return [('pod', p)]
                    rec = event(); rec.update(podUID='new', action='DENIED', eventTimestamp=int(time.time()))
                    rec['event'].update(path='/bootstrap', responseCode=403, reason='rbac_access_denied_matched_policy[none]')
                    files['1:1'] = (files['1:1'][0], (json.dumps(rec)+'\n').encode())
                    return [('pod', p)]
            class Reader(MemoryReader):
                def __init__(self, api, s): super().__init__(files); self.api = api
            def get(ctx, resource, ns=None, name=None):
                if resource in ('replicasets', 'deployments'):
                    remaining = KUBE_DEADLINE - time.monotonic()
                    query_deadlines.append(remaining)
                    if remaining <= 0: raise TimeoutError('phase deadline reached')
                    return {'metadata': {'uid': 'rs-1', 'ownerReferences': [
                        {'kind': 'Deployment', 'name': 'orders', 'uid': 'd-1', 'controller': True}]}} if resource == 'replicasets' else \
                        {'metadata': {'uid': 'd-1', 'name': 'orders', 'labels': {'app': 'orders'}}}
                return copy.deepcopy(candidate) if resource == 'varmorpolicies' else {'items': [old], 'metadata': {'resourceVersion': '1'}}
            with patch.object(a, 'get', get), contextlib.redirect_stdout(io.StringIO()):
                a.prepare_verification(a.parser().parse_args(['prepare-verification', '--session', str(phase),
                    '--observation-session', str(obs), '--policy-file', str(base/'candidate.yaml'), '--new-pods']))
            args = a.parser().parse_args(['monitor', '--session', str(phase), '--duration', '2'])
            def kube(*args):
                if deny_controller and 'replicasets' in args:
                    if deny_controller == 'error': raise RuntimeError('')
                    return 'no'
                return 'yes'
            def reschedule(api, root, progress, watch):
                if shorten and progress.get('rounds'):
                    global KUBE_DEADLINE
                    progress['plan']['until'] = (dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=1)).isoformat()
                    KUBE_DEADLINE = time.monotonic()
                    return True
                return False
            output = io.StringIO()
            with patch.object(a, 'collector_module', return_value=c), patch.object(a, 'get', get), patch.object(a, 'kube', kube), patch.object(c, 'PodWatch', Watch), \
                 patch.object(c, 'Reader', Reader), patch.object(c, 'apply_deadline_request', reschedule), \
                 patch.object(c, 'endpoints', return_value=[{'id': 'node/node-1'}]), contextlib.redirect_stdout(output):
                self.assertEqual(a.monitor(args), 2 if deny_controller else 0, output.getvalue())
            if deny_controller:
                return a.load(phase/'collector.json')
            return a.load(phase/'enforcement-collection.json'), query_deadlines

    def test_complete_monitor_arms_baseline_before_birth_and_saves_boot_denied(self):
        result, _ = self.monitor_fixture()
        self.assertEqual(result['events'], 1)
        self.assertIn('old', result['baselinePodUIDs'])
        self.assertEqual(result['podUIDs'], ['new'])
        self.assertEqual(result['denials'][0]['decision'], 'pending')

    def test_controller_get_permission_checked_before_startup_ready(self):
        for response in (True, 'error'):
            with self.subTest(response=response):
                result = self.monitor_fixture(kind='Deployment', deny_controller=response)
                self.assertNotIn('readyAt', result)
                self.assertIn('get permission for replicasets', result['error'])

    def test_final_owner_reads_respect_shortened_phase_deadline(self):
        result, deadlines = self.monitor_fixture(kind='Deployment', shorten=True)
        self.assertEqual(result['podUIDs'], ['new'])
        self.assertIn('late', result['identityFailures'])
        self.assertLessEqual(deadlines[-1], 0)
        self.assertTrue(all(bound <= 30 for bound in deadlines))


if __name__ == '__main__':
    unittest.main()
