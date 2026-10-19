# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Real interface initialization and evidence/budget separation invariants."""
import contextlib
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_advisor import advisor as a


class VerificationInitializationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'new-workflow'
        self.candidate = {'apiVersion': 'crd.varmor.org/v1beta1', 'kind': 'VarmorPolicy',
            'metadata': {'name': 'approved', 'namespace': 'owned'}, 'spec': {
                'target': {'kind': 'Pod', 'name': 'client'}, 'updateExistingWorkloads': False,
                'policy': {'mode': 'EnhanceProtect', 'enforcer': 'NetworkProxy',
                    'enhanceProtect': {'networkProxyRawRules': {'egress': {'defaultAction': 'deny',
                        'httpRules': [{'qualifiers': ['allow'], 'match': {'hosts': ['owned.test'],
                            'ports': [{'port': 8080}], 'methods': ['GET'], 'paths': [{'exact': '/read'}]}}]}}}}}}
        self.file = self.base / 'approved.yaml'
        a.write(self.file, self.candidate)
        self.live = copy.deepcopy(self.candidate)
        self.live['metadata'].update(uid='new-policy-uid', generation=1)
        self.live['status'] = {'profileName': 'varmor-owned-approved', 'ready': True}
        self.pods = [{'metadata': {'name': 'client', 'namespace': 'owned', 'uid': 'client-uid',
            'annotations': {'pod.networkproxy.security.beta.varmor.org': 'localhost/varmor-owned-approved'}},
            'spec': {'containers': [{'name': 'app'}, {'name': 'varmor-network-proxy'}]}}]

    def args(self, *extra):
        return a.parser().parse_args(['init-verification', '--session', str(self.root),
            '--context', 'test', '--namespace', 'owned', '--name', 'approved',
            '--policy-file', str(self.file), '--approval-evidence', 'user approved deployed scope and budget',
            *extra])

    def get(self, context, resource, namespace=None, name=None):
        return copy.deepcopy({'items': self.pods} if resource == 'pods' else self.live)

    def initialize(self, args):
        with patch.object(a, 'get', side_effect=self.get), patch.object(a, 'kube') as kube, \
                contextlib.redirect_stdout(io.StringIO()):
            result = a.init_verification(args)
            kube.assert_not_called()
            return result

    def test_existing_pod_has_real_identity_and_no_observation_or_readiness_claim(self):
        self.assertEqual(self.initialize(self.args('--pod-uid', 'client-uid', '--language', 'zh-CN')), 0)
        s = a.load(self.root / 'session.json')
        self.assertEqual(s['purpose'], 'verification-only')
        self.assertEqual(s['policyUID'], 'new-policy-uid')
        self.assertEqual(s['baselinePodUIDs'], [])
        self.assertEqual(s['verifiedPodUIDs'], ['client-uid'])
        p = a.load(self.root / 'collector.json')
        self.assertEqual(p['phase'], 'prepared')
        self.assertNotIn('until', p['plan'])
        self.assertNotIn('readyAt', p)
        self.assertNotIn('processId', p)
        self.assertFalse((self.root / 'events.sqlite').exists())
        status = a.load(self.root / 'workflow-status.json')
        self.assertEqual(status['stage'], 'verification-prepared')
        self.assertEqual(status['nextActor'], 'assistant')
        self.assertEqual(status['deploymentState'], 'not-queried')
        for command in ('collect', 'analyze', 'refine', 'monitor'):
            argv = [command, '--session', str(self.root)]
            if command == 'refine': argv += ['--decisions', str(self.base / 'not-read.json')]
            with self.subTest(command=command), self.assertRaises(ValueError):
                getattr(a, command)(a.parser().parse_args(argv))
        self.assertEqual(a.load(self.root / 'candidate.yaml'), self.candidate)
        self.assertFalse((self.root / 'events.sqlite').exists())

    def test_startup_freezes_current_inventory_and_normal_prepare_needs_no_scaffold(self):
        self.initialize(self.args('--new-pods'))
        self.assertEqual(a.load(self.root / 'session.json')['baselinePodUIDs'], ['client-uid'])
        collection = self.base / 'startup'
        args = a.parser().parse_args(['prepare-verification', '--session', str(collection),
            '--observation-session', str(self.root), '--policy-file', str(self.root / 'candidate.yaml'), '--new-pods'])
        with patch.object(a, 'get', side_effect=self.get), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(a.prepare_verification(args), 0)
        state = a.load(collection / 'session.json')
        self.assertEqual(state['purpose'], 'verification')
        self.assertEqual(state['pinnedPolicy']['uid'], 'new-policy-uid')
        self.assertEqual(state['baselinePodUIDs'], ['client-uid'])
        self.assertEqual(state['resourcePlan']['maxConcurrentReads'], 2)

    def test_full_spec_target_and_lifecycle_differences_reject_before_output(self):
        for variant in ('system', 'target', 'automatic-update'):
            with self.subTest(variant=variant):
                live = copy.deepcopy(self.live)
                if variant == 'system': live['spec']['policy']['enforcer'] = 'AppArmorNetworkProxy'
                elif variant == 'target': live['spec']['target']['name'] = 'other'
                else: live['spec']['updateExistingWorkloads'] = True
                with patch.object(a, 'get', return_value=live), self.assertRaisesRegex(ValueError, 'complete Policy spec'):
                    a.init_verification(self.args('--new-pods'))
                self.assertFalse(self.root.exists())

    def test_policy_recreation_during_read_and_missing_injection_reject(self):
        newer = copy.deepcopy(self.live); newer['metadata']['uid'] = 'another-policy-uid'
        with patch.object(a, 'get', side_effect=[self.live, {'items': self.pods}, newer]), \
                self.assertRaisesRegex(ValueError, 'changed during initialization'):
            a.init_verification(self.args('--new-pods'))
        self.pods[0]['spec']['containers'] = [{'name': 'app'}]
        with self.assertRaisesRegex(ValueError, 'currently injected'):
            self.initialize(self.args('--pod-uid', 'client-uid'))
        self.assertFalse(self.root.exists())

    def test_non_network_drift_after_init_is_not_rebound_as_approved(self):
        self.initialize(self.args('--new-pods'))
        self.live['spec']['policy']['enhanceProtect']['hardeningRules'] = ['unexpected-change']
        self.live['metadata']['generation'] = 2
        collection = self.base / 'must-not-create'
        args = a.parser().parse_args(['prepare-verification', '--session', str(collection),
            '--observation-session', str(self.root), '--policy-file', str(self.root / 'candidate.yaml'), '--new-pods'])
        with patch.object(a, 'get', side_effect=self.get), self.assertRaisesRegex(RuntimeError, 'full Policy spec'):
            a.prepare_verification(args)
        self.assertFalse(collection.exists())
        self.assertEqual(a.load(self.root / 'session.json')['initialPolicy']['generation'], 1)

    def test_candidate_change_and_collection_inventory_drift_reject(self):
        self.initialize(self.args('--pod-uid', 'client-uid'))
        collection = self.base / 'normal-collection'
        args = a.parser().parse_args(['prepare-verification', '--session', str(collection),
            '--observation-session', str(self.root), '--policy-file', str(self.root / 'candidate.yaml'), '--pod-uid', 'client-uid'])
        with patch.object(a, 'get', side_effect=self.get), contextlib.redirect_stdout(io.StringIO()):
            a.prepare_verification(args)
        child = a.load(collection / 'session.json')
        self.live['spec']['policy']['enhanceProtect']['hardeningRules'] = ['unexpected-change']
        with patch.object(a, 'get', side_effect=self.get), self.assertRaisesRegex(RuntimeError, 'full Policy spec'):
            a.live_inventory(child, self.candidate)
        self.live['spec'] = copy.deepcopy(self.candidate['spec'])
        changed = copy.deepcopy(self.candidate); changed['metadata']['annotations'] = {'changed': 'source'}
        a.write(self.root / 'candidate.yaml', changed)
        status = a.workflow_module().summary(self.root, vars(a), language='zh-CN')
        self.assertEqual(status['stage'], 'verification-changed')
        args.session = str(self.base / 'changed-candidate-collection')
        with patch.object(a, 'get', side_effect=self.get), self.assertRaisesRegex(RuntimeError, 'frozen candidate'):
            a.prepare_verification(args)

    def test_nonempty_directory_and_invalid_budget_preserve_evidence(self):
        with self.assertRaises(ValueError): self.initialize(self.args('--new-pods', '--max-concurrent-reads', '0'))
        self.root.mkdir(); note = self.root / 'original.txt'; note.write_text('keep')
        with self.assertRaisesRegex(ValueError, 'new or empty'): self.initialize(self.args('--new-pods'))
        self.assertEqual(note.read_text(), 'keep')

    def test_frozen_mitm_scope_preserves_denial_granularity(self):
        self.candidate['spec']['policy']['networkProxyConfig'] = {'mitm': {'domains': ['owned.test']}}
        self.live['spec'] = copy.deepcopy(self.candidate['spec'])
        a.write(self.file, self.candidate)
        self.initialize(self.args('--pod-uid', 'client-uid'))
        state = a.load(self.root / 'session.json')
        self.assertEqual(state['mitmDomains'], ['owned.test'])
        event = {'action': 'DENIED', 'podUID': 'client-uid', 'eventTimestamp': '2026-10-14T01:00:00Z',
            'event': {'layer': 'L7', 'dstAddress': '10.0.0.8:8080', 'authority': 'owned.test:8080',
                'sni': 'owned.test', 'method': 'GET', 'path': '/missing', 'reason': 'rbac_access_denied_matched_policy[none]'}}
        item = a.refinement_module().denied_items([event], state, vars(a))[0]
        self.assertTrue(item['reviewable'])
        self.assertEqual(item['granularity'], 'exact HTTP method/path')
        event['event'] = {'layer': 'L4', 'dstAddress': '10.0.0.8:8080', 'sni': 'owned.test',
                          'reason': 'rbac_access_denied_matched_policy[none]'}
        item = a.refinement_module().denied_items([event], state, vars(a))[0]
        self.assertFalse(item['reviewable'])
        self.assertIn('whole MITM domain', item['reason'])

    def test_budget_lineage_preserves_plan_ledger_and_refuses_silent_change(self):
        self.initialize(self.args('--new-pods', '--max-transfer-mb-per-minute', '0.125'))
        owner = self.root; ledger = owner / 'resource-usage.json'
        ledger.write_text('{"totalBytes":1024,"charges":[]}')
        before = ledger.read_bytes()
        self.root = self.base / 'another-new-workflow'
        self.initialize(self.args('--new-pods', '--budget-session', str(owner)))
        s = a.load(self.root / 'session.json')
        self.assertEqual(s['budgetSession'], str(owner.resolve()))
        self.assertEqual(s['resourcePlan']['maxTransferMiBPerMinute'], 0.125)
        self.assertEqual(ledger.read_bytes(), before)
        self.root = self.base / 'invalid-budget-workflow'
        with self.assertRaisesRegex(ValueError, 'cannot change'):
            self.initialize(self.args('--new-pods', '--budget-session', str(owner), '--max-transfer-mb-per-minute', '16'))
        self.assertFalse(self.root.exists())


if __name__ == '__main__':
    unittest.main()
