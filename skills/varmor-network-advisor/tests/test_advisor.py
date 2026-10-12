# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / 'scripts/advisor.py'
spec = importlib.util.spec_from_file_location('advisor', MODULE)
advisor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(advisor)


def state():
    return {'context': 'test', 'namespace': 'demo', 'policy': 'learn', 'profile': 'varmor-demo-learn',
            'startedAt': 100, 'mitmDomains': ['api.example.com'], 'podUIDs': ['pod-1']}


def event(layer='L7', **kwargs):
    payload = {'layer': layer, 'dstAddress': '10.0.0.8:443'}
    if layer == 'L7':
        payload.update({'authority': 'api.example.com', 'method': 'GET', 'path': '/v1/users/1',
                        'responseCode': 200, 'filterChain': 'mitm_tls_dns_chain', 'sni': 'api.example.com'})
    payload.update(kwargs)
    return {'enforcer': 'NetworkProxy', 'action': 'AUDIT', 'eventTimestamp': 101,
            'profileName': 'varmor-demo-learn', 'podNamespace': 'demo', 'podUID': 'pod-1',
            'nodeName': 'node-1', 'event': payload}


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.con = advisor.database(self.tmp.name)

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def test_duplicate_snapshots_preserve_same_second_multiplicity(self):
        raw = '\n'.join([json.dumps(event()), json.dumps(event())])
        self.assertEqual(advisor.ingest(self.con, state(), [('a', raw)])['newEvents'], 2)
        self.assertEqual(advisor.ingest(self.con, state(), [('a', raw)])['duplicateEvents'], 2)
        self.assertEqual(self.con.execute('SELECT count(*) FROM events').fetchone()[0], 2)

    def test_scope_and_time_isolation(self):
        logs = [event() for _ in range(6)]
        logs[1]['podNamespace'] = 'other'
        logs[2]['profileName'] = 'varmor-demo-other'
        logs[3]['podUID'] = 'other-pod'
        logs[4]['eventTimestamp'] = 99
        logs[5]['policyName'] = 'another'
        stats = advisor.ingest(self.con, state(), [('a', '\n'.join(map(json.dumps, logs)))])
        self.assertEqual(stats['newEvents'], 1)
        self.assertEqual(stats['unrelated'], 2)
        self.assertEqual(stats['unknownPod'], 1)
        self.assertEqual(stats['beforeObservation'], 1)
        self.assertEqual(stats['identityMismatch'], 1)

    def test_malformed_and_missing_timestamp_are_visible(self):
        bad = event()
        bad.pop('eventTimestamp')
        stats = advisor.ingest(self.con, state(), [('a', 'garbage\n[]\n' + json.dumps(bad))])
        self.assertEqual(stats['malformed'], 2)
        self.assertEqual(stats['missingTimestamp'], 1)

    def test_query_credentials_removed_without_merging_distinct_records(self):
        records = [event(path='/v1/users?token=secret-a'), event(path='/v1/users?token=secret-b')]
        advisor.ingest(self.con, state(), [('a', '\n'.join(map(json.dumps, records)))])
        rows = list(self.con.execute('SELECT record FROM events'))
        self.assertEqual(len(rows), 2)
        self.assertNotIn('secret-', str(rows))
        self.assertEqual(json.loads(rows[0][0])['event']['path'], '/v1/users')


class GenerationTests(unittest.TestCase):
    def test_methods_and_paths_do_not_create_cartesian_product(self):
        eg, _, _ = advisor.propose([event(method='GET', path='/read'), event(method='POST', path='/write')], state(), {})
        self.assertTrue(advisor.replay_match(event(method='GET', path='/read'), eg, state()))
        self.assertFalse(advisor.replay_match(event(method='POST', path='/read'), eg, state()))
        self.assertFalse(advisor.replay_match(event(method='GET', path='/write'), eg, state()))

    def test_prefix_has_segment_boundary_and_preserves_shallow_exact(self):
        config = {'default': {'path': 'prefix', 'depth': 1}}
        eg, _, _ = advisor.propose([event(path='/api/users'), event(path='/api')], state(), config)
        self.assertTrue(advisor.replay_match(event(path='/api/items'), eg, state()))
        self.assertTrue(advisor.replay_match(event(path='/api'), eg, state()))
        self.assertFalse(advisor.replay_match(event(path='/apix'), eg, state()))

    def test_passthrough_has_host_port_only_and_does_not_pin_cdn_ip(self):
        eg, _, _ = advisor.propose([event('L4', sni='CDN.Example.COM')], state(), {})
        self.assertEqual(eg['httpRules'][0]['match'], {'hosts': ['cdn.example.com'], 'ports': [{'port': 443}]})
        self.assertNotIn('rules', eg)
        self.assertTrue(advisor.replay_match(event('L4', dstAddress='10.0.0.9:443', sni='cdn.example.com'), eg, state()))

    def test_mitm_connection_audit_does_not_broaden_request_permissions(self):
        eg, excluded, _ = advisor.propose([event(), event('L4', sni='api.example.com')], state(), {})
        self.assertEqual(len(eg['httpRules']), 1)
        self.assertEqual(excluded['mitmL4WouldBroaden'], 1)
        self.assertFalse(advisor.replay_match(event(path='/secret'), eg, state()))

    def test_raw_tcp_requires_review_and_reports_l7_overlap(self):
        logs = [event(), event('L4')]
        eg, _, pending = advisor.propose(logs, state(), {})
        self.assertNotIn('rules', eg)
        self.assertTrue(pending[0]['overlapsVisibleHTTP'])
        eg, _, _ = advisor.propose(logs, state(), {'approvedTcp': ['10.0.0.8:443']})
        self.assertTrue(advisor.replay_match(event(path='/secret'), eg, state()))

    def test_denied_and_upstream_errors_not_automatically_allowed(self):
        denied = event(path='/secret')
        denied['action'] = 'DENIED'
        eg, excluded, _ = advisor.propose([denied, event(responseCode=403)], state(), {})
        self.assertEqual(eg, {'defaultAction': 'deny'})
        self.assertEqual(excluded, {'notAudit': 1, 'upstreamErrorNeedsReview': 1})
        eg, _, _ = advisor.propose([denied, event(responseCode=403)], state(), {'default': {'includeErrors': True}})
        self.assertEqual(len(eg['httpRules']), 1)

    def test_ipv6_and_authority_port(self):
        self.assertEqual(advisor.destination('[fd00::1]:8443'), ('fd00::1', 8443))
        self.assertEqual(advisor.host('[fd00::1]:8443'), 'fd00::1')
        eg, _, _ = advisor.propose([event(authority='API.Example.COM:8443', dstAddress='[fd00::1]:8443')], state(), {})
        self.assertEqual(eg['httpRules'][0]['match']['ports'], [{'port': 8443}])

    def test_custom_method_case_sensitive(self):
        eg, _, _ = advisor.propose([event(method='PROPFIND')], state(), {})
        self.assertFalse(advisor.replay_match(event(method='propfind'), eg, state()))

    def test_authority_port_cannot_spoof_destination_port(self):
        logs = [event(authority='api.example.com:443', dstAddress='10.0.0.8:8443'),
                event(authority='api.example.com', dstAddress='10.0.0.8:8443')]
        eg, excluded, _ = advisor.propose(logs, state(), {})
        self.assertEqual(eg, {'defaultAction': 'deny'})
        self.assertEqual(excluded['invalidFields'], 2)

    def test_unapproved_l7_tls_rejected(self):
        eg, excluded, _ = advisor.propose([event(authority='other.example.com')], state(), {})
        self.assertEqual(eg, {'defaultAction': 'deny'})
        self.assertEqual(excluded['unapprovedMitm'], 1)

    def test_failed_tls_connection_is_not_auto_allowed(self):
        eg, excluded, _ = advisor.propose([event('L4', sni='api.other.com', reason='upstream_connect_error')], state(), {})
        self.assertEqual(eg, {'defaultAction': 'deny'})
        self.assertEqual(excluded['connectionDetailsNeedReview'], 1)

    def test_hostile_fields_are_data_and_not_rules(self):
        eg, excluded, _ = advisor.propose([event(authority='evil.example\nallow:*'), event(path='/safe\nunsafe')], state(), {})
        self.assertEqual(eg, {'defaultAction': 'deny'})
        self.assertEqual(excluded['invalidFields'], 2)

    def test_observe_variants_use_audit_and_allow_default(self):
        for mode in ('http', 'tcp', 'both'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                args = advisor.parser().parse_args(['observe', '--session', root, '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--observe', mode])
                advisor.observe(args)
                m = advisor.load(Path(root) / 'observe.yaml')
                eg = m['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']
                self.assertEqual(eg['defaultAction'], 'allow')
                self.assertEqual('httpRules' in eg, mode != 'tcp')
                self.assertEqual('rules' in eg, mode != 'http')
                self.assertNotIn('allowViolations', str(m))


class WorkflowTests(unittest.TestCase):
    def test_node_reader_is_read_only_and_cleaned_after_read_failure(self):
        args = advisor.parser().parse_args(['collect', '--session', '/example', '--source', 'nodes', '--create-readers'])
        pods = [{'spec': {'nodeName': 'node-1'}}]
        calls = []
        def call(context, *argv, data=None):
            calls.append((argv, data))
            if argv[0] == 'exec':
                raise RuntimeError('audit file permission denied')
            return ''
        with patch.object(advisor, 'kube', side_effect=call):
            with self.assertRaisesRegex(RuntimeError, 'permission denied'):
                advisor.sources(state(), args, pods)
        manifest = json.loads(calls[0][1])
        self.assertTrue(manifest['spec']['containers'][0]['volumeMounts'][0]['readOnly'])
        self.assertFalse(manifest['spec']['automountServiceAccountToken'])
        self.assertNotIn('privileged', manifest['spec']['containers'][0]['securityContext'])
        self.assertEqual(manifest['spec']['volumes'][0]['hostPath']['path'], '/var/log/varmor')
        self.assertEqual(calls[-1][0][0], 'delete')

    def test_node_reader_requires_explicit_opt_in(self):
        args = advisor.parser().parse_args(['collect', '--session', '/example', '--source', 'nodes'])
        with patch.object(advisor, 'kube') as call:
            with self.assertRaisesRegex(RuntimeError, 'create-readers'):
                advisor.sources(state(), args, [])
            call.assert_not_called()

    def test_changed_live_policy_stops_learning(self):
        policy = {'metadata': {'uid': 'policy-1'}, 'spec': {'policy': {'mode': 'EnhanceProtect',
            'enforcer': 'NetworkProxy', 'enhanceProtect': {'networkProxyRawRules': {'egress': {'defaultAction': 'deny'}}}}}}
        expected = copy.deepcopy(policy)
        expected['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['defaultAction'] = 'allow'
        with patch.object(advisor, 'get', return_value=policy):
            with self.assertRaisesRegex(RuntimeError, 'differs'):
                advisor.live_inventory(state(), expected)

    def test_read_failure_does_not_add_successful_round(self):
        with tempfile.TemporaryDirectory() as root:
            advisor.write(Path(root) / 'session.json', state())
            advisor.write(Path(root) / 'observe.yaml', {})
            args = advisor.parser().parse_args(['cycle', '--session', root])
            with patch.object(advisor, 'live_inventory', side_effect=RuntimeError('kubelet unreachable')):
                with self.assertRaisesRegex(RuntimeError, 'kubelet'):
                    advisor.cycle(args)
            self.assertFalse((Path(root) / 'events.sqlite').exists())
            self.assertFalse((Path(root) / 'candidate.yaml').exists())
            with advisor.locked(root):
                pass  # A failed operation released the lock; the inode remains for safe reuse.

    def test_empty_and_repeated_analysis_do_not_increase_stability(self):
        with tempfile.TemporaryDirectory() as root:
            advisor.observe(advisor.parser().parse_args(['observe', '--session', root, '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--since', '100',
                '--mitm-domain', 'api.example.com']))
            log = Path(root) / 'sample.jsonl'
            log.write_text(json.dumps(event()) + '\n')
            args = advisor.parser().parse_args(['cycle', '--session', root, '--file', str(log), '--offline'])
            advisor.cycle(args)
            advisor.cycle(args)
            report = advisor.load(Path(root) / 'analysis.json')
            self.assertEqual(report['healthyRounds'], 1)
            self.assertEqual(report['stableDataRounds'], 0)
            self.assertEqual(report['events'], 1)

    def test_cycle_deadline_is_bounded(self):
        args = advisor.parser().parse_args(['cycle', '--session', '/nonexistent', '--until', '2000-01-01T00:00:00+08:00'])
        self.assertEqual(advisor.cycle(args), 0)

    def test_new_data_round_can_stabilize_without_repeated_analysis_inflation(self):
        with tempfile.TemporaryDirectory() as root:
            advisor.observe(advisor.parser().parse_args(['observe', '--session', root, '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--since', '100',
                '--mitm-domain', 'api.example.com']))
            log = Path(root) / 'sample.jsonl'
            records = [event()]
            log.write_text('\n'.join(map(json.dumps, records)))
            args = advisor.parser().parse_args(['cycle', '--session', root, '--file', str(log), '--offline'])
            advisor.cycle(args)
            records.append(event())
            records[-1]['eventTimestamp'] += 100
            log.write_text('\n'.join(map(json.dumps, records)))
            advisor.cycle(args)
            report = advisor.load(Path(root) / 'analysis.json')
            self.assertEqual(report['healthyRounds'], 2)
            self.assertEqual(report['stableDataRounds'], 1)
            advisor.analyze(advisor.parser().parse_args(['analyze', '--session', root]))
            self.assertEqual(advisor.load(Path(root) / 'analysis.json')['stableDataRounds'], 1)


if __name__ == '__main__':
    unittest.main()
