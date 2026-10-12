# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'scripts/advisor.py'
spec = importlib.util.spec_from_file_location('advisor_review', CLI)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


def record(layer='L7', **fields):
    event = {'layer': layer, 'dstAddress': '10.0.0.1:443', 'authority': 'api.example.com',
             'filterChain': 'http_chain', 'method': 'GET', 'path': '/read', 'responseCode': 200}
    if layer == 'L4':
        event = {'layer': layer, 'dstAddress': '10.0.0.1:443', 'sni': 'api.example.com'}
    event.update(fields)
    return {'enforcer': 'NetworkProxy', 'action': 'AUDIT', 'profileName': 'varmor-demo-learn',
            'podNamespace': 'demo', 'podUID': 'pod-1', 'nodeName': 'node-1', 'eventTimestamp': 1000, 'event': event}


def state():
    return {'context': 'test', 'namespace': 'demo', 'policy': 'learn', 'profile': 'varmor-demo-learn',
            'startedAt': 100, 'podUIDs': ['pod-1'], 'mitmDomains': []}


def observe(root, *extra):
    return a.observe(a.parser().parse_args(['observe', '--session', str(root), '--context', 'test',
                     '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--since', '100', *extra]))


class ReviewRegressions(unittest.TestCase):
    def test_business_exclusions_survive_future_analysis_without_repeated_flags(self):
        with tempfile.TemporaryDirectory() as root:
            observe(root)
            with a.contextlib.closing(a.database(root)) as con, con:
                a.ingest(con, state(), [('a', json.dumps(record()))], offline=True)
            original = a.parser().parse_args(['analyze', '--session', root])
            self.assertEqual(a.analyze(original), 0)
            review = Path(root) / 'user-review.json'
            a.write(review, {'excludedHosts': ['api.example.com']})
            self.assertEqual(a.analyze(a.parser().parse_args(['analyze', '--session', root, '--review', str(review)])), 2)
            self.assertTrue((Path(root) / 'candidate.previous.yaml').exists())
            self.assertFalse((Path(root) / 'candidate.yaml').exists())
            self.assertEqual(a.analyze(original), 2)
            self.assertEqual(a.load(Path(root) / 'analysis.json')['excluded']['businessExcludedHost'], 1)

    def test_approved_and_excluded_tcp_cannot_conflict(self):
        with self.assertRaisesRegex(ValueError, 'both approved and excluded'):
            a.propose([], state(), {'approvedTcp': ['10.0.0.1:443'], 'excludedTcp': ['10.0.0.1:443']})

    def test_business_rejected_tcp_is_not_proposed_again(self):
        raw = record('L4')
        raw['event'].pop('sni')
        rules, excluded, pending = a.propose([raw], state(), {'excludedTcp': ['10.0.0.1:443']})
        self.assertEqual(rules, {'defaultAction': 'deny'})
        self.assertEqual(pending, [])
        self.assertEqual(excluded['businessExcludedTcp'], 1)

    def test_old_pod_records_are_filtered_before_current_uid_validation(self):
        stale = record()
        stale.update({'podUID': 'old-pod', 'eventTimestamp': 99})
        with tempfile.TemporaryDirectory() as root, a.contextlib.closing(a.database(root)) as con:
            stats = a.ingest(con, state(), [('node-1', '\n'.join(map(json.dumps, [stale, record()])))])
            self.assertEqual(stats.get('unknownPod', 0), 0)
            self.assertEqual(stats['beforeObservation'], 1)
            self.assertEqual(stats['newEvents'], 1)

    def test_tls_observation_cannot_broaden_plain_http_rules(self):
        eg, _, _ = a.propose([record('L4'), record()], state(), {})
        self.assertEqual(len(eg['httpRules']), 1)
        self.assertTrue(a.replay_match(record('L4'), eg, state()))
        self.assertFalse(a.replay_match(record(path='/private'), eg, state()))
        self.assertFalse(a.replay_match(record(method='POST'), eg, state()))

    def test_multiple_source_copies_do_not_inflate_observation(self):
        raw = '\n'.join([json.dumps(record()), json.dumps(record())])
        with tempfile.TemporaryDirectory() as root:
            with a.contextlib.closing(a.database(root)) as con:
                stats = a.ingest(con, state(), [('a', raw), ('b', raw), ('a', raw)], offline=True)
                self.assertEqual(stats['newEvents'], 2)
                self.assertEqual(stats['duplicateEvents'], 2)
                self.assertEqual(stats['duplicateSources'], 1)

    def test_process_crash_does_not_leave_a_stale_lock(self):
        with tempfile.TemporaryDirectory() as root:
            code = 'import importlib.util,os; s=importlib.util.spec_from_file_location("a",%r);a=importlib.util.module_from_spec(s);s.loader.exec_module(a)\nwith a.locked(%r): os._exit(0)' % (str(CLI), root)
            result = subprocess.run([sys.executable, '-c', code], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            with a.locked(root):
                with self.assertRaisesRegex(RuntimeError, 'busy'):
                    with a.locked(root):
                        pass
            with a.locked(root):
                pass

    def test_no_usable_candidate_with_empty_or_denied_only_data(self):
        with tempfile.TemporaryDirectory() as root:
            observe(root)
            analyze = a.parser().parse_args(['analyze', '--session', root])
            self.assertEqual(a.analyze(analyze), 2)
            self.assertFalse((Path(root) / 'candidate.yaml').exists())
            self.assertIsNone(a.load(Path(root) / 'analysis.json')['candidateFile'])
            denied = record()
            denied['action'] = 'DENIED'
            with a.contextlib.closing(a.database(root)) as con, con:
                a.ingest(con, state(), [('a', json.dumps(denied))], offline=True)
            self.assertEqual(a.analyze(analyze), 2)
            self.assertFalse((Path(root) / 'candidate.yaml').exists())

    def test_live_and_offline_sessions_cannot_be_mixed(self):
        with tempfile.TemporaryDirectory() as root:
            observe(root)
            s = a.load(Path(root) / 'session.json')
            s['collectionMode'] = 'live'
            a.write(Path(root) / 'session.json', s)
            file = Path(root) / 'logs.jsonl'
            file.write_text(json.dumps(record()))
            with patch.object(a, 'kube') as call:
                with self.assertRaisesRegex(RuntimeError, 'cannot share'):
                    a.collect(a.parser().parse_args(['collect', '--session', root, '--file', str(file), '--offline']))
                call.assert_not_called()

    def test_invalid_log_field_types_are_diagnosed_without_analysis_traceback(self):
        logs = [record(authority={'untrusted': 'value'}), record(path=['not', 'a', 'path']), record(responseCode=True)]
        with tempfile.TemporaryDirectory() as root, a.contextlib.closing(a.database(root)) as con:
            stats = a.ingest(con, state(), [('a', '\n'.join(map(json.dumps, logs)))], offline=True)
            self.assertEqual(stats['invalidEvent'], 3)
            self.assertEqual(con.execute('SELECT count(*) FROM events').fetchone()[0], 0)

    def test_malformed_review_produces_a_clear_validation_error(self):
        for config in ([], {'default': []}, {'domains': []}, {'domains': {'api.example.com': []}}, {'approvedTcp': 'bad'}):
            with self.subTest(config=config), self.assertRaises(ValueError):
                a.options_check(config)
        a.options_check({'default': {'depth': 2}, 'domains': {'api.example.com': {'path': 'prefix'}}})

    def test_existing_files_and_permissions_are_preserved(self):
        with tempfile.TemporaryDirectory() as root:
            existing = Path(root) / 'observe.yaml'
            existing.write_text('user-owned content')
            os.chmod(root, 0o755)
            with self.assertRaisesRegex(ValueError, 'new or empty'):
                observe(root)
            self.assertEqual(existing.read_text(), 'user-owned content')
            self.assertEqual(Path(root).stat().st_mode & 0o777, 0o755)

    def test_mitm_domain_rejects_port_suffix(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, 'without a port'):
                observe(root, '--mitm-domain', 'api.example.com:8443')

    def test_base_policy_preserves_system_dimension_and_existing_tls_settings(self):
        for mode in ('EnhanceProtect', 'DefenseInDepth'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                policy = {'apiVersion': 'crd.varmor.org/v1beta1', 'kind': 'VarmorPolicy',
                    'metadata': {'namespace': 'demo', 'name': 'learn', 'uid': 'policy-1'},
                    'spec': {'target': {'kind': 'Deployment', 'name': 'app'}, 'updateExistingWorkloads': True,
                    'policy': {'enforcer': 'AppArmorSeccomp', 'mode': mode,
                        'networkProxyConfig': {'proxyUID': 1234, 'proxyPort': 15501, 'mitm': {'domains': ['api.example.com']}},
                        'enhanceProtect': {'hardeningRules': ['disallow-write-core-pattern'], 'allowViolations': True},
                        'defenseInDepth': {'appArmor': {'profileType': 'Custom', 'customProfile': 'user profile'}}}}}
                source = Path(tmp) / 'original.json'
                a.write(source, policy)
                root = Path(tmp) / 'session'
                observe(root, '--base-policy', str(source))
                self.assertEqual(a.load(root / 'original-policy.json'), policy)
                self.assertFalse(a.load(root / 'observe.yaml')['spec']['updateExistingWorkloads'])
                actual = a.load(root / 'observe.yaml')['spec']['policy']
                self.assertEqual(actual['mode'], mode)
                self.assertEqual(actual['enhanceProtect']['hardeningRules'], ['disallow-write-core-pattern'])
                self.assertEqual(actual['defenseInDepth']['appArmor']['customProfile'], 'user profile')
                self.assertEqual(actual['networkProxyConfig'], policy['spec']['policy']['networkProxyConfig'])
                self.assertEqual(a.network_rules(actual)['egress']['defaultAction'], 'allow')
                self.assertEqual(a.load(root / 'session.json')['policyUID'], 'policy-1')
                with a.contextlib.closing(a.database(root)) as con, con:
                    s = a.load(root / 'session.json')
                    a.ingest(con, s, [('a', json.dumps(record(filterChain='mitm_tls_dns_chain')))], offline=True)
                self.assertEqual(a.analyze(a.parser().parse_args(['analyze', '--session', str(root)])), 0)
                candidate = a.load(root / 'candidate.yaml')['spec']['policy']
                self.assertFalse(a.load(root / 'candidate.yaml')['spec']['updateExistingWorkloads'])
                self.assertFalse(a.load(root / 'validation.yaml')['spec']['updateExistingWorkloads'])
                self.assertEqual(candidate['enhanceProtect']['hardeningRules'], ['disallow-write-core-pattern'])
                self.assertEqual(a.network_rules(candidate)['egress']['defaultAction'], 'deny')

    def test_wildcard_mitm_keeps_path_restrictions_without_coarse_tls_allow(self):
        s = state()
        s['mitmDomains'] = ['*.example.com']
        eg, _, _ = a.propose([record(filterChain='mitm_tls_dns_chain'), record('L4')], s, {})
        self.assertEqual(len(eg['httpRules']), 1)
        self.assertFalse(a.replay_match(record(path='/private'), eg, s))
        self.assertFalse(a.mitm_applies('example.com', ['*.example.com']))

    def test_helm_agent_and_container_are_discovered(self):
        args = a.parser().parse_args(['collect', '--session', '/unused', '--source', 'agent'])
        agent = {'metadata': {'name': 'varmor-agent-abc'}, 'spec': {'nodeName': 'node-1',
                 'containers': [{'name': 'agent', 'command': ['/varmor/vArmor', '--agent']}]}}
        calls = []
        def kube(context, *argv):
            calls.append(argv)
            return json.dumps({'items': [agent]}) if argv[0] == 'get' else json.dumps(record())
        with patch.object(a, 'kube', side_effect=kube):
            streams = a.sources(state(), args, [{'spec': {'nodeName': 'node-1'}}])
        self.assertEqual(len(streams), 1)
        self.assertIn('agent', calls[-1])
        self.assertNotIn('varmor-agent', calls[-1])

    def test_auto_does_not_create_node_readers_without_authorization(self):
        args = a.parser().parse_args(['collect', '--session', '/unused'])
        pods = [{'spec': {'nodeName': 'node-1', 'volumes': [
                {'name': 'varmor-network-proxy-audit-als', 'hostPath': {'path': '/run/varmor'}}]}}]
        with patch.object(a, 'kube', return_value=json.dumps({'items': []})) as call:
            with self.assertRaisesRegex(RuntimeError, 'create-readers'):
                a.sources(state(), args, pods)
            self.assertEqual(call.call_count, 1)

    def test_installer_checks_both_destinations_before_mutating(self):
        with tempfile.TemporaryDirectory() as root:
            conflict = Path(root) / '.claude/skills/varmor-network-advisor'
            conflict.mkdir(parents=True)
            (conflict / 'SKILL.md').write_text('existing user skill')
            result = subprocess.run([sys.executable, str(ROOT / 'install.py'), '--project', root], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((Path(root) / '.agents').exists())
            self.assertEqual((conflict / 'SKILL.md').read_text(), 'existing user skill')

    def test_actual_cli_one_shot_and_iterative_user_flow(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / 'session'
            def cli(*argv):
                r = subprocess.run([sys.executable, str(CLI), *argv], text=True, capture_output=True, timeout=20)
                self.assertEqual(r.returncode, 0, r.stderr)
                return r
            cli('observe', '--session', str(session), '--context', 'test', '--namespace', 'demo', '--name', 'learn',
                '--workload', 'app', '--since', '100', '--mitm-domain', 'api.example.com')
            log = Path(tmp) / 'logs.jsonl'
            events = [record(filterChain='mitm_tls_dns_chain', path='/v1/items/one?api_key=SECRET')]
            log.write_text(json.dumps(events[0]))
            review = Path(tmp) / 'review.json'
            review.write_text(json.dumps({'default': {'path': 'prefix', 'depth': 2}}))
            cli('cycle', '--session', str(session), '--file', str(log), '--offline', '--review', str(review))
            events.append(record(filterChain='mitm_tls_dns_chain', path='/v1/items/two'))
            events[1]['eventTimestamp'] += 60
            log.write_text('\n'.join(map(json.dumps, events)))
            cli('cycle', '--session', str(session), '--file', str(log), '--offline', '--review', str(review))
            report = json.loads((session / 'analysis.json').read_text())
            self.assertEqual(report['events'], 2)
            self.assertEqual(report['stableDataRounds'], 1)
            self.assertEqual(report['evidenceMode'], 'offline')
            candidate = a.load(session / 'candidate.yaml')
            self.assertEqual(a.network_rules(candidate['spec']['policy'])['egress']['httpRules'][0]['match']['paths'], [{'prefix': '/v1/items/'}])
            self.assertIn('/v1/items/', (session / 'report.md').read_text())
            self.assertNotIn('SECRET', (session / 'report.md').read_text())
            self.assertNotIn(b'SECRET', (session / 'events.sqlite').read_bytes())


if __name__ == '__main__':
    unittest.main()
