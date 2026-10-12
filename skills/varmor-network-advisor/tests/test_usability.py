# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import argparse
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/advisor.py'
spec = importlib.util.spec_from_file_location('advisor_usability', SCRIPT)
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)


class UsabilityTests(unittest.TestCase):
    def compatible_crd(self):
        return {'spec': {'versions': [{'name': 'v1beta1', 'served': True,
                'schema': {'openAPIV3Schema': {'properties': {'spec': {'properties': {
                'updateExistingWorkloads': {'type': 'boolean'}, 'policy': {'properties': {
                'networkProxyConfig': {'type': 'object'}, 'enhanceProtect': {'properties': {
                'networkProxyRawRules': {'properties': {'egress': {'properties': {
                'defaultAction': {'type': 'string'}, 'httpRules': {'type': 'array'},
                'rules': {'type': 'array'}}}}}}}}}}}}}}}]}}

    def run_doctor(self, crd):
        responses = {'nodes': {'items': [{'metadata': {'name': 'node'},
                     'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]},
                     'crd': crd, 'mutatingwebhookconfigurations': {'items': [{'webhooks': [
                     {'name': 'mutatepod.varmor.org', 'clientConfig': {}}]}]}}
        output = io.StringIO()
        with patch.object(a, 'get', side_effect=lambda context, resource, **kwargs: responses[resource]), \
             contextlib.redirect_stdout(output):
            code = a.doctor(a.parser().parse_args(['doctor', '--context', 'test']))
        return code, json.loads(output.getvalue())

    def test_doctor_accepts_later_releases_with_compatible_api(self):
        for release in ('v0.10.5', 'v0.11.0', 'v1.0.0'):
            with self.subTest(release=release):
                crd = self.compatible_crd()
                crd['metadata'] = {'labels': {'app.kubernetes.io/version': release}}
                # A newer API may be added while the API used by the Skill stays served.
                crd['spec']['versions'].insert(0, {'name': 'v1', 'served': True})
                code, result = self.run_doctor(crd)
                self.assertEqual(code, 0)
                self.assertTrue(result['compatibility']['compatibleCRD'])
                self.assertEqual(result['compatibility']['servedCRDVersions'], ['v1', 'v1beta1'])

    def test_doctor_explains_missing_or_retired_api_without_crashing(self):
        for versions in ([], [{'name': 'v1', 'served': True}],
                         [{'name': 'v1beta1', 'served': False}]):
            with self.subTest(versions=versions):
                code, result = self.run_doctor({'spec': {'versions': versions}})
                self.assertEqual(code, 2)
                self.assertFalse(result['compatibility']['compatibleCRD'])
                self.assertIn('does not serve crd.varmor.org/v1beta1', result['findings'][0])
                self.assertEqual(len(result['webhooks']), 1)

    def test_doctor_rejects_newer_label_with_missing_network_rule_capability(self):
        crd = self.compatible_crd()
        crd['metadata'] = {'labels': {'app.kubernetes.io/version': 'v1.0.0'}}
        fields = crd['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']['properties']
        del fields['policy']['properties']['enhanceProtect']
        code, result = self.run_doctor(crd)
        self.assertEqual(code, 2)
        self.assertIn('spec.policy.enhanceProtect.networkProxyRawRules.egress.httpRules',
                      result['compatibility']['missingCRDFields'])

    def test_doctor_rejects_schema_missing_safe_lifecycle_control(self):
        crd = self.compatible_crd()
        fields = crd['spec']['versions'][0]['schema']['openAPIV3Schema']['properties']['spec']['properties']
        del fields['updateExistingWorkloads']
        code, result = self.run_doctor(crd)
        self.assertEqual(code, 2)
        self.assertEqual(result['compatibility']['missingCRDFields'], ['spec.updateExistingWorkloads'])

    def test_doctor_explains_missing_schema_instead_of_raising_key_error(self):
        code, result = self.run_doctor({'spec': {'versions': [{'name': 'v1beta1', 'served': True}]}})
        self.assertEqual(code, 2)
        self.assertIn('spec.policy.networkProxyConfig', result['compatibility']['missingCRDFields'])

    def test_user_manages_lifecycle_for_controller_and_pod_targets(self):
        for kind, flags in (('Deployment', ['--workload', 'client']),
                            ('StatefulSet', ['--workload', 'client']),
                            ('DaemonSet', ['--workload', 'client']),
                            ('Pod', ['--workload', 'client']),
                            ('Pod', ['--selector', 'app=custom-agent'])):
            with self.subTest(kind=kind, flags=flags), tempfile.TemporaryDirectory() as folder:
                args = a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--kind', kind, *flags])
                with patch.object(a, 'kube') as call:
                    a.observe(args)
                    call.assert_not_called()
                manifest = a.load(Path(folder) / 'observe.yaml')
                self.assertIs(manifest['spec']['updateExistingWorkloads'], False)
                self.assertEqual(manifest['spec']['target']['kind'], kind)
                if '--selector' in flags:
                    self.assertEqual(manifest['spec']['target']['selector']['matchLabels'], {'app': 'custom-agent'})

    def test_cli_cannot_enable_workload_updates(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            a.parser().parse_args(['observe', '--session', '/unused', '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'client', '--update-existing'])
        self.assertEqual(raised.exception.code, 2)

    def test_live_policy_with_automatic_updates_stops_before_pod_collection(self):
        state = {'context': 'test', 'namespace': 'demo', 'policy': 'learn'}
        policy = {'spec': {'updateExistingWorkloads': True}}
        with patch.object(a, 'get', return_value=policy) as call:
            with self.assertRaisesRegex(RuntimeError, 'automatic workload updates'):
                a.live_inventory(state)
            call.assert_called_once_with('test', 'varmorpolicies', 'demo', 'learn')

    def test_legacy_session_with_automatic_updates_cannot_generate_candidates(self):
        with tempfile.TemporaryDirectory() as folder:
            a.observe(a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
            manifest = a.load(Path(folder) / 'observe.yaml')
            manifest['spec']['updateExistingWorkloads'] = True
            a.write(Path(folder) / 'observe.yaml', manifest)
            with self.assertRaisesRegex(RuntimeError, 'create a new session'):
                a.analyze(a.parser().parse_args(['analyze', '--session', folder]))
            self.assertFalse((Path(folder) / 'candidate.yaml').exists())
            self.assertFalse((Path(folder) / 'validation.yaml').exists())
            self.assertEqual(a.load(Path(folder) / 'observe.yaml'), manifest)

    def test_tcp_observation_has_an_actual_match_predicate(self):
        for mode in ('tcp', 'both'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as folder:
                a.observe(a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                    '--namespace', 'demo', '--name', 'learn', '--workload', 'client', '--observe', mode]))
                egress=a.network_rules(a.load(Path(folder)/'observe.yaml')['spec']['policy'])['egress']
                self.assertEqual(egress['defaultAction'], 'allow')
                self.assertEqual(egress['rules'][0]['qualifiers'], ['audit'])
                self.assertEqual(egress['rules'][0]['ports'], [{'port':1,'endPort':65535}])

    def test_combined_profile_name_fails_before_writing_a_session(self):
        with tempfile.TemporaryDirectory() as folder:
            args = a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                '--namespace', 'a'*40, '--name', 'b'*20, '--workload', 'client'])
            with self.assertRaisesRegex(ValueError, '63 characters'):
                a.observe(args)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_status_requires_actual_pod_readiness_not_just_a_sidecar(self):
        with tempfile.TemporaryDirectory() as folder:
            a.write(Path(folder)/'session.json', {'context':'test','namespace':'demo','policy':'learn'})
            a.write(Path(folder)/'observe.yaml', {})
            pod={'metadata':{'name':'client','uid':'uid'}, 'spec':{'nodeName':'node'},
                 'status':{'phase':'Running','conditions':[{'type':'Ready','status':'False'}]}}
            with patch.object(a, 'live_inventory', return_value=([pod],{'status':{'ready':True}})):
                self.assertEqual(a.status(argparse.Namespace(session=folder)), 2)
            pod['status']['conditions'][0]['status']='True'
            with patch.object(a, 'live_inventory', return_value=([pod],{'status':{'ready':True}})):
                self.assertEqual(a.status(argparse.Namespace(session=folder)), 0)

    def test_tls_authority_mismatch_does_not_become_approved_business(self):
        state={'mitmDomains':['a.test','b.test']}
        event={'action':'AUDIT','event':{'layer':'L7','dstAddress':'10.0.0.1:443','authority':'a.test',
               'method':'GET','path':'/read','responseCode':200,'filterChain':'mitm_tls_dns_chain','sni':'b.test'}}
        rules,excluded,_=a.propose([event],state,{})
        self.assertNotIn('httpRules',rules)
        self.assertEqual(excluded['sniAuthorityMismatchNeedsReview'],1)

    def test_review_changes_and_empty_rounds_explain_what_changed(self):
        with tempfile.TemporaryDirectory() as folder:
            a.observe(a.parser().parse_args(['observe','--session',folder,'--context','test',
                '--namespace','demo','--name','learn','--workload','client','--since','100']))
            state=a.load(Path(folder)/'session.json')
            state['podUIDs']=['uid']
            event={'enforcer':'NetworkProxy','action':'AUDIT','podUID':'uid','podNamespace':'demo',
                'profileName':state['profile'],'eventTimestamp':101,'event':{'layer':'L7',
                'dstAddress':'10.0.0.1:80','authority':'a.test','method':'GET','path':'/read','responseCode':200}}
            with a.contextlib.closing(a.database(folder)) as con,con:
                a.ingest(con,state,[('node',json.dumps(event))])
            args=a.parser().parse_args(['analyze','--session',folder])
            self.assertEqual(a.analyze(args),0)
            self.assertEqual(len(a.load(Path(folder)/'analysis.json')['ruleChanges']['added']),1)
            self.assertEqual(a.analyze(args),0)
            report=a.load(Path(folder)/'analysis.json')
            self.assertEqual(report['ruleChanges']['added'],[])
            self.assertEqual(report['stableDataRounds'],0)
            review=Path(folder)/'review.json'
            a.write(review,{'excludedHosts':['a.test']})
            self.assertEqual(a.analyze(args),2)
            self.assertEqual(len(a.load(Path(folder)/'analysis.json')['ruleChanges']['removed']),1)
            self.assertFalse((Path(folder)/'candidate.yaml').exists())


class ReportLanguageTests(unittest.TestCase):
    def prepare(self, folder, language=None):
        flags = ['--language', language] if language else []
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'client', *flags]))
        root = Path(folder)
        state = a.load(root / 'session.json')
        state.update(startedAt=100, podUIDs=['pod-1'])
        a.write(root / 'session.json', state)
        records = [
            {'enforcer': 'NetworkProxy', 'action': 'AUDIT', 'eventTimestamp': 101,
             'profileName': state['profile'], 'podNamespace': 'demo', 'podUID': 'pod-1',
             'event': {'layer': 'L7', 'authority': 'api.example.com:80', 'method': 'GET',
                       'path': '/项目/123?token=private-canary', 'dstAddress': '10.0.0.8:80', 'responseCode': 200}},
            {'enforcer': 'NetworkProxy', 'action': 'AUDIT', 'eventTimestamp': 102,
             'profileName': state['profile'], 'podNamespace': 'demo', 'podUID': 'pod-1',
             'event': {'layer': 'L4', 'dstAddress': '10.0.0.8:9000'}},
        ]
        with contextlib.closing(a.database(root)) as con, con:
            a.ingest(con, state, [('fixture', '\n'.join(map(json.dumps, records)))])
        a.write(root / 'review.json', {'approvedTcp': ['10.0.0.8:9000']})
        return root

    def analyze(self, root, language=None):
        flags = ['--language', language] if language else []
        with contextlib.redirect_stdout(io.StringIO()):
            return a.analyze(a.parser().parse_args(['analyze', '--session', str(root), *flags]))

    def test_new_sessions_select_chinese_english_or_default(self):
        for language in ('zh-CN', 'en', None):
            with self.subTest(language=language), tempfile.TemporaryDirectory() as folder:
                root = self.prepare(folder, language)
                self.assertEqual(a.load(root / 'session.json')['reportLanguage'], language or 'en')
                self.assertEqual(self.analyze(root), 0)
                self.assertEqual(a.load(root / 'analysis.json')['reportLanguage'], language or 'en')
                prose = (root / 'report.md').read_text()
                self.assertIn('# NetworkProxy 白名单建议' if language == 'zh-CN' else
                              '# NetworkProxy allowlist recommendations', prose)
                self.assertIn('/项目/123', prose)
                self.assertNotIn('private-canary', prose)

    def test_switching_language_preserves_policy_evidence_and_background_choice(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepare(folder, 'zh-CN')
            self.analyze(root)
            candidate = (root / 'candidate.yaml').read_bytes()
            review = (root / 'review.json').read_bytes()
            with contextlib.closing(a.database(root)) as con:
                events = con.execute('SELECT id,record FROM events ORDER BY id').fetchall()
            for language in ('en', 'zh-CN'):
                self.assertEqual(self.analyze(root, language), 0)
                # monitor passes no language flag: periodic/final analysis must
                # use the latest persisted user choice rather than revert to en.
                args = a.parser().parse_args(['monitor', '--session', str(root)])
                with contextlib.redirect_stdout(io.StringIO()), patch.object(a, 'kube') as kube:
                    self.assertTrue(a.collector_module().local_analysis(vars(a), args))
                    kube.assert_not_called()
                self.assertEqual(a.load(root / 'analysis.json')['reportLanguage'], language)
                self.assertEqual(a.load(root / 'session.json')['reportLanguage'], language)
                self.assertEqual((root / 'candidate.yaml').read_bytes(), candidate)
                self.assertEqual((root / 'review.json').read_bytes(), review)
                with contextlib.closing(a.database(root)) as con:
                    self.assertEqual(con.execute('SELECT id,record FROM events ORDER BY id').fetchall(), events)
                self.assertEqual(a.load(root / 'analysis.json')['ruleChanges']['added'], [])
                self.assertEqual(a.load(root / 'analysis.json')['ruleChanges']['removed'], [])

    def test_legacy_session_falls_back_to_english(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepare(folder)
            state = a.load(root / 'session.json')
            del state['reportLanguage']
            a.write(root / 'session.json', state)
            self.analyze(root)
            self.assertEqual(a.load(root / 'session.json')['reportLanguage'], 'en')
            self.assertIn('# NetworkProxy allowlist recommendations', (root / 'report.md').read_text())

    def test_chinese_empty_report_does_not_deliver_a_stale_candidate(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.prepare(folder, 'zh-CN')
            self.analyze(root)
            a.write(root / 'review.json', {'excludedHosts': ['api.example.com'],
                                        'excludedTcp': ['10.0.0.8:9000']})
            self.assertEqual(self.analyze(root), 2)
            self.assertFalse((root / 'candidate.yaml').exists())
            prose = (root / 'report.md').read_text()
            self.assertIn('未生成 candidate.yaml', prose)
            self.assertIn('## 覆盖限制', prose)
            self.assertNotIn('## Coverage limitations', prose)


if __name__ == '__main__':
    unittest.main()
