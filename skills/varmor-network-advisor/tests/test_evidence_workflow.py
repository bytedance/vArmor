# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_advisor import advisor as a, event, state
import test_collector as fixtures
from test_optimization import v

e = a.evidence_module()
w = a.workflow_module()
c = fixtures.c


def candidate(port=8080, audited=True):
    return {'kind': 'VarmorPolicy', 'metadata': {'name': 'learn', 'namespace': 'demo'},
        'spec': {'target': {'kind': 'Deployment', 'name': 'client'}, 'updateExistingWorkloads': False,
        'policy': {'mode': 'EnhanceProtect', 'enforcer': 'NetworkProxy', 'enhanceProtect': {'networkProxyRawRules': {
            'egress': {'defaultAction': 'deny', 'httpRules': [{'qualifiers': ['allow', 'audit'] if audited else ['allow'],
                'match': {'hosts': ['api.example.com'], 'ports': [{'port': port}],
                    'methods': ['GET'], 'paths': [{'exact': '/v1/users/1'}]}}]}}}}}}


def projection(audited=True):
    # Explicit Envoy-shaped fixture, independent of the expected-rule builder.
    permission = {'permissions': [{'and_rules': {'rules': [
        {'header': {'name': ':authority', 'string_match': {'exact': 'api.example.com:8080', 'ignore_case': True}}},
        {'destination_port': 8080}, {'header': {'name': ':method', 'string_match': {'exact': 'GET'}}},
        {'url_path': {'path': {'exact': '/v1/users/1'}}}]}}], 'principals': [{'any': True}]}
    sni = copy.deepcopy(permission)
    sni['permissions'][0]['and_rules']['rules'] = [
        {'requested_server_name': {'exact': 'api.example.com', 'ignore_case': True}}, {'destination_port': 8080}]
    def rbac(value):
        return [{'rules': {'action': 'ALLOW', 'policies': {'http_0': copy.deepcopy(value)}}},
                {'shadow_rules': {'action': 'ALLOW', 'policies': {'http_0': copy.deepcopy(value)}}}]
    def logs(http):
        expr = ('response.code_details' if http else 'connection.termination_details') + '.matches("rbac_access_denied.*")'
        shadow = "'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters." + ('http' if http else 'network') + ".rbac']"
        return [{'or_filter': {'filters': [{'extension_filter': {'name': 'envoy.access_loggers.extension_filters.cel',
            'typed_config': {'@type': 'type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter',
                             'expression': s}}} for s in (expr, shadow)]}}]
    result = {'name': 'varmor_outbound', 'inspectors': ['envoy.filters.listener.' + x for x in ('original_dst', 'tls_inspector', 'http_inspector')],
        'chains': [
            {'name': 'tls_chain', 'match': {'transport_protocol': 'tls'},
                'filters': ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy'],
                'rbac': [{**rbac(sni)[0], **rbac(sni)[1]}]},
            {'name': 'http_chain', 'match': {'application_protocols': ['http/1.0', 'http/1.1', 'h2c']},
                'filters': ['envoy.filters.network.http_connection_manager'], 'rbac': [],
                'http': {'filters': ['envoy.filters.http.rbac'] * 2 + ['envoy.filters.http.router'],
                    'rbac': list(reversed(rbac(permission))), 'normalize_path': True, 'merge_slashes': True,
                    'path_with_escaped_slashes_action': 'UNESCAPE_AND_FORWARD', 'logs': logs(True)}}],
        'default': {'name': 'tcp_default_chain', 'match': {},
            'filters': ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy'],
            'rbac': [{'rules': {'action': 'ALLOW', 'policies': {}}}]}, 'logs': logs(False)}
    if not audited:
        result['chains'][0]['rbac'][0].pop('shadow_rules')
        result['chains'][1]['http']['rbac'] = result['chains'][1]['http']['rbac'][1:]
        result['chains'][1]['http']['filters'].pop(0)
        for area in (result, result['chains'][1]['http']):
            area['logs'] = [area['logs'][0]['or_filter']['filters'][0]]
    return result


def listener_dump():
    p = projection()
    def chain(value):
        output = {'name': value['name'], 'filters': []}
        if value['match']:
            output['filter_chain_match'] = value['match']
        index = 0
        for name in value['filters']:
            config = {}
            if name == 'envoy.filters.network.rbac':
                config = {'@type': 'type.googleapis.com/envoy.extensions.filters.network.rbac.v3.RBAC', **value['rbac'][index]}; index += 1
            if name == 'envoy.filters.network.http_connection_manager':
                h = value['http']; config = {k: h[k] for k in ('normalize_path', 'merge_slashes', 'path_with_escaped_slashes_action')}
                config['access_log'] = [{'filter': x} for x in h['logs']]
                config['route_config'] = {'virtual_hosts': [{'request_headers_to_add': [{'header': {'key': 'authorization', 'value': 'private-canary'}}]}]}
                config['http_filters'] = []
                j = 0
                for n in h['filters']:
                    tc = {}
                    if n.endswith('.rbac'):
                        tc = {'@type': 'type.googleapis.com/envoy.extensions.filters.http.rbac.v3.RBAC', **h['rbac'][j]}; j += 1
                    config['http_filters'].append({'name': n, 'typed_config': tc})
            output['filters'].append({'name': name, 'typed_config': config})
        return output
    listener = {'name': p['name'], 'filter_chains': [chain(x) for x in p['chains']],
        'default_filter_chain': chain(p['default']), 'listener_filters': [{'name': n} for n in p['inspectors']],
        'access_log': [{'filter': x} for x in p['logs']]}
    return {'configs': [{'@type': 'type.googleapis.com/envoy.admin.v3.ListenersConfigDump',
        'dynamic_listeners': [{'name': 'varmor_outbound', 'active_state': {'listener': listener}}]}]}


class ClockTests(unittest.TestCase):
    def test_forward_wall_jump_stops_before_new_read_and_is_not_observed_time(self):
        fixture = fixtures.MonitorTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.arguments.duration = 3
        shift = [dt.timedelta()]
        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return dt.datetime.now(tz) + shift[0]
        fake_dt = SimpleNamespace(datetime=Clock, timezone=dt.timezone, timedelta=dt.timedelta)
        fixture.handoff_action = lambda: shift.__setitem__(0, dt.timedelta(hours=1))
        original = fixture.reader.manifest
        def manifest(endpoint):
            self.assertFalse(shift[0], 'a new file read began after the absolute deadline')
            return original(endpoint)
        fixture.reader.manifest = manifest
        with patch.object(c, 'dt', fake_dt), patch.object(a, 'now', lambda: Clock.now(dt.timezone.utc).isoformat()):
            self.assertEqual(fixture.run_monitor(), 0)
        progress = a.load(fixture.root / 'collector.json')
        self.assertEqual(progress['stopReason'], 'deadline')
        self.assertLess(progress['observedSeconds'], 3)
        self.assertGreater(progress['elapsedSeconds'], 3600)
        self.assertEqual(len(progress['timingGaps']), 1)
        self.assertEqual(progress['collectionHealth']['status'], 'suspected-gap')

    def test_backward_clock_jump_cannot_extend_monotonic_budget(self):
        fixture = fixtures.MonitorTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        shift = [dt.timedelta()]
        class Clock(dt.datetime):
            @classmethod
            def now(cls, tz=None):
                return dt.datetime.now(tz) + shift[0]
        fixture.handoff_action = lambda: shift.__setitem__(0, -dt.timedelta(hours=1))
        started = time.monotonic()
        with patch.object(c, 'dt', SimpleNamespace(datetime=Clock, timezone=dt.timezone, timedelta=dt.timedelta)), \
                patch.object(a, 'now', lambda: Clock.now(dt.timezone.utc).isoformat()):
            self.assertEqual(fixture.run_monitor(), 0)
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(a.load(fixture.root / 'collector.json')['timingGaps'])

    def test_pre_dispatch_rechecks_wall_deadline(self):
        with patch.object(a, 'KUBE_WALL_DEADLINE', time.time() - 1), patch.object(a, 'KUBE_DEADLINE', time.monotonic() + 60), \
                patch.object(a.subprocess, 'run') as run:
            with self.assertRaises(a.KubeDeadlineError):
                a.kube('test', 'get', 'pods')
            run.assert_not_called()

    def test_long_heartbeat_gap_is_excluded_even_when_both_clocks_advance(self):
        progress = {'plan': {'maxRoundSeconds': 30}, 'readyAt': a.now(), 'observedSeconds': 4}
        timing = c.ObservationTiming(progress)
        timing.tick -= 3600
        timing.wall -= dt.timedelta(hours=1)
        timing.sample()
        self.assertEqual(progress['observedSeconds'], 4)
        self.assertEqual(progress['timingGaps'][0]['reason'], 'heartbeat-interruption')


class PermissionTests(unittest.TestCase):
    def test_projection_rejects_matcher_override_and_drops_route_credentials(self):
        dump = listener_dump(); listener = dump['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
        self.assertNotIn('private-canary', json.dumps(e.project_listener(listener)))
        listener['filter_chains'][0]['filters'][0]['typed_config']['matcher'] = {'on_no_match': {'allow_all': True}}
        with self.assertRaisesRegex(ValueError, 'matcher overrides'):
            e.project_listener(listener)

    def test_public_active_read_pins_identity_and_saves_only_projection(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); s = state(); s.update(context='test', policy='learn', baselinePodUIDs=[])
            a.write(root / 'session.json', s); a.write(root / 'candidate.yaml', candidate())
            live = candidate(); live['metadata'].update(uid='policy-1', generation=2)
            pod = {'metadata': {'name': 'client-1', 'uid': 'pod-1'}}
            body = json.dumps(listener_dump()).encode()
            response = b'HTTP/1.1 200 OK\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n' + body
            args = a.parser().parse_args(['active-config', '--session', str(root), '--policy-file', str(root / 'candidate.yaml'), '--pod-uid', 'pod-1', '--output', str(root / 'proof.json')])
            with patch.object(a, 'live_inventory', return_value=([pod], live)), patch.object(a, 'kube', return_value=response) as command, \
                    patch.object(a, 'get', side_effect=[live, pod]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(a.active_config(args), 0)
            self.assertTrue(command.call_args.kwargs['binary'])
            self.assertIn('head -c', command.call_args.args[-1]); self.assertIn('--reuid=1337', command.call_args.args)
            self.assertNotIn('private-canary', (root / 'proof.json').read_text())
            changed = copy.deepcopy(pod); changed['metadata']['uid'] = 'reused-name'
            with patch.object(a, 'live_inventory', return_value=([pod], live)), patch.object(a, 'kube', return_value=response), \
                    patch.object(a, 'get', side_effect=[live, changed]):
                with self.assertRaisesRegex(ValueError, 'identity changed'):
                    a.active_config(args)
    def test_silent_and_default_port_authority_spellings(self):
        self.assertEqual(e.compare_permissions(candidate(audited=False), projection(False), vars(a))[0], 'confirmed')
        for port in (80, 443):
            shaped = projection()
            for item in shaped['chains'][0]['rbac'][0].values():
                item['policies']['http_0']['permissions'][0]['and_rules']['rules'][1]['destination_port'] = port
            for item in shaped['chains'][1]['http']['rbac']:
                rules = next(iter(item.values()))['policies']['http_0']['permissions'][0]['and_rules']['rules']
                rules[0] = {'or_rules': {'rules': [
                    {'header': {'name': ':authority', 'string_match': {'exact': 'api.example.com', 'ignore_case': True}}},
                    {'header': {'name': ':authority', 'string_match': {'exact': 'api.example.com:' + str(port), 'ignore_case': True}}}]}}
                rules[1]['destination_port'] = port
            self.assertEqual(e.compare_permissions(candidate(port), shaped, vars(a))[0], 'confirmed')
    def test_active_scope_matches_but_stale_method_path_or_audit_does_not(self):
        self.assertEqual(e.compare_permissions(candidate(), projection(), vars(a))[0], 'confirmed')
        for mutate in (
            lambda x: x['chains'][1]['http']['rbac'][1]['rules']['policies']['http_0']['permissions'][0]['and_rules']['rules'][2]['header']['string_match'].update(exact='POST'),
            lambda x: x['chains'][1]['http']['rbac'][1]['rules']['policies']['http_0']['permissions'][0]['and_rules']['rules'][3]['url_path']['path'].update(exact='/admin'),
            lambda x: x['default']['rbac'][0]['rules']['policies'].update(allow_all={'permissions': [{'any': True}], 'principals': [{'any': True}]}),
            lambda x: x['chains'][1]['http']['logs'].clear()):
            changed = projection(); mutate(changed)
            self.assertEqual(e.compare_permissions(candidate(), changed, vars(a))[0], 'contradicted')
        self.assertEqual(e.compare_permissions(candidate(audited=False), projection(), vars(a))[0], 'contradicted')

    def test_unknown_mitm_and_extra_chain_stay_insufficient(self):
        p = candidate(); p['spec']['policy']['networkProxyConfig'] = {'mitm': {'domains': ['api.example.com']}}
        self.assertEqual(e.compare_permissions(p, projection(), vars(a))[0], 'insufficient')
        shaped = projection(); shaped['chains'].append(copy.deepcopy(shaped['chains'][0]))
        self.assertEqual(e.compare_permissions(candidate(), shaped, vars(a))[0], 'insufficient')


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.p = candidate()
        self.pinned = {'uid': 'policy-1', 'generation': 2, 'specHash': e.digest(self.p['spec'])}
        self.since, self.until = '1970-01-01T01:00:00Z', '1970-01-01T01:01:00Z'
        self.check = {'id': 'orders', 'layer': 'L7', 'destination': '10.0.0.8:8080', 'expected': 'allow',
            'authority': 'api.example.com:8080', 'method': 'GET', 'path': '/v1/users/1',
            'clientConfirmed': True, 'backendConfirmed': True, 'configurationConfirmed': True}
        client = {'kind': 'NetworkProxyCommandReceipt', 'checkId': 'orders', 'podUID': 'pod-1',
            'startedAt': '1970-01-01T01:00:01Z', 'endedAt': '1970-01-01T01:00:02Z', 'exitCode': 0,
            'stdout': 'HTTP 200\nprobe-orders-001'}
        backend = {**client, 'startedAt': '1970-01-01T01:01:01Z', 'endedAt': '1970-01-01T01:01:02Z',
            'stdout': 'GET /v1/users/1 probe-orders-001'}
        self.item = {'id': 'orders', 'podUID': 'pod-1',
            'client': {**self.save('client.json', client), 'exitCode': 0, 'stdoutContains': ['HTTP 200', 'probe-orders-001']},
            'backend': {**self.save('backend.json', backend), 'exitCode': 0, 'stdoutContains': ['GET /v1/users/1 probe-orders-001']},
            'configuration': [self.proof('before', '1970-01-01T00:59:58Z'), self.proof('after', '1970-01-01T01:01:02Z')]}
        self.bundle = {'kind': 'NetworkProxyCheckReceipts', 'candidateHash': e.digest(self.p), 'policy': self.pinned,
            'podUIDs': ['pod-1'], 'since': self.since, 'until': self.until, 'checks': [self.item]}

    def save(self, name, data):
        path = self.root / name; a.write(path, data)
        return {'file': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}

    def proof(self, name, at):
        permissions = projection('audit' in self.p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['httpRules'][0]['qualifiers'])
        data = {'kind': 'NetworkProxyActivePermissionProof', 'candidateHash': e.digest(self.p), 'policy': self.pinned,
            'podUID': 'pod-1', 'startedAt': at, 'checkedAt': at, 'permissions': permissions,
            'permissionsHash': e.digest(permissions), 'result': 'confirmed'}
        return self.save(name + '.json', data)

    def evaluate(self):
        return e.evaluate_bundle(self.bundle, [self.check], self.p, self.pinned, ['pod-1'], self.since, self.until, vars(a))

    def test_positive_raw_receipts_match_without_trusting_confirmation_flags(self):
        result = self.evaluate()
        self.assertIs(result['orders']['clientConfirmed'], True)
        self.assertIs(result['orders']['backendConfirmed'], True)
        self.assertIs(result['orders']['configurationConfirmed'], True)
        rec = event(authority='api.example.com:8080', dstAddress='10.0.0.8:8080')
        checked = v.check_results([self.check], [rec], vars(a), self.p, state(), receipt_results=result)
        self.assertEqual(checked[0]['result'], 'confirmed')
        self.assertEqual(v.check_results([self.check], [rec], vars(a), self.p, state(), receipt_results={})[0]['result'], 'insufficient')

    def test_changed_bytes_or_fabricated_booleans_do_not_pass(self):
        (self.root / 'client.json').write_text('{}')
        result = self.evaluate()['orders']
        self.assertIsNone(result['clientConfirmed'])
        self.assertIn('hash', result['problems'][0])

    def test_malformed_source_shapes_remain_insufficient_instead_of_crashing(self):
        ref = self.save('invalid.json', [])
        self.item['client'].update(ref)
        self.assertIsNone(self.evaluate()['orders']['clientConfirmed'])
        self.assertEqual(e.compare_permissions(self.p, None, vars(a))[0], 'insufficient')
        with self.assertRaises(ValueError):
            e.instant(None)
        with self.assertRaises(ValueError):
            e.evaluate_bundle([], [self.check], self.p, self.pinned, ['pod-1'], self.since, self.until, vars(a))

    def test_actual_unexpected_output_is_contradictory(self):
        self.item['client']['stdoutContains'] = ['HTTP 201']
        self.assertIs(self.evaluate()['orders']['clientConfirmed'], False)

    def test_missing_proof_or_stale_candidate_uid_window_are_rejected(self):
        self.item['configuration'] = self.item['configuration'][:1]
        self.assertIsNone(self.evaluate()['orders']['configurationConfirmed'])
        for key, value in [('candidateHash', 'other'), ('podUIDs', ['old']), ('until', '1970-01-01T01:02:00Z')]:
            original = self.bundle[key]; self.bundle[key] = value
            with self.assertRaises(ValueError):
                self.evaluate()
            self.bundle[key] = original

    def test_saved_success_does_not_hide_actual_permission_mismatch(self):
        path = Path(self.item['configuration'][1]['file']); data = a.load(path)
        data['permissions']['default']['rbac'][0]['rules']['action'] = 'DENY'
        data['permissionsHash'] = e.digest(data['permissions'])
        self.item['configuration'][1] = self.save(path.name, data)
        self.assertIs(self.evaluate()['orders']['configurationConfirmed'], False)

    def test_audit_from_other_selected_pod_cannot_confirm_this_probe(self):
        result = self.evaluate()
        rec = event(authority='api.example.com:8080', dstAddress='10.0.0.8:8080'); rec['podUID'] = 'other-pod'
        self.assertEqual(v.check_results([self.check], [rec], vars(a), self.p, state(), receipt_results=result)[0]['result'], 'insufficient')

    def verify_cli(self, use_receipts=True, quiet=False):
        obs = self.root / 'observation'
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', str(obs), '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'client']))
        saved = a.load(obs / 'session.json'); saved.update(policyUID='policy-1', baselinePodUIDs=['old'], podUIDs=['pod-1'])
        a.write(obs / 'session.json', saved); a.write(obs / 'candidate.yaml', self.p)
        live = copy.deepcopy(self.p); live['metadata'].update(uid='policy-1', generation=2)
        a.write(self.root / 'checks.json', {'checks': [self.check]})
        a.write(self.root / 'receipts.json', self.bundle)
        out = self.root / 'verification'
        argv = ['verify', '--session', str(out), '--observation-session', str(obs), '--policy-file', str(obs / 'candidate.yaml'),
            '--pod-uid', 'pod-1', '--since', self.since, '--until', self.until, '--checks', str(self.root / 'checks.json')]
        if use_receipts:
            argv += ['--receipts', str(self.root / 'receipts.json')]
        rec = event(authority='api.example.com:8080', dstAddress='10.0.0.8:8080')
        rec['eventTimestamp'] = int(e.instant(self.since).timestamp()) + 1
        if quiet:
            folder = self.root / 'bounded'; folder.mkdir()
            a.write(folder / 'events.json', [])
            a.write(folder / 'enforcement-collection.json', {
                'kind': 'NetworkProxyEnforcementCollection', 'observationSession': str(obs.resolve()),
                'candidateHash': e.digest(self.p), 'eventsHash': e.digest([]), 'policy': self.pinned, 'podUIDs': ['pod-1'],
                'since': self.since, 'until': self.until, 'collectionHealth': {'status': 'no-detected-gap'},
                'completeRead': True, 'requiredSources': ['node/one'],
                'observation': {'phase': 'stopped', 'sourceCapturedAt': {'node/one': self.until}}})
            argv += ['--collection-session', str(folder)]
        with patch.object(a, 'live_inventory', return_value=([{'metadata': {'uid': 'pod-1'}}], live)), \
                patch.object(a, 'sources', return_value=[('node', json.dumps(rec))]), patch.object(a, 'get', return_value=live), \
                contextlib.redirect_stdout(io.StringIO()):
            status = a.verify(a.parser().parse_args(argv))
        return status, a.load(out / 'verification.json')

    def test_public_verify_requires_raw_receipts_and_preserves_audit(self):
        status, report = self.verify_cli(use_receipts=False)
        self.assertEqual(status, 2); self.assertEqual(report['summary'], {'insufficient': 1})
        self.assertEqual(report['events'], 1)

    def test_public_verify_matches_checked_receipts_to_actual_audit(self):
        status, report = self.verify_cli()
        self.assertEqual(status, 0); self.assertEqual(report['summary'], {'confirmed': 1})
        brief = w.summary(self.root / 'observation', vars(a), verification=str(self.root / 'verification/verification.json'))
        self.assertEqual(brief['stage'], 'verified')

    def test_public_quiet_verify_needs_bounded_read_and_real_permission_projection(self):
        self.p = candidate(audited=False); self.pinned['specHash'] = e.digest(self.p['spec'])
        self.bundle.update(candidateHash=e.digest(self.p), policy=self.pinned)
        self.item['configuration'] = [self.proof('before', '1970-01-01T00:59:58Z'), self.proof('after', '1970-01-01T01:01:02Z')]
        status, report = self.verify_cli(quiet=True)
        self.assertEqual(status, 0); self.assertEqual(report['checks'][0]['auditMode'], 'silent')

    def test_backend_denial_requires_complete_window_and_actual_absence(self):
        self.check['expected'] = 'deny'
        self.item['backend'].pop('stdoutContains'); self.item['backend']['stdoutAbsent'] = ['denied-probe-002']
        data = a.load(self.root / 'backend.json'); data.update(coverageSince=self.since, coverageUntil=self.until)
        self.item['backend'].update(self.save('backend.json', data))
        self.assertIs(self.evaluate()['orders']['backendConfirmed'], True)
        data['coverageSince'] = '1970-01-01T01:00:30Z'
        self.item['backend'].update(self.save('backend.json', data))
        self.assertIsNone(self.evaluate()['orders']['backendConfirmed'])


class WorkflowTests(unittest.TestCase):
    def test_intended_negative_control_is_not_a_new_permission_prompt(self):
        check = {'id': 'wrong-method', 'layer': 'L7', 'destination': '10.0.0.8:8080',
            'authority': 'api.example.com:8080', 'method': 'DELETE', 'path': '/v1/users/1',
            'expected': 'deny', 'result': 'confirmed'}
        rule = {'match': {'hosts': ['api.example.com'], 'ports': [{'port': 8080}],
            'methods': ['DELETE'], 'paths': [{'exact': '/v1/users/1'}]}}
        key = a.refinement_module().permission_id('HTTP/SNI', rule)
        self.assertEqual(w.intentional_denials({'checks': [check]}, vars(a)), set())
        check['intentionalDeny'] = True
        self.assertEqual(w.intentional_denials({'checks': [check]}, vars(a)), {key})
        check['result'] = 'insufficient'
        self.assertEqual(w.intentional_denials({'checks': [check]}, vars(a)), set())

    def test_impossible_intentional_allow_is_rejected(self):
        check = {'id': 'one', 'layer': 'L7', 'destination': '10.0.0.8:8080',
            'authority': 'api.example.com:8080', 'method': 'GET', 'path': '/v1/users/1',
            'expected': 'allow', 'intentionalDeny': True}
        with self.assertRaises(ValueError):
            v.check_results([check], [], vars(a))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        with contextlib.redirect_stdout(io.StringIO()):
            a.observe(a.parser().parse_args(['observe', '--session', str(self.root), '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'client', '--language', 'zh-CN']))

    def test_prepared_review_and_saved_confirmation_are_not_online_claims(self):
        self.assertEqual(w.summary(self.root, vars(a))['stage'], 'prepared')
        a.write(self.root / 'candidate.yaml', candidate())
        result = w.summary(self.root, vars(a))
        self.assertEqual(result['stage'], 'review')
        self.assertEqual(result['nextActor'], 'user')
        self.assertEqual(result['deploymentState'], 'not-queried')
        w.write_summary(self.root, result, vars(a))
        self.assertIn('尚未查询当前集群状态', (self.root / 'workflow-status.md').read_text())

    def test_candidate_change_invalidates_saved_checks_and_language_changes(self):
        a.write(self.root / 'candidate.yaml', candidate())
        receipt = {'kind': 'NetworkProxyVerification', 'observationSession': str(self.root),
            'candidateHash': e.digest(candidate()), 'policy': {'uid': None}, 'eventsHash': e.digest([]),
            'checks': [{'id': 'one', 'result': 'confirmed'}], 'denials': []}
        out = self.root / 'separate'; out.mkdir(); a.write(out / 'events.json', [])
        a.write(out / 'verification.json', receipt)
        result = w.summary(self.root, vars(a), verification=str(out / 'verification.json'))
        self.assertEqual(result['stage'], 'legacy-evidence')
        a.write(self.root / 'candidate.yaml', candidate(audited=False))
        result = w.summary(self.root, vars(a), verification=str(out / 'verification.json'))
        self.assertTrue(result['verificationStale']); self.assertEqual(result['stage'], 'changed')
        saved = a.load(self.root / 'session.json'); saved['reportLanguage'] = 'en'; a.write(self.root / 'session.json', saved)
        self.assertEqual(w.summary(self.root, vars(a))['message'], 'Candidate permissions are ready for business review.')

    def test_new_collection_does_not_reuse_old_success_or_force_rule_rollout(self):
        a.write(self.root / 'candidate.yaml', candidate())
        collection = self.root / 'separate-collection'; collection.mkdir()
        a.write(collection / 'observe.yaml', candidate())
        a.write(collection / 'session.json', {'observationSession': str(self.root), 'verificationMode': 'existing-pods'})
        a.write(collection / 'collector.json', {'phase': 'stopped'})
        w.register_collection(self.root, collection, vars(a))
        out = self.root / 'verification'; out.mkdir()
        a.write(out / 'events.json', [])
        a.write(out / 'verification.json', {'kind': 'NetworkProxyVerification', 'observationSession': str(self.root),
            'candidateHash': e.digest(candidate()), 'policy': {'uid': None}, 'eventsHash': e.digest([]),
            'checks': [{'id': 'one', 'result': 'confirmed'}], 'collectionSession': '/older-collection'})
        result = w.summary(self.root, vars(a), verification=str(out / 'verification.json'))
        self.assertEqual(result['stage'], 'verify')
        self.assertFalse(result['verificationAppliesToCurrentCollection'])
        with patch.object(c, 'handoff_status', return_value={'readyForHandoff': True}), \
                patch.object(a, 'collector_module', return_value=c):
            a.write(collection / 'collector.json', {'phase': 'observing'})
            result = w.summary(self.root, vars(a))
            self.assertEqual(result['stage'], 'enforce-traffic')
            self.assertIn('复用', result['nextAction'])
            self.assertNotIn('重建', result['nextAction'])

    def test_withdraw_then_restore_same_bytes_invalidates_old_result(self):
        a.write(self.root / 'candidate.yaml', candidate())
        out = self.root / 'verification'; out.mkdir(); a.write(out / 'events.json', [])
        a.write(out / 'verification.json', {'kind': 'NetworkProxyVerification', 'observationSession': str(self.root),
            'candidateHash': e.digest(candidate()), 'policy': {'uid': None}, 'eventsHash': e.digest([]),
            'until': '1970-01-01T01:00:00Z', 'checks': [{'id': 'one', 'result': 'confirmed'}]})
        a.write(self.root / 'refinement.json', {'permissionDecisions': [{'at': '1970-01-01T01:01:00Z', 'action': 'restore'}]})
        result = w.summary(self.root, vars(a), verification=str(out / 'verification.json'))
        self.assertTrue(result['verificationStale']); self.assertEqual(result['stage'], 'changed')

    def test_deny_all_and_pending_tcp_are_visible(self):
        a.write(self.root / 'analysis.json', {'pendingTcp': [{'destination': '10.0.0.8:9000'}]})
        self.assertEqual(w.summary(self.root, vars(a))['stage'], 'review')
        p = candidate(); p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress'].pop('httpRules')
        a.write(self.root / 'candidate.yaml', p)
        result = w.summary(self.root, vars(a)); w.write_summary(self.root, result, vars(a))
        self.assertTrue(result['denyAll'])
        self.assertIn('拒绝所有被代理的 TCP', (self.root / 'workflow-status.md').read_text())


if __name__ == '__main__':
    unittest.main()
