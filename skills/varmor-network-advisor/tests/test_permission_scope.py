# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Literal MITM/TCP permissions, unsafe variations and metadata-independent equality."""
import copy
import json
import unittest

from test_evidence_workflow import candidate, projection, listener_dump, a, e


def mixed(audited=True):
    p = candidate(audited=audited)
    p['spec']['policy']['networkProxyConfig'] = {'mitm': {'domains': ['api.example.com']}}
    eg = p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']
    eg['rules'] = [{'ip': '10.0.0.8', 'ports': [{'port': 9090}], 'qualifiers': ['allow', 'audit'] if audited else ['allow']}]
    pr = projection(audited)
    raw = {'permissions': [{'and_rules': {'rules': [
        {'destination_ip': {'address_prefix': '10.0.0.8', 'prefix_len': 32}}, {'destination_port': 9090}]}}],
        'principals': [{'any': True}]}
    for entry in pr['chains'][1]['http']['rbac']:
        value = next(iter(entry.values()))['policies']
        value['http_1'] = value.pop('http_0'); value['egress_0'] = copy.deepcopy(raw)
    pr['chains'][0]['rbac'] = [{'rules': {'action': 'ALLOW', 'policies': {'egress_0': copy.deepcopy(raw)}},
        **({'shadow_rules': {'action': 'ALLOW', 'policies': {'egress_0': copy.deepcopy(raw)}}} if audited else {})}]
    pr['default']['rbac'] = copy.deepcopy(pr['chains'][0]['rbac'])
    mitm = copy.deepcopy(pr['chains'][1]); mitm.update(name='mitm_tls_dns_chain',
        match={'transport_protocol': 'tls', 'server_names': ['api.example.com']}, tlsTermination=True)
    mitm['http']['routing'] = {'ignore_port_in_host_matching': True, 'hosts': [
        {'domains': ['api.example.com', 'api.example.com:*'],
         'routes': [{'match': {'prefix': '/'}, 'cluster': 'mitm_upstream'}]}]}
    pr['chains'].insert(0, mitm)
    return p, pr


class PermissionScopeTests(unittest.TestCase):
    def test_unknown_router_type_or_options_are_rejected(self):
        for config in ({'@type':'unknown-router'},
                {'@type':'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router',
                 'upstream_http_filters':[{'name':'unknown-upstream','typed_config':{'sensitive':'canary'}}]}):
            l=listener_dump()['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
            l['filter_chains'][1]['filters'][0]['typed_config']['http_filters'][-1]['typed_config']=config
            with self.assertRaisesRegex(ValueError,'router') as caught:e.project_listener(l)
            self.assertNotIn('canary',str(caught.exception))

    def test_custom_method_codec_must_accept_the_candidate(self):
        p = candidate(); pr = projection()
        p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['httpRules'][0]['match']['methods'] = ['CUSTOM']
        for entry in pr['chains'][1]['http']['rbac']:
            next(iter(entry.values()))['policies']['http_0']['permissions'][0]['and_rules']['rules'][2]['header']['string_match']['exact'] = 'CUSTOM'
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'confirmed')
        pr['chains'][1]['http']['allow_custom_methods'] = False
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'contradicted')
        normal = projection(); normal['chains'][1]['http']['allow_custom_methods'] = False
        self.assertEqual(e.compare_permissions(candidate(), normal, vars(a))[0], 'confirmed')

    def test_unknown_sensitive_rbac_and_cel_are_rejected_before_persistence(self):
        for target in ('header', 'principal', 'expression'):
            l = listener_dump()['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
            h = l['filter_chains'][1]['filters'][0]['typed_config']
            policy = h['http_filters'][1]['typed_config']['rules']['policies']['http_0']
            if target == 'header':
                policy['permissions'] = [{'header': {'name': 'Authorization', 'string_match': {'exact': 'sensitive-canary'}}}]
            elif target == 'principal':
                policy['principals'] = [{'header': {'name': 'Authorization', 'string_match': {'exact': 'sensitive-canary'}}}]
            else:
                h['access_log'][0]['filter']['or_filter']['filters'][0]['extension_filter']['typed_config']['expression'] = 'sensitive-canary'
            with self.assertRaises(ValueError) as caught: e.project_listener(l)
            self.assertNotIn('sensitive-canary', str(caught.exception))

    def test_mixed_audited_and_quiet_permissions_match_without_version_field(self):
        for audit in (True, False):
            p, pr = mixed(audit)
            self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'confirmed')
        self.assertNotIn('version', json.dumps(pr))

    def test_mitm_tcp_weakenings_are_not_confirmed(self):
        p, pr = mixed()
        mutations = [
            lambda x: x['chains'][0]['match'].update(server_names=['wrong.example.com']),
            lambda x: x['chains'][0].pop('tlsTermination'),
            lambda x: x['chains'][0]['http']['routing']['hosts'][0].update(domains=['*']),
            lambda x: x['chains'][0]['http']['routing'].update(ignore_port_in_host_matching=False),
            lambda x: x['default']['rbac'][0]['rules']['policies']['egress_0']['permissions'][0]['and_rules']['rules'][0]['destination_ip'].update(prefix_len=8),
            lambda x: x['default']['rbac'][0]['rules']['policies']['egress_0']['permissions'][0]['and_rules']['rules'][1].update(destination_port=9091),
            lambda x: x['chains'][0]['http']['rbac'][1]['rules']['policies']['http_1']['permissions'][0]['and_rules']['rules'][3]['url_path'].update(path={'prefix': '/'}),
            lambda x: x['chains'][0]['http']['logs'].clear(),
            lambda x: x['chains'][0]['http']['rbac'][0]['shadow_rules']['policies'].pop('egress_0'),
        ]
        for mutate in mutations:
            changed = copy.deepcopy(pr); mutate(changed)
            self.assertNotEqual(e.compare_permissions(p, changed, vars(a))[0], 'confirmed')

    def test_multi_path_permissions_are_or_branches_not_simultaneous_paths(self):
        p = candidate(); m = p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['httpRules'][0]['match']
        m['paths'].append({'exact': '/v1/users/2'})
        pr = projection()
        for item in pr['chains'][1]['http']['rbac']:
            perms = next(iter(item.values()))['policies']['http_0']['permissions']
            second = copy.deepcopy(perms[0]); second['and_rules']['rules'][3]['url_path']['path'] = {'exact': '/v1/users/2'}
            perms.append(second)
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'confirmed')
        m['methods'] *= 257
        with self.assertRaisesRegex(ValueError, '256 branches'):
            e.supported_rules(p, vars(a))

    def test_listener_and_route_overrides_are_rejected_without_credentials(self):
        for key in ('typed_per_filter_config', 'per_filter_config', 'filter_action'):
            d = listener_dump(); l = d['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
            l['filter_chains'][1]['filters'][0]['typed_config']['route_config'][key] = {'secret-canary': 'disabled-rbac'}
            with self.assertRaisesRegex(ValueError, 'overrides'):
                e.project_listener(l)
        l = listener_dump()['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
        l['filter_chain_matcher'] = {'on_no_match': {}}
        with self.assertRaises(ValueError): e.project_listener(l)

    def test_unknown_scopes_stay_insufficient(self):
        p, pr = mixed()
        for value in ('*.example.com', '10.0.0.8', '10.0.0.0/8'):
            changed = copy.deepcopy(p); changed['spec']['policy']['networkProxyConfig']['mitm']['domains'] = [value]
            self.assertEqual(e.compare_permissions(changed, pr, vars(a))[0], 'insufficient')
        changed = copy.deepcopy(p); changed['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['rules'][0]['ports'][0]['endPort'] = 9099
        self.assertEqual(e.compare_permissions(changed, pr, vars(a))[0], 'insufficient')

    def test_saved_projection_unknown_fields_and_scalar_types_are_rejected(self):
        p, pr = mixed()
        edits = [lambda x: x.update(filter_chain_matcher={}),
            lambda x: x['chains'][0].update(transport_socket_matches=[]),
            lambda x: x['chains'][0]['http'].update(upgrade_configs=[]),
            lambda x: x['chains'][0].update(tlsTermination='false'),
            lambda x: x['chains'][0]['http']['routing'].update(ignore_port_in_host_matching=1)]
        for edit in edits:
            x = copy.deepcopy(pr); edit(x)
            self.assertEqual(e.compare_permissions(p, x, vars(a))[0], 'insufficient')
        pr['chains'][0]['http']['rbac'][1]['rules']['policies']['http_1']['principals'][0]['any'] = 1
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'contradicted')

    def test_upgrades_mirrors_and_header_rewrites_are_not_silently_dropped(self):
        changes = [
            lambda c: c.update(upgrade_configs=[{'upgrade_type': 'websocket', 'enabled': True,
                'filters': [{'name': 'envoy.filters.http.router'}]}]),
            lambda c: c['route_config']['virtual_hosts'][0]['routes'][0]['route'].update(request_mirror_policies=[{'cluster': 'mirror'}]),
            lambda c: c['route_config']['virtual_hosts'][0]['routes'][0]['route'].update(host_rewrite_literal='elsewhere.test'),
            lambda c: c['route_config']['virtual_hosts'][0].update(request_headers_to_add=[{'header': {'key': 'authorization', 'value': 'private-token'}}]),
        ]
        for change in changes:
            l = listener_dump()['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
            change(l['filter_chains'][1]['filters'][0]['typed_config'])
            with self.assertRaises(ValueError) as caught:
                e.project_listener(l)
            self.assertNotIn('private-token', str(caught.exception))

    def test_transport_routes_and_inspector_semantics_are_checked(self):
        p = candidate(); pr = projection()
        pr['default']['tcp']['cluster'] = 'unapproved'
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'contradicted')
        pr = projection(); pr['chains'][1]['http']['routing']['hosts'][0]['routes'][0]['cluster'] = 'unapproved'
        self.assertEqual(e.compare_permissions(p, pr, vars(a))[0], 'contradicted')
        l = listener_dump()['configs'][0]['dynamic_listeners'][0]['active_state']['listener']
        l['listener_filters'][1]['filter_disabled'] = {'any_match': True}
        with self.assertRaisesRegex(ValueError, 'inspector'):
            e.project_listener(l)


if __name__ == '__main__':
    unittest.main()
