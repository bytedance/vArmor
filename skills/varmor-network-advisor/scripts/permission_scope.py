# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Bounded literal permission oracle for the supported vArmor listener layout."""
import copy
import ipaddress
import itertools
import json
import math
import re


def ports(values):
    if not isinstance(values, list) or not 1 <= len(values) <= 16 or any(
            not isinstance(p, dict) or set(p) != {'port'} or type(p['port']) is not int or
            not 1 <= p['port'] <= 65535 for p in values):
        raise ValueError('Automatic proof requires bounded exact ports; ranges remain unsupported')


def qualifier(rule):
    if not isinstance(rule, dict):
        raise ValueError('Automatic proof requires rule objects')
    q = rule.get('qualifiers', [])
    if not isinstance(q, list) or any(not isinstance(x, str) for x in q) or \
            set(q) not in ({'allow'}, {'allow', 'audit'}) or len(q) != len(set(q)):
        raise ValueError('Automatic proof supports allow or allow+audit, without explicit denies')


def scope(policy, api):
    body = copy.deepcopy(policy['spec']['policy'])
    eg = api['network_rules'](body).get('egress', {})
    if eg.get('defaultAction') != 'deny' or set(eg) - {'defaultAction', 'rules', 'httpRules'}:
        raise ValueError('Automatic proof requires the supported default-deny egress layout')
    http, raw = eg.get('httpRules', []), eg.get('rules', [])
    if not isinstance(http, list) or not isinstance(raw, list) or len(http) + len(raw) > 128:
        raise ValueError('Automatic proof requires a bounded rule list')
    for rule in http:
        qualifier(rule)
        m = rule.get('match', {})
        if set(rule) - {'match', 'qualifiers', 'description'} or not isinstance(m, dict) or \
                set(m) - {'hosts', 'ports', 'paths', 'methods'}:
            raise ValueError('Unsupported automatic HTTP match shape')
        hosts = m.get('hosts', [])
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 16 or any(
                not isinstance(h, str) or '*' in h or ':' in h or api['host'](h) != h for h in hosts):
            raise ValueError('Automatic proof requires canonical literal hosts; wildcards remain unsupported')
        ports(m.get('ports'))
        methods, paths = m.get('methods', []), m.get('paths', [])
        if not isinstance(methods, list) or any(not isinstance(x, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", x) for x in methods):
            raise ValueError('Unsupported automatic HTTP methods')
        if not isinstance(paths, list) or any(not isinstance(p, dict) or len(p) != 1 or
                not set(p) <= {'exact', 'prefix'} or any(not api['safe_text'](x) or not x.startswith('/') or '?' in x for x in p.values()) for p in paths):
            raise ValueError('Unsupported automatic path match')
        if math.prod([len(hosts), len(m['ports']), max(1, len(methods)), max(1, len(paths))]) > 256:
            raise ValueError('Automatic proof match expansion exceeds 256 branches per rule')
    for rule in raw:
        qualifier(rule)
        if set(rule) - {'ip', 'ports', 'qualifiers', 'description'} or \
                str(ipaddress.ip_address(rule.get('ip', ''))) != rule.get('ip'):
            raise ValueError('Automatic TCP proof requires a canonical literal IP; CIDRs remain unsupported')
        ports(rule.get('ports'))
    mitm = body.get('networkProxyConfig', {}).get('mitm', {})
    if not isinstance(mitm, dict) or set(mitm) - {'domains', 'headerMutations'} or mitm.get('headerMutations'):
        raise ValueError('Automatic MITM proof does not cover header mutations or unknown options')
    domains = mitm.get('domains', [])
    if not isinstance(domains, list) or any(not isinstance(h, str) for h in domains) or \
            len(domains) > 16 or len(domains) != len(set(domains)):
        raise ValueError('Unsupported automatic MITM domain set')
    for h in domains:
        if not isinstance(h, str) or '*' in h or ':' in h or '/' in h or api['host'](h) != h:
            raise ValueError('Automatic MITM proof requires literal DNS domains')
        try:
            ipaddress.ip_address(h)
        except ValueError:
            continue
        raise ValueError('Automatic IP-based MITM remains unsupported')
    return http, raw, domains


def header(name, value, fold=False):
    return {'header': {'name': name, 'string_match': {'exact': value, **({'ignore_case': True} if fold else {})}}}


def rbac(http, tls=False, raw=()):
    policies = {}
    def permission(parts):
        return parts[0] if len(parts) == 1 else {'and_rules': {'rules': parts}}
    for i, rule in enumerate(raw):
        address = ipaddress.ip_address(rule['ip'])
        ps = [permission([{'destination_ip': {'address_prefix': str(address), 'prefix_len': address.max_prefixlen}},
                          {'destination_port': port['port']}]) for port in rule['ports']]
        policies['egress_' + str(i)] = {'permissions': ps, 'principals': [{'any': True}]}
    for i, rule in enumerate(http, len(raw)):
        m = rule['match']; ps = []
        for host, port, method, path in itertools.product(m['hosts'], m['ports'],
                [None] if tls else m.get('methods') or [None], [None] if tls else m.get('paths') or [None]):
            p = port['port']
            if tls:
                first = {'requested_server_name': {'exact': host, 'ignore_case': True}}
            else:
                explicit = header(':authority', host + ':' + str(p), True)
                first = {'or_rules': {'rules': [header(':authority', host, True), explicit]}} if p in (80, 443) else explicit
            parts = [first, {'destination_port': p}]
            if method is not None: parts.append(header(':method', method))
            if path is not None: parts.append({'url_path': {'path': path}})
            ps.append(permission(parts))
        policies['http_' + str(i)] = {'permissions': ps, 'principals': [{'any': True}]}
    return {'action': 'ALLOW', 'policies': policies}


def filter_hosts(rules, hosts, inside):
    result = []
    for rule in rules:
        selected = [h for h in rule['match']['hosts'] if (h in hosts) == inside]
        if selected:
            r = copy.deepcopy(rule); r['match']['hosts'] = selected; result.append(r)
    return result


def compare(policy, projected, api, log_filter):
    http, raw, domains = scope(policy, api)
    def shape(value, allowed):
        if not isinstance(value, dict) or set(value) - set(allowed):
            raise ValueError('Unknown permission projection fields')
    def equal(left, right):
        # JSON distinguishes booleans from numeric 0/1; Python equality does not.
        return json.dumps(left, sort_keys=True) == json.dumps(right, sort_keys=True)
    shape(projected, {'name', 'inspectors', 'chains', 'default', 'logs'})
    for chain in projected.get('chains', []) + [projected.get('default', {})]:
        shape(chain, {'name', 'match', 'filters', 'rbac', 'tlsTermination', 'http', 'tcp'})
        if 'tlsTermination' in chain and type(chain['tlsTermination']) is not bool:
            raise ValueError('TLS termination projection requires a boolean')
        if 'http' in chain:
            area = chain['http']
            shape(area, {'filters', 'rbac', 'normalize_path', 'merge_slashes',
                         'path_with_escaped_slashes_action', 'logs', 'routing', 'allow_custom_methods'})
            if type(area.get('allow_custom_methods')) is not bool:
                raise ValueError('HTTP custom-method projection requires a boolean')
            if chain.get('rbac') != [] or chain['name'] not in ('http_chain', 'mitm_tls_dns_chain'):
                raise ValueError('Unexpected HTTP or network RBAC projection')
            if 'routing' in area:
                route = area['routing']; shape(route, {'ignore_port_in_host_matching', 'hosts'})
                if type(route.get('ignore_port_in_host_matching')) is not bool:
                    raise ValueError('Routing port-matching projection requires a boolean')
                for host in route.get('hosts', []):
                    shape(host, {'domains', 'routes'})
                    for entry in host.get('routes', []):
                        shape(entry, {'match', 'cluster'})
    audit_http = [r for r in http if 'audit' in r['qualifiers']]
    audit_raw = [r for r in raw if 'audit' in r['qualifiers']]
    names = {'http_chain', 'tls_chain'} | ({'mitm_tls_dns_chain'} if domains else set())
    inspectors = ['envoy.filters.listener.' + x for x in ('original_dst', 'tls_inspector', 'http_inspector')]
    if projected.get('name') != 'varmor_outbound' or projected.get('inspectors') != inspectors:
        return 'insufficient', 'Unknown listener or inspector layout'
    chains = projected.get('chains', [])
    if len(chains) != len(names) or {x.get('name') for x in chains} != names:
        return 'insufficient', 'Unknown filter-chain layout'
    for chain in chains:
        mitm = chain['name'] == 'mitm_tls_dns_chain'
        hcm = chain['name'] != 'tls_chain'
        selection = {'transport_protocol': 'tls', 'server_names': domains} if mitm else \
            {'application_protocols': ['http/1.0', 'http/1.1', 'h2c']} if hcm else {'transport_protocol': 'tls'}
        if not equal(chain.get('match'), selection) or chain.get('tlsTermination', False) is not mitm:
            return 'contradicted', 'Chain selection or TLS termination differs from the candidate'
        fs = ['envoy.filters.network.http_connection_manager'] if hcm else ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy']
        if chain.get('filters') != fs:
            return 'insufficient', 'Unknown or additional network filters'
        expected_tcp = {'cluster': 'original_dst', 'upstream_connect_mode': 'ON_DOWNSTREAM_DATA', 'max_early_data_bytes': 8192}
        if (hcm and 'tcp' in chain) or (not hcm and not equal(chain.get('tcp'), expected_tcp)):
            return 'contradicted', 'TCP routing or RBAC-before-connect behavior differs'
        rules = filter_hosts(http, domains, mitm) if domains and (mitm or not hcm) else http
        audited = filter_hosts(audit_http, domains, mitm) if domains and (mitm or not hcm) else audit_http
        area = chain.get('http', {}) if hcm else chain
        if hcm and any(method not in {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'}
                for r in rules for method in r['match'].get('methods', [])) and not area.get('allow_custom_methods'):
            return 'contradicted', 'HTTP codec does not accept the candidate custom methods'
        wanted = [{'rules': rbac(rules, not hcm, raw)}]
        has_shadow = bool(audited or audit_raw)
        if has_shadow:
            shadow = rbac(audited, not hcm, audit_raw)
            if hcm: wanted.insert(0, {'shadow_rules': shadow})
            else: wanted[0]['shadow_rules'] = shadow
        if not equal(area.get('rbac'), wanted):
            return 'contradicted', 'Active default action, permission scope or audit qualifiers differ from candidate'
        if hcm and (area.get('filters') != ['envoy.filters.http.rbac'] * len(wanted) + ['envoy.filters.http.router'] or
                area.get('normalize_path') is not True or area.get('merge_slashes') is not True or
                area.get('path_with_escaped_slashes_action') != 'UNESCAPE_AND_FORWARD' or
                not equal(area.get('logs'), [log_filter(has_shadow, True)])):
            return 'contradicted', 'HTTP filter order, normalization or audit selection differs'
        if hcm:
            expected = {'ignore_port_in_host_matching': True, 'hosts': [
                {'domains': [host, host + ':*'], 'routes': [{'match': {'prefix': '/'}, 'cluster': 'mitm_upstream'}]}
                for host in domains]} if mitm else {'ignore_port_in_host_matching': False,
                'hosts': [{'domains': ['*'], 'routes': [{'match': {'prefix': '/'}, 'cluster': 'original_dst'}]}]}
            if not equal(area.get('routing'), expected):
                return 'contradicted', 'MITM domain routing or anti-domain-fronting boundary differs'
    default = projected.get('default', {})
    expected = {'rules': rbac([], raw=raw)}
    if audit_raw: expected['shadow_rules'] = rbac([], raw=audit_raw)
    if default.get('name') != 'tcp_default_chain' or default.get('match') or default.get('tlsTermination') or \
            not equal(default.get('tcp'), expected_tcp) or \
            default.get('filters') != ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy'] or \
            not equal(default.get('rbac'), [expected]) or not equal(projected.get('logs'), [log_filter(bool(audit_http or audit_raw))]):
        return 'contradicted', 'Default TCP permissions or listener audit selection differ'
    return 'confirmed', 'Active HTTP/SNI, literal DNS MITM and literal TCP permissions and audit selection match the candidate'
