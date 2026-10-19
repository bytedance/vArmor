# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Read-only permission checks and hash-bound, mechanically checked receipts.

Source authenticity remains the responsibility of the supplying operator.
Unknown proxy shapes remain insufficient, never an inferred success.
"""
import copy
import datetime as dt
import hashlib
import http.client
import io
import importlib.util
import json
import re
from pathlib import Path


MAX_RECEIPT = 4 * 1024 * 1024


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def instant(value):
    if not isinstance(value, str):
        raise ValueError('Receipt timestamp must be a timezone-aware string')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Receipt timestamps require explicit timezones')
    return parsed


def read_pinned(reference):
    """Read once, then verify the bytes used, including missing/changed-file failures."""
    path = Path(reference['file'])
    if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_RECEIPT:
        raise ValueError('Receipt must be a bounded regular file at an absolute path')
    with path.open('rb') as source:
        raw = source.read(MAX_RECEIPT + 1)
    if len(raw) > MAX_RECEIPT or hashlib.sha256(raw).hexdigest() != reference['sha256']:
        raise ValueError('Receipt byte hash differs from the supplied hash')
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError('Source receipt must be a JSON object')
    return value


def header(name, value, fold=False):
    return {'header': {'name': name, 'string_match': {'exact': value, **({'ignore_case': True} if fold else {})}}}


def permission_module():
    spec = importlib.util.spec_from_file_location('varmor_permission_scope', Path(__file__).with_name('permission_scope.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_rbac(rules, tls=False, raw=()):
    return permission_module().rbac(rules, tls, raw)


def supported_rules(policy, api):
    return permission_module().scope(policy, api)[0]


def normalize_rbac(value):
    result = copy.deepcopy(value)
    result.setdefault('action', 'ALLOW')  # Envoy omits the protobuf zero enum.
    result.setdefault('policies', {})
    return result


def log_filter(shadow, http=False):
    namespace = 'http' if http else 'network'
    deny = ('response.code_details' if http else 'connection.termination_details') + '.matches("rbac_access_denied.*")'
    expressions = [deny]
    if shadow:
        expressions.append("'shadow_effective_policy_id' in metadata.filter_metadata['envoy.filters." + namespace + ".rbac']")
    filters = [{'extension_filter': {'name': 'envoy.access_loggers.extension_filters.cel', 'typed_config': {
        '@type': 'type.googleapis.com/envoy.extensions.access_loggers.filters.cel.v3.ExpressionFilter', 'expression': value}}}
        for value in expressions]
    return {'or_filter': {'filters': filters}} if shadow else filters[0]


def project_listener(listener):
    """Persist only permission and audit selection fields, never credentials or Secrets."""
    if listener.get('filter_chain_matcher'):
        raise ValueError('Listener matcher overrides are unsupported')
    if set(listener) - {'@type', 'name', 'address', 'additional_addresses', 'socket_options',
            'listener_filters', 'filter_chains', 'default_filter_chain', 'access_log'}:
        raise ValueError('Unknown listener options are unsupported')
    inspector_types = {'original_dst': 'OriginalDst', 'tls_inspector': 'TlsInspector', 'http_inspector': 'HttpInspector'}
    for inspector in listener.get('listener_filters', []):
        short = inspector.get('name', '').removeprefix('envoy.filters.listener.')
        expected_type = 'type.googleapis.com/envoy.extensions.filters.listener.' + short + '.v3.' + inspector_types.get(short, '')
        if set(inspector) - {'name', 'typed_config'} or inspector.get('typed_config') != {'@type': expected_type} or short not in inspector_types:
            raise ValueError('Unknown or disabled listener inspector configuration')
    def rbac_config(config, layer):
        if config.get('@type') != 'type.googleapis.com/envoy.extensions.filters.' + layer + '.rbac.v3.RBAC' or \
                set(config) - {'@type', 'rules', 'shadow_rules', 'stat_prefix', 'rules_stat_prefix', 'shadow_rules_stat_prefix'}:
            raise ValueError('Unknown RBAC configuration fields or matcher overrides')
        def permission(value, depth=0):
            if not isinstance(value, dict) or len(value) != 1 or depth > 16:
                raise ValueError('Unknown RBAC permission tree')
            key, data = next(iter(value.items()))
            if key in ('and_rules', 'or_rules'):
                if not isinstance(data, dict) or set(data) != {'rules'} or not isinstance(data['rules'], list) or len(data['rules']) > 256:
                    raise ValueError('Unsupported RBAC permission branches')
                for item in data['rules']: permission(item, depth + 1)
            elif key in ('header', 'requested_server_name'):
                if not isinstance(data, dict) or set(data) - ({'name', 'string_match'} if key == 'header' else {'exact', 'ignore_case'}):
                    raise ValueError('Unknown RBAC header or SNI match')
                if key == 'header' and data.get('name') not in (':authority', ':method'):
                    raise ValueError('Unsupported RBAC header; sensitive values are not persisted')
                match = data.get('string_match', {}) if key == 'header' else data
                if not isinstance(match, dict) or set(match) - {'exact', 'ignore_case'} or not isinstance(match.get('exact'), str):
                    raise ValueError('Unsupported RBAC string match')
            elif key == 'destination_ip':
                if not isinstance(data, dict) or set(data) != {'address_prefix', 'prefix_len'} or not isinstance(data['address_prefix'], str) or type(data['prefix_len']) is not int:
                    raise ValueError('Unsupported RBAC destination IP')
            elif key == 'destination_port':
                if type(data) is not int: raise ValueError('Unsupported RBAC destination port')
            elif key == 'url_path':
                if not isinstance(data, dict) or set(data) != {'path'} or not isinstance(data['path'], dict) or len(data['path']) != 1 or not set(data['path']) <= {'exact', 'prefix'} or not all(isinstance(v, str) for v in data['path'].values()):
                    raise ValueError('Unsupported RBAC URL path')
            else:
                raise ValueError('Unknown RBAC permission; sensitive values are not persisted')
        result = {}
        for key in ('rules', 'shadow_rules'):
            if key not in config: continue
            value = normalize_rbac(config[key])
            if set(value) != {'action', 'policies'} or value['action'] not in ('ALLOW', 'DENY') or not isinstance(value['policies'], dict) or len(value['policies']) > 128:
                raise ValueError('Unsupported RBAC policy layout')
            for name, policy in value['policies'].items():
                if not isinstance(name, str) or not re.fullmatch(r'(egress|http)_[0-9]+', name) or not isinstance(policy, dict) or set(policy) != {'permissions', 'principals'} or json.dumps(policy['principals']) != '[{"any": true}]' or not isinstance(policy['permissions'], list) or len(policy['permissions']) > 256:
                    raise ValueError('Unknown RBAC policies or principals are not persisted')
                for item in policy['permissions']: permission(item)
            result[key] = value
        return result
    def audit_filters(logs, http=False):
        filters = [x.get('filter') for x in logs]
        for item in filters:
            if item not in (log_filter(False, http), log_filter(True, http)):
                raise ValueError('Unknown audit selection expressions are not persisted')
        return filters

    def project(chain):
        fs = chain.get('filters', [])
        result = {'name': chain.get('name'), 'match': chain.get('filter_chain_match', {}),
                  'filters': [f['name'] for f in fs], 'rbac': []}
        transport = chain.get('transport_socket')
        if transport:
            if transport.get('name') != 'envoy.transport_sockets.tls' or \
                    transport.get('typed_config', {}).get('@type') != 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext':
                raise ValueError('Unsupported downstream TLS transport')
            result['tlsTermination'] = True  # No certificate, key or SDS contents persisted.
        if chain.get('transport_socket_matches'):
            raise ValueError('Conditional transport sockets are unsupported')
        for f in fs:
            if set(f) - {'name', 'typed_config'}:
                raise ValueError('Unknown network filter discovery or options')
            config = f.get('typed_config', {})
            if f['name'] == 'envoy.filters.network.rbac':
                result['rbac'].append(rbac_config(config, 'network'))
            elif f['name'] == 'envoy.filters.network.http_connection_manager':
                if config.get('@type') != 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager':
                    raise ValueError('Unknown HTTP connection manager type')
                if set(config) - {'@type', 'stat_prefix', 'internal_address_config', 'http_protocol_options',
                        'stream_idle_timeout', 'normalize_path', 'merge_slashes', 'path_with_escaped_slashes_action',
                        'route_config', 'http_filters', 'access_log'}:
                    raise ValueError('Unknown HTTP manager fields, upgrades or routing overrides are unsupported')
                if config.get('internal_address_config', {}) or set(config.get('http_protocol_options', {})) - {'allow_custom_methods'}:
                    raise ValueError('Unknown HTTP protocol or address options are unsupported')
                custom_methods = config.get('http_protocol_options', {}).get('allow_custom_methods', False)
                if type(custom_methods) is not bool:
                    raise ValueError('HTTP custom-method option requires a boolean')
                http_filters = config.get('http_filters', [])
                if any(x.get('disabled') or set(x) - {'name', 'typed_config', 'disabled'} for x in http_filters):
                    raise ValueError('Disabled or dynamically supplied HTTP filters are unsupported')
                for item in http_filters:
                    if item['name'] == 'envoy.filters.http.router' and item.get('typed_config') != {
                            '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'}:
                        raise ValueError('Unknown HTTP router type or options are unsupported')
                def reject_overrides(value):
                    if isinstance(value, dict):
                        if set(value) & {'typed_per_filter_config', 'per_filter_config', 'filter_action'}:
                            raise ValueError('Per-route filter overrides are unsupported')
                        for v in value.values(): reject_overrides(v)
                    elif isinstance(value, list):
                        for v in value: reject_overrides(v)
                route = config.get('route_config', {})
                reject_overrides(route)
                if set(route) - {'name', 'ignore_port_in_host_matching', 'validate_clusters', 'virtual_hosts'}:
                    raise ValueError('Unknown route configuration fields are unsupported')
                for vh in route.get('virtual_hosts', []):
                    if set(vh) - {'name', 'domains', 'routes'}:
                        raise ValueError('Unknown virtual host fields, header mutation or overrides are unsupported')
                    for r in vh.get('routes', []):
                        if set(r) - {'match', 'route'} or set(r.get('match', {})) - {'prefix'} or \
                                set(r.get('route', {})) - {'cluster', 'timeout'}:
                            raise ValueError('Unknown routes, mirrors or rewrites are unsupported')
                result['http'] = {'filters': [x['name'] for x in http_filters],
                    'rbac': [rbac_config(x['typed_config'], 'http')
                             for x in http_filters if x['name'] == 'envoy.filters.http.rbac'],
                    'normalize_path': config.get('normalize_path', False),
                    'merge_slashes': config.get('merge_slashes', False),
                    'allow_custom_methods': custom_methods,
                    'path_with_escaped_slashes_action': config.get('path_with_escaped_slashes_action'),
                    'logs': audit_filters(config.get('access_log', []), True)}
                result['http']['routing'] = {'ignore_port_in_host_matching': route.get('ignore_port_in_host_matching', False),
                    'hosts': [{'domains': vh.get('domains', []), 'routes': [
                        {'match': r.get('match', {}), 'cluster': r.get('route', {}).get('cluster')}
                        for r in vh.get('routes', [])]} for vh in route.get('virtual_hosts', [])]}
            elif f['name'] == 'envoy.filters.network.tcp_proxy':
                if config.get('@type') != 'type.googleapis.com/envoy.extensions.filters.network.tcp_proxy.v3.TcpProxy' or \
                        set(config) - {'@type', 'stat_prefix', 'cluster', 'idle_timeout', 'upstream_connect_mode', 'max_early_data_bytes'}:
                    raise ValueError('Unknown TCP proxy routing or options')
                result['tcp'] = {k: config.get(k) for k in ('cluster', 'upstream_connect_mode', 'max_early_data_bytes')}
        return result
    return {'name': listener.get('name'), 'inspectors': [x['name'] for x in listener.get('listener_filters', [])],
            'chains': [project(x) for x in listener.get('filter_chains', [])],
            'default': project(listener.get('default_filter_chain', {})),
            'logs': audit_filters(listener.get('access_log', []))}


def _compare_permissions(policy, projected, api):
    try:
        return permission_module().compare(policy, projected, api, log_filter)
    except ValueError as exc:
        return 'insufficient', str(exc)


def compare_permissions(policy, projected, api):
    try:
        return _compare_permissions(policy, projected, api)
    except (KeyError, ValueError, TypeError, AttributeError, IndexError):
        return 'insufficient', 'Unsupported or malformed active permission projection'


def active_config(args, api):
    root = Path(args.session).resolve()
    state, candidate = api['load'](root / 'session.json'), api['load'](args.policy_file)
    pods, policy = api['live_inventory'](state, candidate)
    selected = [p for p in pods if p['metadata']['uid'] == args.pod_uid]
    if len(selected) != 1 or args.pod_uid in state.get('baselinePodUIDs', []):
        raise ValueError('Select one currently injected Pod UID outside the observation baseline')
    supported_rules(candidate, api)  # Reject unsupported scope before exec.
    pod = selected[0]
    config = candidate['spec']['policy'].get('networkProxyConfig', {})
    uid, port = config.get('proxyUID', 1337), config.get('proxyAdminPort', 15000)
    if type(uid) is not int or not 0 <= uid <= 2**31 - 1 or type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('Invalid proxy UID/admin port')
    pinned = {'uid': policy['metadata']['uid'], 'generation': policy['metadata'].get('generation'), 'specHash': digest(policy['spec'])}
    started = api['now']()
    # Fixed local admin read, under the actual proxy UID to avoid redirection.
    # Bound response bytes in the sidecar; never persist the complete config dump.
    script = 'exec 3<>/dev/tcp/127.0.0.1/' + str(port) + '; printf "GET /config_dump HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n" >&3; head -c ' + str(MAX_RECEIPT + 1) + ' <&3'
    raw = api['kube'](state['context'], 'exec', '-n', state['namespace'], pod['metadata']['name'],
        '-c', 'varmor-network-proxy', '--', 'timeout', '15', 'setpriv', '--reuid=' + str(uid),
        '--regid=' + str(uid), '--clear-groups', 'bash', '-c', script, binary=True)
    if len(raw) > MAX_RECEIPT:
        raise ValueError('Admin response exceeds the bounded evidence limit')
    class Socket:
        def makefile(self, *unused):
            return io.BytesIO(raw)
    try:
        response = http.client.HTTPResponse(Socket())
        response.begin()
        if response.status != 200:
            raise ValueError('Proxy admin configuration read did not return HTTP 200')
        dump = json.loads(response.read())
    except (http.client.HTTPException, json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError('Invalid or incomplete proxy admin response') from None
    try:
        listeners = [x['active_state']['listener'] for block in dump.get('configs', [])
            if block.get('@type', '').endswith('ListenersConfigDump') for x in block.get('dynamic_listeners', [])
            if x.get('name') == 'varmor_outbound' and x.get('active_state') and not x.get('error_state')]
    except (KeyError, TypeError, AttributeError):
        raise ValueError('Unsupported proxy admin configuration structure') from None
    if len(listeners) != 1:
        raise ValueError('A unique active outbound listener without update errors is required')
    projected = project_listener(listeners[0])
    result, basis = compare_permissions(candidate, projected, api)
    current = api['get'](state['context'], 'varmorpolicies', state['namespace'], state['policy'])
    current_pod = api['get'](state['context'], 'pods', state['namespace'], pod['metadata']['name'])
    if pinned != {'uid': current['metadata']['uid'], 'generation': current['metadata'].get('generation'), 'specHash': digest(current['spec'])} or \
            current_pod['metadata']['uid'] != args.pod_uid:
        raise ValueError('Policy or Pod identity changed during active configuration read')
    proof = {'kind': 'NetworkProxyActivePermissionProof', 'candidateHash': digest(candidate), 'policy': pinned,
        'podUID': args.pod_uid, 'startedAt': started, 'checkedAt': api['now'](), 'result': result, 'basis': basis,
        'permissionsHash': digest(projected),
        'scope': 'HTTP/SNI, literal DNS MITM and literal TCP permission enforcement, path normalization and audit selection; not full xDS, credentials or business coverage'}
    # Only a supported projection equal to the reviewed candidate is persisted.
    # Failed checks retain their result and hash, never unknown match values.
    if result == 'confirmed':
        proof['permissions'] = projected
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    api['write'](output, proof)
    print(json.dumps({'result': result, 'basis': basis, 'checkedAt': proof['checkedAt'], 'file': str(output)}, ensure_ascii=False))
    return 0 if result == 'confirmed' else 2


def command_result(reference, check, pod_uid, since, until, role):
    receipt = read_pinned(reference)
    begun, ended = instant(receipt['startedAt']), instant(receipt['endedAt'])
    timely = since <= begun <= ended <= until if role == 'client' else until <= begun <= ended and (ended - until).total_seconds() <= 300
    if receipt.get('kind') != 'NetworkProxyCommandReceipt' or receipt.get('checkId') != check['id'] or \
            receipt.get('podUID') != pod_uid or not timely:
        raise ValueError('Command receipt identity or execution window differs from the check')
    contains, absent = reference.get('stdoutContains', []), reference.get('stdoutAbsent', [])
    if not isinstance(contains, list) or not isinstance(absent, list) or not (contains or absent) or \
            any(not isinstance(x, str) or not x for x in contains + absent) or \
            not isinstance(receipt.get('stdout'), str) or type(reference.get('exitCode')) is not int or \
            type(receipt.get('exitCode')) is not int:
        raise ValueError('Source receipts require an exit code and nonempty literal output predicates')
    if role == 'client' and not contains:
        raise ValueError('Client evidence needs a positive protocol/status marker; empty output does not prove denial')
    if role == 'backend' and check['expected'] == 'deny':
        if not absent or instant(receipt.get('coverageSince', '')) > since or instant(receipt.get('coverageUntil', '')) < until:
            raise ValueError('Backend denial evidence must cover the complete traffic window and an absent request marker')
    elif role == 'backend' and not contains:
        raise ValueError('Backend allow evidence requires the actual received request marker')
    return receipt['exitCode'] == reference['exitCode'] and all(x in receipt['stdout'] for x in contains) and \
        all(x not in receipt['stdout'] for x in absent)


def evaluate_bundle(bundle, checks, candidate, pinned, pod_uids, since, until, api):
    """Bind checks to exact candidate/window/UIDs; never trust declared confirmation flags."""
    start, end = instant(since), instant(until)
    if not isinstance(bundle, dict) or not isinstance(bundle.get('podUIDs'), list) or \
            any(not isinstance(x, str) for x in bundle['podUIDs']):
        raise ValueError('Receipt bundle must be an object with explicit Pod UID strings')
    if bundle.get('kind') != 'NetworkProxyCheckReceipts' or bundle.get('candidateHash') != digest(candidate) or \
            bundle.get('policy') != pinned or set(bundle.get('podUIDs', [])) != set(pod_uids) or \
            instant(bundle['since']) != start or instant(bundle['until']) != end:
        raise ValueError('Receipt bundle candidate, policy, UID set and window must match verification')
    items = bundle.get('checks', [])
    if not isinstance(items, list) or any(not isinstance(x, dict) or not isinstance(x.get('id'), str) for x in items):
        raise ValueError('Receipt bundle requires a list of named check objects')
    by_id = {x['id']: x for x in items}
    if len(by_id) != len(items) or set(by_id) != {x['id'] for x in checks}:
        raise ValueError('Receipt checks must match the complete unique check list')
    results = {}
    for check in checks:
        item = by_id[check['id']]
        if item.get('podUID') not in pod_uids:
            raise ValueError('Receipt check Pod UID is not selected')
        result = {'clientConfirmed': None, 'backendConfirmed': None, 'configurationConfirmed': None,
                  'podUID': item['podUID'], 'problems': []}
        for role in ('client', 'backend'):
            if role not in item:
                continue
            try:
                result[role + 'Confirmed'] = command_result(item[role], check, item['podUID'], start, end, role)
            except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
                result['problems'].append(role + ': ' + str(exc))
        try:
            proofs = [read_pinned(r) for r in item.get('configuration', [])]
            valid = []
            for proof in proofs:
                if proof.get('kind') != 'NetworkProxyActivePermissionProof' or proof.get('candidateHash') != digest(candidate) or \
                        proof.get('policy') != pinned or proof.get('podUID') != item['podUID'] or \
                        proof.get('permissionsHash') != digest(proof.get('permissions')):
                    raise ValueError('Active permission proof binding/hash differs')
                verdict, basis = compare_permissions(candidate, proof['permissions'], api)
                if verdict != 'confirmed':
                    if verdict == 'contradicted':
                        result['configurationConfirmed'] = False
                    raise ValueError(basis)
                if instant(proof['startedAt']) > instant(proof['checkedAt']):
                    raise ValueError('Active permission proof time order differs')
                valid.append(proof)
            # Bracket traffic with actual reads; saved success booleans are ignored.
            result['configurationConfirmed'] = True if any(instant(x['checkedAt']) <= start and
                (start - instant(x['checkedAt'])).total_seconds() <= 300 for x in valid) and \
                any(instant(x['startedAt']) >= end and (instant(x['checkedAt']) - end).total_seconds() <= 300 for x in valid) else None
            if result['configurationConfirmed'] is not True:
                result['problems'].append('configuration: matching before/after permission reads are missing or stale')
        except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            result['problems'].append('configuration: ' + str(exc))
        results[check['id']] = result
    return results
