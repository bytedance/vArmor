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
import json
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


def expected_rbac(rules, tls=False):
    policies = {}
    for index, rule in enumerate(rules):
        match = rule['match']
        host, port = match['hosts'][0], match['ports'][0]['port']
        if tls:
            parts = [{'requested_server_name': {'exact': host, 'ignore_case': True}}]
        else:
            explicit = header(':authority', host + ':' + str(port), True)
            parts = [{'or_rules': {'rules': [header(':authority', host, True), explicit]}}] if port in (80, 443) else [explicit]
        parts.append({'destination_port': port})
        if not tls:
            if match.get('methods'):
                parts.append(header(':method', match['methods'][0]))
            if match.get('paths'):
                parts.append({'url_path': {'path': match['paths'][0]}})
        policies['http_' + str(index)] = {'permissions': [{'and_rules': {'rules': parts}}], 'principals': [{'any': True}]}
    return {'action': 'ALLOW', 'policies': policies}


def supported_rules(policy, api):
    body = copy.deepcopy(policy['spec']['policy'])
    egress = api['network_rules'](body).get('egress', {})
    if egress.get('defaultAction') != 'deny' or egress.get('rules') or \
            body.get('networkProxyConfig', {}).get('mitm') or set(egress) - {'defaultAction', 'rules', 'httpRules'}:
        raise ValueError('Automatic proof currently supports default-deny literal HTTP/SNI rules without MITM or raw TCP grants')
    rules = egress.get('httpRules', [])
    for rule in rules:
        match, qualifiers = rule.get('match', {}), rule.get('qualifiers', [])
        if set(rule) - {'match', 'qualifiers', 'description'} or set(match) - {'hosts', 'ports', 'paths', 'methods'} or \
                set(qualifiers) not in ({'allow'}, {'allow', 'audit'}) or len(qualifiers) != len(set(qualifiers)) or \
                len(match.get('hosts', [])) != 1 or '*' in match['hosts'][0] or ':' in match['hosts'][0] or \
                api['host'](match['hosts'][0]) != match['hosts'][0] or len(match.get('ports', [])) != 1 or \
                set(match['ports'][0]) != {'port'} or type(match['ports'][0]['port']) is not int or \
                not 1 <= match['ports'][0]['port'] <= 65535 or len(match.get('paths', [])) > 1 or len(match.get('methods', [])) > 1:
            raise ValueError('Unsupported automatic match shape; keep configuration evidence unverified')
        if match.get('paths') and (set(match['paths'][0]) not in ({'exact'}, {'prefix'}) or
                not next(iter(match['paths'][0].values())).startswith('/')):
            raise ValueError('Unsupported automatic path match')
    return rules


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
    def rbac_config(config, layer):
        if config.get('@type') != 'type.googleapis.com/envoy.extensions.filters.' + layer + '.rbac.v3.RBAC' or \
                set(config) - {'@type', 'rules', 'shadow_rules', 'stat_prefix', 'rules_stat_prefix', 'shadow_rules_stat_prefix'}:
            raise ValueError('Unknown RBAC configuration fields or matcher overrides')
        return {k: normalize_rbac(config[k]) for k in ('rules', 'shadow_rules') if k in config}

    def project(chain):
        fs = chain.get('filters', [])
        result = {'name': chain.get('name'), 'match': chain.get('filter_chain_match', {}),
                  'filters': [f['name'] for f in fs], 'rbac': []}
        if chain.get('transport_socket'):
            raise ValueError('MITM listener requires manual configuration evidence')
        for f in fs:
            config = f.get('typed_config', {})
            if f['name'] == 'envoy.filters.network.rbac':
                result['rbac'].append(rbac_config(config, 'network'))
            elif f['name'] == 'envoy.filters.network.http_connection_manager':
                http_filters = config.get('http_filters', [])
                result['http'] = {'filters': [x['name'] for x in http_filters],
                    'rbac': [rbac_config(x['typed_config'], 'http')
                             for x in http_filters if x['name'] == 'envoy.filters.http.rbac'],
                    'normalize_path': config.get('normalize_path', False),
                    'merge_slashes': config.get('merge_slashes', False),
                    'path_with_escaped_slashes_action': config.get('path_with_escaped_slashes_action'),
                    'logs': [x.get('filter') for x in config.get('access_log', [])]}
        return result
    return {'name': listener.get('name'), 'inspectors': [x['name'] for x in listener.get('listener_filters', [])],
            'chains': [project(x) for x in listener.get('filter_chains', [])],
            'default': project(listener.get('default_filter_chain', {})),
            'logs': [x.get('filter') for x in listener.get('access_log', [])]}


def _compare_permissions(policy, projected, api):
    try:
        rules = supported_rules(policy, api)
    except (ValueError, KeyError, TypeError) as exc:
        return 'insufficient', str(exc)
    audited = [r for r in rules if 'audit' in r['qualifiers']]
    expected_filters = ['envoy.filters.listener.' + name for name in ('original_dst', 'tls_inspector', 'http_inspector')]
    if projected.get('name') != 'varmor_outbound' or projected.get('inspectors') != expected_filters:
        return 'insufficient', 'Unknown listener or inspector layout'
    chains = projected.get('chains', [])
    if len(chains) != 2 or {x.get('name') for x in chains} != {'http_chain', 'tls_chain'}:
        return 'insufficient', 'Unknown filter-chain layout'
    for chain in chains:
        http = chain['name'] == 'http_chain'
        match = {'application_protocols': ['http/1.0', 'http/1.1', 'h2c']} if http else {'transport_protocol': 'tls'}
        if chain['match'] != match:
            return 'contradicted', 'Chain selection differs from the supported policy layout'
        fs = ['envoy.filters.network.http_connection_manager'] if http else ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy']
        if chain['filters'] != fs:
            return 'insufficient', 'Unknown or additional network filters'
        area = chain.get('http', {}) if http else chain
        wanted = [{'rules': expected_rbac(rules, not http)}]
        if audited:
            if http:
                wanted.insert(0, {'shadow_rules': expected_rbac(audited)})
            else:
                wanted[0]['shadow_rules'] = expected_rbac(audited, True)
        if area.get('rbac') != wanted:
            return 'contradicted', 'Active default action, permission scope or audit qualifiers differ from candidate'
        if http and (area.get('filters') != ['envoy.filters.http.rbac'] * len(wanted) + ['envoy.filters.http.router'] or
                area.get('normalize_path') is not True or area.get('merge_slashes') is not True or
                area.get('path_with_escaped_slashes_action') != 'UNESCAPE_AND_FORWARD' or
                area.get('logs') != [log_filter(bool(audited), True)]):
            return 'contradicted', 'HTTP filter order, normalization or audit selection differs'
    default = projected.get('default', {})
    if default.get('name') != 'tcp_default_chain' or default.get('match') or \
            default.get('filters') != ['envoy.filters.network.rbac', 'envoy.filters.network.tcp_proxy'] or \
            default.get('rbac') != [{'rules': expected_rbac([])}] or projected.get('logs') != [log_filter(bool(audited))]:
        return 'contradicted', 'Default TCP permissions or listener audit selection differ'
    return 'confirmed', 'Active HTTP/SNI RBAC scope and audit selection match candidate; raw TCP defaults to deny'


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
        'permissions': projected, 'permissionsHash': digest(projected),
        'scope': 'HTTP/SNI permission enforcement, path normalization and audit selection; not full xDS or business coverage'}
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
