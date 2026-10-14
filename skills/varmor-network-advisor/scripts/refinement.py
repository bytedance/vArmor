# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""User-reviewed enforcement evidence; never turn DENIED into observation success."""
import collections
import contextlib
import copy
import datetime as dt
import hashlib
import ipaddress
import json
from pathlib import Path
import re


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def permission_id(layer, rule):
    return fingerprint({'layer': layer, **{k: v for k, v in rule.items() if k not in ('qualifiers', 'description')}})


def permissions(egress):
    return [{'id': permission_id(layer, r), 'layer': layer, 'rule': r,
             'audit': 'audit' in r.get('qualifiers', [])}
            for layer, key in (('HTTP/SNI', 'httpRules'), ('TCP', 'rules')) for r in egress.get(key, [])
            if 'allow' in r.get('qualifiers', []) and 'deny' not in r.get('qualifiers', [])]


def restriction_id(layer, rule):
    return fingerprint({'action': 'deny', 'layer': layer,
                        **{k: v for k, v in rule.items() if k not in ('qualifiers', 'description')}})


def restriction_rule(choice, api):
    """Accept explicit literal scopes only; never turn a rejected grant into deny."""
    if not isinstance(choice, dict) or set(choice) != {'layer', 'rule', 'reason', 'approvalEvidence'} or \
       choice['layer'] not in ('HTTP/SNI', 'TCP'):
        raise ValueError('Deny constraint requires layer, rule, reason and approvalEvidence')
    for key in ('reason', 'approvalEvidence'):
        if not api['safe_text'](choice[key]) or not choice[key].strip():
            raise ValueError('Deny constraint requires a reason and user approval evidence')
    r = copy.deepcopy(choice['rule'])
    if not isinstance(r, dict) or r.get('qualifiers') not in (['deny'], ['deny', 'audit']) or \
       set(r) - ({'qualifiers', 'description', 'match'} if choice['layer'] == 'HTTP/SNI' else
                 {'qualifiers', 'description', 'ip', 'ports'}):
        raise ValueError('Unsupported deny rule; use deny or deny,audit without allow')
    if 'description' in r and not api['safe_text'](r['description']):
        raise ValueError('Unsafe deny description')
    m = r.get('match') if choice['layer'] == 'HTTP/SNI' else r
    if not isinstance(m, dict):
        raise ValueError('Deny rule requires match criteria')
    if choice['layer'] == 'HTTP/SNI':
        if set(m) - {'hosts', 'ports', 'paths', 'methods'} or not isinstance(m.get('hosts'), list) or not m['hosts']:
            raise ValueError('HTTP deny requires literal hosts and ports')
        for h in m['hosts']:
            if api['host'](h) != h:
                raise ValueError('Use canonical literal deny hosts')
        if 'methods' in m and (not isinstance(m['methods'], list) or not m['methods'] or any(
                not isinstance(x, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", x) for x in m['methods'])):
            raise ValueError('Invalid deny methods')
        if 'paths' in m:
            if not isinstance(m['paths'], list) or not m['paths']:
                raise ValueError('Invalid deny paths')
            for p in m['paths']:
                if not isinstance(p, dict) or len(p) != 1 or not set(p) <= {'exact', 'prefix'} or any(
                        not api['safe_text'](x) or not x.startswith('/') or '?' in x for x in p.values()):
                    raise ValueError('Use safe exact/prefix deny paths without query strings')
    elif str(ipaddress.ip_address(r.get('ip', ''))) != r['ip']:
        raise ValueError('Use canonical literal deny IP')
    ports = m.get('ports')
    if not isinstance(ports, list) or not ports:
        raise ValueError('Deny requires explicit ports')
    for p in ports:
        if not isinstance(p, dict) or set(p) - {'port', 'endPort'} or type(p.get('port')) is not int or \
           type(p.get('endPort', p['port'])) is not int or not 1 <= p['port'] <= p.get('endPort', p['port']) <= 65535:
            raise ValueError('Invalid deny ports')
    return r


def assert_candidate_owned(root, api, adopted=()):
    """A file edit is not an approval; only explicitly registered denies may be adopted."""
    root = Path(root)
    if not (root / 'candidate.yaml').exists() or not (root / 'analysis.json').exists():
        return
    current = api['load'](root / 'candidate.yaml')
    digest = api['load'](root / 'analysis.json').get('candidateHash')
    if not digest or fingerprint(current) == digest:
        return
    check = copy.deepcopy(current)
    egress = api['network_rules'](check['spec']['policy'])['egress']
    ids = set(adopted)
    if not ids and (root / 'refinement.json').exists():
        prior = api['load'](root / 'analysis.json').get('denyConstraints', [])
        ids = set(api['load'](root / 'refinement.json').get('denyConstraints', {})) - {x['id'] for x in prior}
    for layer, key in (('HTTP/SNI', 'httpRules'), ('TCP', 'rules')):
        if key in egress:
            egress[key] = [r for r in egress[key] if not ('deny' in r.get('qualifiers', []) and
                                                       restriction_id(layer, r) in ids)]
            if not egress[key]:
                egress.pop(key)
    if not ids or fingerprint(check) != digest:
        raise ValueError('Candidate was edited outside saved decisions; preserve it and register reviewed constraints before regeneration')


def denied_items(records, state, api):
    grouped = {}
    review_root = state.get('observationSession')
    review = api['load'](Path(review_root) / 'refinement.json') if review_root and \
        (Path(review_root) / 'refinement.json').exists() else {}
    for rec in records:
        if rec.get('action') != 'DENIED':
            continue
        ev = rec['event']
        try:
            if not str(ev.get('reason', '')).startswith('rbac_access_denied'):
                raise ValueError('DENIED without a proxy denial reason')
            ip, port = api['destination'](ev.get('dstAddress'))
            if ev['layer'] == 'L7':
                domain = api['http_host'](ev.get('authority'), port)
                method, path = ev.get('method'), ev.get('path')
                if not isinstance(method, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method) or \
                   not api['safe_text'](path) or not path.startswith('/') or '?' in path:
                    raise ValueError('Missing exact HTTP method or normalized path')
                if ev.get('sni') and (api['host'](ev['sni']) != domain or
                                     not api['mitm_applies'](domain, state['mitmDomains'])):
                    raise ValueError('SNI/authority mismatch or unapproved MITM scope')
                layer, granularity = 'HTTP/SNI', 'exact HTTP method/path'
                rule = {'qualifiers': ['allow', 'audit'], 'match': {'hosts': [domain],
                    'ports': [{'port': port}], 'methods': [method], 'paths': [{'exact': path}]}}
            elif ev.get('sni'):
                domain = api['host'](ev['sni'])
                if api['mitm_applies'](domain, state['mitmDomains']):
                    raise ValueError('L4 evidence cannot grant a whole MITM domain')
                layer, granularity = 'HTTP/SNI', 'entire SNI/port; also permits plaintext HTTP Host/port'
                rule = {'qualifiers': ['allow', 'audit'], 'match': {'hosts': [domain], 'ports': [{'port': port}]}}
            else:
                layer, granularity = 'TCP', 'entire literal IP/port, including HTTP/TLS'
                rule = {'qualifiers': ['allow', 'audit'], 'ip': ip, 'ports': [{'port': port}]}
            key = permission_id(layer, rule)
            item = grouped.setdefault(key, {'id': key, 'layer': layer, 'rule': rule,
                'granularity': granularity, 'reviewable': True, 'decision': 'pending', 'count': 0,
                'firstSeen': rec['eventTimestamp'], 'lastSeen': rec['eventTimestamp'],
                'podUIDs': [], 'origin': 'DENIED', 'observedSuccess': False})
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            key = fingerprint({'event': ev, 'action': 'DENIED'})
            item = grouped.setdefault(key, {'id': key, 'reviewable': False, 'decision': 'pending',
                'reason': str(exc), 'count': 0, 'firstSeen': rec['eventTimestamp'],
                'lastSeen': rec['eventTimestamp'], 'podUIDs': [], 'origin': 'DENIED', 'observedSuccess': False})
        item['count'] += 1
        item['lastSeen'] = max(item['lastSeen'], rec['eventTimestamp'])
        item['firstSeen'] = min(item['firstSeen'], rec['eventTimestamp'])
        item['podUIDs'] = sorted(set(item['podUIDs'] + [rec['podUID']]))
        matching = [key for key, constraint in review.get('denyConstraints', {}).items()
                    if api['_replay_rules'](rec, {('httpRules' if constraint['layer'] == 'HTTP/SNI' else 'rules'):
                                                [constraint['rule']]}, state)]
        if matching:
            item['intentionalDenyIds'] = sorted(set(item.get('intentionalDenyIds', []) + matching))
            item.update(decision='reject', authorizationState='explicit-deny', reviewable=False)
    if review:
        prior = review.get('decisions', {})
        revoked = set(review.get('revokedRuleIds', []))
        for item in grouped.values():
            saved = prior.get(item['id'])
            if saved:
                item['previousDecision'] = saved['decision']
                item['previousApprovalEvidence'] = saved['approvalEvidence']
                # A recurrence of an approved denial needs investigation. A
                # rejected exact scope retains the user's business decision.
                if saved['decision'] == 'reject':
                    item['decision'] = 'reject'
            if item['id'] in revoked:
                item['decision'] = 'reject'
                item['authorizationState'] = 'revoked'
    return list(grouped.values())


def annotated_verification(saved, receipt, state, api):
    result = copy.deepcopy(saved)
    for item in result.get('decisions', {}).values():
        item['currentCandidateVerification'] = 'not-assessed'
        item['authorizationState'] = 'revoked' if item['id'] in result.get('revokedRuleIds', []) else item['decision']
        if item['authorizationState'] == 'revoked':
            item.pop('currentCandidateCheckIds', None)
            continue
        if item['decision'] != 'approve' or not receipt or not receipt.get('currentCandidate'):
            continue
        key = 'httpRules' if item['layer'] == 'HTTP/SNI' else 'rules'
        matches = []
        for check in receipt.get('checks', []):
            ev = {'layer': check.get('layer'), 'dstAddress': check.get('destination'),
                  **{k: check[k] for k in ('authority', 'sni', 'method', 'path') if k in check}}
            if check.get('expected') == 'allow' and api['replay_match']({'event': ev}, {key: [item['rule']]}, state):
                matches.append(check)
        if matches:
            item['currentCandidateCheckIds'] = [c['id'] for c in matches]
            item['currentCandidateVerification'] = 'contradicted' if any(c['result'] == 'contradicted' for c in matches) else \
                'confirmed' if all(c['result'] == 'confirmed' for c in matches) else 'insufficient'
    return result


def authorized_rules(egress, saved):
    """Rebuild historical grants before applying explicit withdrawals."""
    egress = copy.deepcopy(egress)
    for item in saved.get('decisions', {}).values():
        if item['decision'] != 'approve':
            continue
        key = 'httpRules' if item['layer'] == 'HTTP/SNI' else 'rules'
        if item['id'] not in {permission_id(item['layer'], r) for r in egress.get(key, [])}:
            egress.setdefault(key, []).append(copy.deepcopy(item['rule']))
    return egress


def merge(egress, saved):
    egress = authorized_rules(egress, saved)
    revoked = set(saved.get('revokedRuleIds', []))
    for layer, key in (('HTTP/SNI', 'httpRules'), ('TCP', 'rules')):
        if key in egress:
            egress[key] = [r for r in egress[key] if permission_id(layer, r) not in revoked]
            if not egress[key]:
                egress.pop(key)
    quiet = set(saved.get('silentRuleIds', []))
    known = {p['id'] for p in permissions(egress)}
    if quiet - known:
        raise ValueError('Silent rule approval is stale: permission scope changed or was removed; review it again')
    for p in permissions(egress):
        p['rule']['qualifiers'] = ['allow'] if p['id'] in quiet else ['allow', 'audit']
    # Restrictions never enter grant IDs, withdrawals, or quiet-audit rewriting.
    for key, item in sorted(saved.get('denyConstraints', {}).items()):
        if key != restriction_id(item['layer'], item['rule']) or item['rule'].get('qualifiers') not in (['deny'], ['deny', 'audit']):
            raise ValueError('Saved deny constraint identity is invalid')
        bucket = 'httpRules' if item['layer'] == 'HTTP/SNI' else 'rules'
        egress.setdefault(bucket, []).insert(0, copy.deepcopy(item['rule']))
    return egress


def revocations(egress, saved, state, api):
    """Conservative overlap diagnostics, never a claim of runtime denial."""
    latest = {d['id']: d for d in saved.get('permissionDecisions', []) if d['action'] == 'revoke'}
    active = permissions(egress)

    def overlaps(left, right):
        a, b = left['rule'], right['rule']
        am, bm = a.get('match', a), b.get('match', b)
        if not any(p['port'] <= q.get('endPort', q['port']) and q['port'] <= p.get('endPort', p['port'])
                   for p in am['ports'] for q in bm['ports']):
            return False
        if left['layer'] != right['layer']:
            # A DNS host may resolve to an L4-authorized IP; no DNS guesses.
            return True
        if left['layer'] == 'TCP':
            return a['ip'] == b['ip']
        common = set(am['hosts']) & set(bm['hosts'])
        if not common:
            return False
        if any(not api['mitm_applies'](host, state['mitmDomains']) for host in common):
            return True  # Shared SNI/port ignores HTTP method/path restrictions.
        if am.get('methods') and bm.get('methods') and not set(am['methods']) & set(bm['methods']):
            return False
        if not am.get('paths') or not bm.get('paths'):
            return True
        for p in am['paths']:
            for q in bm['paths']:
                if 'exact' in p and 'exact' in q:
                    if p['exact'] == q['exact']:
                        return True
                elif 'prefix' in p and 'prefix' in q:
                    if p['prefix'].startswith(q['prefix']) or q['prefix'].startswith(p['prefix']):
                        return True
                else:
                    exact, prefix = (p['exact'], q['prefix']) if 'exact' in p else (q['exact'], p['prefix'])
                    if exact.startswith(prefix):
                        return True
        return False

    return [{**copy.deepcopy(latest[key]), 'possibleOverlapRuleIds':
             [p['id'] for p in active if overlaps(latest[key], p)]}
            for key in saved.get('revokedRuleIds', []) if key in latest]


def refine(args, api):
    root = Path(args.session).resolve()
    with api['locked'](root):
        state = api['load'](root / 'session.json')
        if state.get('purpose') in ('verification', 'verification-only'):
            raise ValueError('Refine the original observation session, not enforcement evidence')
        choices = api['load'](args.decisions)
        if not isinstance(choices, dict) or set(choices) - {'decisions', 'silentRuleIds', 'auditRuleIds',
                'revokeRuleIds', 'restoreRuleIds', 'denyRules', 'removeDenyRuleIds', 'reason', 'approvalEvidence'}:
            raise ValueError('Unknown refinement decision keys')
        saved = api['load'](root / 'refinement.json') if (root / 'refinement.json').exists() else {'decisions': {}, 'silentRuleIds': []}
        saved = copy.deepcopy(saved)
        additions, removals = choices.get('denyRules', []), choices.get('removeDenyRuleIds', [])
        if not isinstance(additions, list) or not isinstance(removals, list) or any(
                not isinstance(x, str) or not re.fullmatch('[0-9a-f]{64}', x) for x in removals) or len(set(removals)) != len(removals):
            raise ValueError('Deny decisions must be explicit lists with unique full IDs')
        adopted = []
        constraints = saved.setdefault('denyConstraints', {})
        for choice in additions:
            rule = restriction_rule(choice, api)
            key = restriction_id(choice['layer'], rule)
            if key in adopted or key in removals:
                raise ValueError('Conflicting/duplicate deny decisions')
            adopted.append(key)
            item = {**choice, 'rule': rule, 'id': key, 'at': api['now'](), 'origin': 'explicit-user-constraint'}
            constraints[key] = item
            saved.setdefault('constraintDecisions', []).append({**item, 'action': 'add'})
        for key in removals:
            if key not in constraints or not api['safe_text'](choices.get('reason')) or not choices['reason'].strip() or \
               not api['safe_text'](choices.get('approvalEvidence')) or not choices['approvalEvidence'].strip():
                raise ValueError('Remove only known deny constraints with a reason and approval evidence')
            saved.setdefault('constraintDecisions', []).append({**constraints.pop(key), 'action': 'remove',
                'at': api['now'](), 'reason': choices['reason'], 'approvalEvidence': choices['approvalEvidence']})
        assert_candidate_owned(root, api, adopted)
        config = api['load'](root / 'review.json') if (root / 'review.json').exists() else {}
        with contextlib.closing(api['database'](root)) as con:
            observed = [json.loads(r[0]) for r in con.execute('SELECT record FROM events ORDER BY id')]
        egress, _, _ = api['propose'](observed, state, config)
        current = api['load'](root / 'candidate.yaml') if (root / 'candidate.yaml').exists() else api['load'](root / 'observe.yaml')
        if not (root / 'candidate.yaml').exists():
            current['spec']['updateExistingWorkloads'] = False
            api['network_rules'](current['spec']['policy'])['egress'] = merge(egress, saved)
        active = {p['id']: p for p in permissions(merge(egress, saved))}
        revoked = set(saved.get('revokedRuleIds', []))
        for key in ('silentRuleIds', 'auditRuleIds', 'revokeRuleIds', 'restoreRuleIds'):
            values = choices.get(key, [])
            if not isinstance(values, list) or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in values) or len(set(values)) != len(values):
                raise ValueError(key + ' must contain unique full permission IDs')
        withdraw, restore = set(choices.get('revokeRuleIds', [])), set(choices.get('restoreRuleIds', []))
        if withdraw & restore or (withdraw | restore) & set(choices.get('silentRuleIds', [])) or withdraw & set(choices.get('auditRuleIds', [])):
            raise ValueError('Conflicting permission withdrawal, restoration or audit decisions')
        if withdraw - active.keys() or restore - revoked:
            raise ValueError('Withdraw only active permission IDs; restore only explicitly revoked IDs')
        if withdraw or restore:
            if not api['safe_text'](choices.get('reason')) or not choices['reason'].strip() or \
               not api['safe_text'](choices.get('approvalEvidence')) or not choices['approvalEvidence'].strip():
                raise ValueError('Withdrawal/restoration requires a reason and user approval evidence')
        changes = choices.get('decisions', [])
        if not isinstance(changes, list):
            raise ValueError('decisions must be an explicit list')
        if changes:
            if not args.verification:
                raise ValueError('DENIED decisions require a verification receipt')
            path = Path(args.verification).resolve()
            receipt = api['load'](path)
            records = api['load'](path.parent / 'events.json')
            if receipt.get('kind') != 'NetworkProxyVerification' or receipt.get('observationSession') != str(root) or \
               receipt.get('candidateHash') != fingerprint(current) or \
               receipt.get('policy', {}).get('uid') != state.get('policyUID') or \
               receipt.get('eventsHash') != fingerprint(records):
                raise ValueError('DENIED evidence is stale, changed or belongs to another policy/session')
            items = {d['id']: d for d in denied_items(records, {**state, 'observationSession': str(root)}, api)}
            seen = set()
            for choice in changes:
                if not isinstance(choice, dict) or set(choice) != {'id', 'decision', 'reason', 'approvalEvidence'} or \
                   choice.get('decision') not in ('approve', 'reject', 'pending') or choice.get('id') in seen or \
                   not api['safe_text'](choice.get('reason')) or not choice['reason'].strip() or \
                   not api['safe_text'](choice.get('approvalEvidence')) or not choice['approvalEvidence'].strip():
                    raise ValueError('Each decision requires unique id, approve/reject/pending, reason and user approval evidence')
                item = items.get(choice['id'])
                if not item or (choice['decision'] == 'approve' and not item['reviewable']):
                    raise ValueError('Unknown denial or incomplete/anomalous evidence cannot be approved')
                seen.add(choice['id'])
                saved['decisions'][choice['id']] = {**item, **choice, 'verificationFile': str(path),
                    'candidateHashAtReview': receipt['candidateHash'], 'policyUID': receipt['policy']['uid'],
                    'since': receipt['since'], 'until': receipt['until'], 'verification': 'not-assessed'}
        if any(choice['decision'] == 'approve' and choice['id'] in (revoked | withdraw) - restore for choice in changes):
            raise ValueError('Permission was revoked; explicit restoreRuleIds approval is required')
        available = {p['id']: p for p in permissions(authorized_rules(egress, saved))}
        if restore - available.keys():
            raise ValueError('Revoked permission scope is no longer available; review a new permission')
        for action, ids in (('revoke', withdraw), ('restore', restore)):
            for key in sorted(ids):
                saved.setdefault('permissionDecisions', []).append({
                    'at': api['now'](), 'action': action, **copy.deepcopy((active if action == 'revoke' else available)[key]),
                    'reason': choices['reason'], 'approvalEvidence': choices['approvalEvidence'],
                    'candidateHashAtReview': fingerprint(current), 'policyUID': state.get('policyUID')})
        saved['revokedRuleIds'] = sorted((revoked | withdraw) - restore)
        if set(choices.get('silentRuleIds', [])) & set(choices.get('auditRuleIds', [])):
            raise ValueError('A permission cannot be both silent and audited')
        if choices.get('silentRuleIds') or choices.get('auditRuleIds'):
            if not api['safe_text'](choices.get('approvalEvidence')) or not choices['approvalEvidence'].strip():
                raise ValueError('Audit changes require user approval evidence')
            saved.setdefault('auditDecisions', []).append({'at': api['now'](), **choices})
        quiet = (set(saved['silentRuleIds']) | set(choices.get('silentRuleIds', []))) - \
            set(choices.get('auditRuleIds', [])) - withdraw - restore
        saved['silentRuleIds'] = sorted(quiet)
        # Rebuild from original successful observation plus reviewed decisions;
        # validation events never enter its database or increase stable rounds.
        final = merge(egress, saved)  # Validate before committing decisions.
        known = {p['id'] for p in permissions(final)}
        if set(choices.get('auditRuleIds', [])) - known:
            raise ValueError('Audit permission ID is not active')
        api['write'](root / 'refinement.json', saved)
        if withdraw or restore or additions or removals:
            state.pop('verificationFile', None)
            api['write'](root / 'session.json', state)
    return api['analyze'](api['parser']().parse_args(['analyze', '--session', str(root)]))


def prepare(args, api):
    root, original = Path(args.session).resolve(), Path(args.observation_session).resolve()
    if root == original or root in original.parents or original in root.parents or \
       (root.exists() and any(root.iterdir())):
        raise ValueError('Enforcement collection requires a new directory separate from observation')
    state = copy.deepcopy(api['load'](original / 'session.json'))
    expected = api['load'](args.policy_file)
    if api['network_rules'](copy.deepcopy(expected['spec']['policy']))['egress']['defaultAction'] != 'deny' or \
       expected['spec']['target'] != api['load'](original / 'observe.yaml')['spec']['target'] or \
       expected['metadata']['name'] != state['policy'] or expected['metadata']['namespace'] != state['namespace']:
        raise ValueError('Use this observation target\'s enforcement candidate')
    new_pods = getattr(args, 'new_pods', False)
    pods, policy = api['live_inventory'](state, expected, allow_empty=new_pods)
    wanted = set(args.pod_uid or [])
    if not new_pods and (not wanted or wanted & set(state.get('baselinePodUIDs', [])) or \
       wanted - {p['metadata']['uid'] for p in pods}):
        raise ValueError('Explicit currently injected UIDs outside the observation baseline are required')
    state.update(purpose='verification', observationSession=str(original), verifiedPodUIDs=sorted(wanted),
        podUIDs=sorted(wanted), podHistory={}, collectionMode='live-incremental',
        verificationMode='new-pods' if new_pods else 'existing-pods', verificationTarget=expected['spec']['target'],
        pinnedPolicy={'uid': policy['metadata']['uid'], 'generation': policy['metadata'].get('generation'),
                      'specHash': fingerprint(policy['spec'])})
    for key in ('observationEpoch', 'historicalSince', 'endedAt'):
        state.pop(key, None)
    state['resourcePlan'] = {k: v for k, v in api['load'](original / 'collector.json')['plan'].items() if k != 'until'}
    for pod in pods:
        if pod['metadata']['uid'] in wanted:
            api['collector_module']().register_pod(state, pod)
    root.mkdir(parents=True, exist_ok=True)
    api['write'](root / 'session.json', state)
    api['write'](root / 'observe.yaml', expected)
    api['workflow_module']().register_collection(original, root, api)
    print(json.dumps({'status': 'enforcement-collection-prepared', 'session': str(root),
        'podUIDs': sorted(wanted), 'next': ('Start bounded monitor before user recreation; new target UIDs are verified and enrolled automatically'
                                          if new_pods else 'Start bounded monitor, wait for ready, then the user exercises business; no Pod recreation required')}))
    return 0


def collection_report(args, api):
    root = Path(args.session)
    with api['locked'](root), contextlib.closing(api['database'](root)) as con:
        state = api['load'](root / 'session.json')
        language = api['report_language'](args, state, root)
        progress = api['load'](root / 'collector.json')
        records = [json.loads(r[0]) for r in con.execute('SELECT record FROM events ORDER BY id')]
        health = api['collector_module']().health(con)
        expected = api['load'](root / 'observe.yaml')
        errors = ('malformed', 'invalidEvent', 'missingTimestamp', 'identityMismatch', 'unknownPod',
                  'pendingPodIdentity', 'unresolvedPodEvents', 'readFailures')
        evidence_errors = {key: sum(json.loads(row[0]).get(key, 0)
            for row in con.execute('SELECT summary FROM rounds')) for key in errors}
        report = {'kind': 'NetworkProxyEnforcementCollection', 'observationSession': state['observationSession'],
            'candidateHash': fingerprint(expected), 'policy': state['pinnedPolicy'], 'podUIDs': state['podUIDs'],
            'since': progress.get('readyAt'), 'until': progress.get('stoppedAt') or api['now'](),
            'eventsHash': fingerprint(records), 'events': len(records), 'collectionHealth': health,
            'reportLanguage': language,
            'verificationMode': state.get('verificationMode', 'existing-pods'),
            'baselinePodUIDs': state.get('baselinePodUIDs', []),
            'identityFailures': state.get('startupIdentityFailures', {}),
            'evidenceErrors': evidence_errors,
            'observation': progress, 'denials': denied_items(records, state, api),
            'completeRead': progress.get('phase') == 'stopped' and progress.get('stopReason') in ('deadline', 'user-stop')
                and bool(progress.get('lastSuccessfulCollection')) and not progress.get('backlogBytes')
                and not progress.get('resourcePressure') and not any(evidence_errors.values())
                and health['status'] == 'no-detected-gap',
            'requiredSources': sorted({('node/' + p['node']) if p['regular'] else ('pod/' + uid)
                                       for uid, p in state.get('podHistory', {}).items()})}
        api['write'](root / 'events.json', records)
        api['write'](root / 'enforcement-collection.json', report)
        api['write'](root / 'denials.json', report['denials'])
        zh = language == 'zh-CN'
        lines = ['# 拦截期证据与待审核拒绝项' if zh else '# Enforcement evidence and pending denials', '',
                 'DENIED 不是成功访问证据；没有自动放行或更新策略。' if zh else
                 'DENIED is not successful access evidence. No automatic permission or policy update.', '',
                 ('事件：' if zh else 'Events: ') + str(len(records)),
                 ('待审核拒绝范围：' if zh else 'Denial scopes for review: ') + str(len(report['denials'])),
                 ('资源预算与积压：' if zh else 'Resource budget and backlog: ') + json.dumps({
                     'plan': progress['plan'], 'resources': progress.get('resources'),
                     'backlogBytes': progress.get('backlogBytes'), 'completeRead': report['completeRead']}, ensure_ascii=False), '',
                 '原观察数据未修改；详细权限与审核 ID 见 denials.json。' if zh else
                 'Original observation unchanged. See denials.json for exact scopes and decision IDs.']
        (root / 'report.md').write_text('\n'.join(lines) + '\n')
    return 0
