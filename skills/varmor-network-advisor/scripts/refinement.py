# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""User-reviewed enforcement evidence; never turn DENIED into observation success."""
import collections
import contextlib
import copy
import datetime as dt
import hashlib
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
            for layer, key in (('HTTP/SNI', 'httpRules'), ('TCP', 'rules')) for r in egress.get(key, [])]


def denied_items(records, state, api):
    grouped = {}
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
    review_root = state.get('observationSession')
    if review_root and (Path(review_root) / 'refinement.json').exists():
        prior = api['load'](Path(review_root) / 'refinement.json').get('decisions', {})
        for item in grouped.values():
            saved = prior.get(item['id'])
            if saved:
                item['previousDecision'] = saved['decision']
                item['previousApprovalEvidence'] = saved['approvalEvidence']
                # A recurrence of an approved denial needs investigation. A
                # rejected exact scope retains the user's business decision.
                if saved['decision'] == 'reject':
                    item['decision'] = 'reject'
    return list(grouped.values())


def annotated_verification(saved, receipt, state, api):
    result = copy.deepcopy(saved)
    for item in result.get('decisions', {}).values():
        item['currentCandidateVerification'] = 'not-assessed'
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


def merge(egress, saved):
    egress = copy.deepcopy(egress)
    for item in saved.get('decisions', {}).values():
        if item['decision'] != 'approve':
            continue
        key = 'httpRules' if item['layer'] == 'HTTP/SNI' else 'rules'
        if item['id'] not in {permission_id(item['layer'], r) for r in egress.get(key, [])}:
            egress.setdefault(key, []).append(copy.deepcopy(item['rule']))
    quiet = set(saved.get('silentRuleIds', []))
    known = {p['id'] for p in permissions(egress)}
    if quiet - known:
        raise ValueError('Silent rule approval is stale: permission scope changed or was removed; review it again')
    for p in permissions(egress):
        p['rule']['qualifiers'] = ['allow'] if p['id'] in quiet else ['allow', 'audit']
    return egress


def refine(args, api):
    root = Path(args.session).resolve()
    with api['locked'](root):
        state = api['load'](root / 'session.json')
        if state.get('purpose') == 'verification':
            raise ValueError('Refine the original observation session, not enforcement evidence')
        current = api['load'](root / 'candidate.yaml')
        choices = api['load'](args.decisions)
        if not isinstance(choices, dict) or set(choices) - {'decisions', 'silentRuleIds', 'auditRuleIds', 'approvalEvidence'}:
            raise ValueError('Unknown refinement decision keys')
        saved = api['load'](root / 'refinement.json') if (root / 'refinement.json').exists() else {'decisions': {}, 'silentRuleIds': []}
        saved = copy.deepcopy(saved)
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
            items = {d['id']: d for d in denied_items(records, state, api)}
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
        for key in ('silentRuleIds', 'auditRuleIds'):
            values = choices.get(key, [])
            if not isinstance(values, list) or any(not isinstance(v, str) or not re.fullmatch('[0-9a-f]{64}', v) for v in values):
                raise ValueError(key + ' must contain full permission IDs')
        if set(choices.get('silentRuleIds', [])) & set(choices.get('auditRuleIds', [])):
            raise ValueError('A permission cannot be both silent and audited')
        if choices.get('silentRuleIds') or choices.get('auditRuleIds'):
            if not api['safe_text'](choices.get('approvalEvidence')) or not choices['approvalEvidence'].strip():
                raise ValueError('Audit changes require user approval evidence')
            saved.setdefault('auditDecisions', []).append({'at': api['now'](), **choices})
        quiet = (set(saved['silentRuleIds']) | set(choices.get('silentRuleIds', []))) - set(choices.get('auditRuleIds', []))
        saved['silentRuleIds'] = sorted(quiet)
        # Rebuild from original successful observation plus reviewed decisions;
        # validation events never enter its database or increase stable rounds.
        config = api['load'](root / 'review.json') if (root / 'review.json').exists() else {}
        with contextlib.closing(api['database'](root)) as con:
            observed = [json.loads(r[0]) for r in con.execute('SELECT record FROM events ORDER BY id')]
        egress, _, _ = api['propose'](observed, state, config)
        merge(egress, saved)  # Validate before committing decisions.
        api['write'](root / 'refinement.json', saved)
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
    pods, policy = api['live_inventory'](state, expected)
    wanted = set(args.pod_uid)
    if not wanted or wanted & set(state.get('baselinePodUIDs', [])) or \
       wanted - {p['metadata']['uid'] for p in pods}:
        raise ValueError('Explicit currently injected UIDs outside the observation baseline are required')
    state.update(purpose='verification', observationSession=str(original), verifiedPodUIDs=sorted(wanted),
        podUIDs=sorted(wanted), podHistory={}, collectionMode='live-incremental',
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
    print(json.dumps({'status': 'enforcement-collection-prepared', 'session': str(root),
        'podUIDs': sorted(wanted), 'next': 'Start bounded monitor, wait for ready, then the user exercises business; no Pod recreation required'}))
    return 0


def collection_report(args, api):
    root = Path(args.session)
    with api['locked'](root), contextlib.closing(api['database'](root)) as con:
        state = api['load'](root / 'session.json')
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
        zh = state.get('reportLanguage') == 'zh-CN'
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
