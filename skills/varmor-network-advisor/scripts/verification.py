# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Separate, read-only NetworkProxy enforcement evidence. No traffic or modeling."""
import collections
import contextlib
import copy
import datetime as dt
import hashlib
import json
from pathlib import Path


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def timestamp(value):
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('verification timestamps require explicit timezones')
    return int(parsed.timestamp())


def check_results(checks, records, api, policy=None, state=None, complete_read=True):
    if not isinstance(checks, list) or not checks:
        raise ValueError('checks must be a nonempty list')
    output, ids = [], set()
    for item in checks:
        keys = {'id', 'layer', 'destination', 'expected', 'authority', 'method', 'path',
                'clientConfirmed', 'backendConfirmed', 'configurationConfirmed', 'evidence', 'sni'}
        if not isinstance(item, dict) or set(item) - keys or not api['safe_text'](item.get('id')) or item['id'] in ids:
            raise ValueError('invalid or duplicate verification check')
        ids.add(item['id'])
        endpoint = api['destination'](item.get('destination'))
        if item.get('layer') not in ('L4', 'L7') or item.get('expected') not in ('allow', 'deny'):
            raise ValueError('check requires layer L4/L7 and expected allow/deny')
        for field in ('clientConfirmed', 'backendConfirmed', 'configurationConfirmed'):
            if field in item and type(item[field]) is not bool:
                raise ValueError(field + ' must be an explicit boolean')
        if not isinstance(item.get('evidence', []), list) or any(not api['safe_text'](s) for s in item.get('evidence', [])):
            raise ValueError('evidence must contain safe receipt descriptions or paths')
        if item['layer'] == 'L7':
            api['http_host'](item.get('authority'), endpoint[1])
            if not api['safe_text'](item.get('method')) or not api['safe_text'](item.get('path')) or \
               not item['path'].startswith('/') or '?' in item['path']:
                raise ValueError('HTTP checks require method and query-free path')
        if 'sni' in item and (item['layer'] != 'L4' or api['host'](item['sni']) != item['sni']):
            raise ValueError('SNI checks require a canonical literal host and L4 layer')
        audit_expected = True
        if policy is not None and item['expected'] == 'allow':
            egress = api['network_rules'](copy.deepcopy(policy['spec']['policy']))['egress']
            synthetic = {'event': {'layer': item['layer'], 'dstAddress': item['destination'],
                **{k: item[k] for k in ('authority', 'method', 'path', 'sni') if k in item}}}
            matches_rules = []
            for key in ('rules', 'httpRules'):
                for rule in egress.get(key, []):
                    if api['replay_match'](synthetic, {'defaultAction': 'deny', key: [rule]}, state):
                        matches_rules.append(rule)
            if not matches_rules:
                raise ValueError('Expected allow is not covered by the supplied candidate')
            audit_expected = any('audit' in r['qualifiers'] for r in matches_rules)
        matches = []
        for rec in records:
            ev = rec['event']
            try:
                same = ev['layer'] == item['layer'] and api['destination'](ev.get('dstAddress')) == endpoint
            except (ValueError, TypeError, AttributeError):
                same = False
            if same and item['layer'] == 'L7':
                same = all(ev.get(k) == item[k] for k in ('authority', 'method', 'path'))
            if same and item['layer'] == 'L4':
                same = ev.get('sni') == item['sni'] if 'sni' in item else not ev.get('sni')
            if same:
                matches.append(rec)
        wanted = 'AUDIT' if item['expected'] == 'allow' else 'DENIED'
        opposite = 'DENIED' if wanted == 'AUDIT' else 'AUDIT'
        def usable_allow(rec):
            ev = rec['event']
            if ev['layer'] == 'L4':
                return ev.get('reason') in (None, '', '-')
            # L7 reason is Envoy's response-code detail, not TCP termination.
            # via_upstream also covers legitimate application error responses.
            code = ev.get('responseCode')
            return type(code) is int and 100 <= code <= 599 and \
                ev.get('reason') in (None, '', '-', 'via_upstream')

        valid = [r for r in matches if r['action'] == wanted and
                 (wanted == 'DENIED' or usable_allow(r))]
        client = item.get('clientConfirmed')
        backend = item.get('backendConfirmed')
        silent = item['expected'] == 'allow' and not audit_expected
        expected_evidence = bool(valid) if not silent else complete_read and not matches and item.get('configurationConfirmed') is True
        contradictory = any(r['action'] == opposite for r in matches) or client is False or backend is False or \
                        item.get('configurationConfirmed') is False or (silent and bool(matches))
        complete = expected_evidence and client is True and (item['layer'] == 'L4' or backend is True)
        result = 'contradicted' if contradictory else 'confirmed' if complete else 'insufficient'
        output.append({**item, 'result': result, 'auditMatches': len(matches), 'expectedAuditMatches': len(valid),
                       'auditMode': 'silent' if silent else 'enabled',
                       'basis': 'client/backend + effective-config assertion + no matching audit in bounded read' if silent else 'client/backend + matching audit',
                       'missing': [label for label, present in (('quiet-read/configuration' if silent else 'expected-audit', expected_evidence),
                                    ('client-result', client is not None),
                                    ('backend-result', item['layer'] == 'L4' or backend is not None)) if not present]})
    return output


def verify(args, api):
    root, observation = Path(args.session).resolve(), Path(args.observation_session).resolve()
    if root == observation or observation in root.parents or root in observation.parents:
        raise ValueError('verification and observation directories must be separate')
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError('verification directory must be new or empty')
    state = copy.deepcopy(api['load'](observation / 'session.json'))
    expected = api['load'](args.policy_file)
    observed = api['load'](observation / 'observe.yaml')
    if expected.get('kind') != 'VarmorPolicy' or expected.get('metadata', {}).get('name') != state['policy'] or \
       expected.get('metadata', {}).get('namespace') != state['namespace'] or \
       expected.get('spec', {}).get('target') != observed['spec']['target']:
        raise ValueError('verification policy must belong to the original target')
    if api['network_rules'](copy.deepcopy(expected['spec']['policy'])).get('egress', {}).get('defaultAction') != 'deny':
        raise ValueError('verify requires an enforcement policy with defaultAction deny')
    start, end = timestamp(args.since), timestamp(args.until)
    if end < start or end > int(dt.datetime.now(dt.timezone.utc).timestamp()):
        raise ValueError('verification requires a completed time window, not a future deadline')
    checks = api['load'](args.checks).get('checks') if args.checks else None
    if args.checks:
        check_results(checks, [], api, expected, state)
    collected = None
    if getattr(args, 'collection_session', None):
        folder = Path(args.collection_session).resolve()
        collected = api['load'](folder / 'enforcement-collection.json')
        records = api['load'](folder / 'events.json')
        progress = collected.get('observation', {})
        if collected.get('kind') != 'NetworkProxyEnforcementCollection' or collected.get('observationSession') != str(observation) or \
           collected.get('candidateHash') != fingerprint(expected) or collected.get('eventsHash') != fingerprint(records) or \
           progress.get('phase') != 'stopped' or start < timestamp(collected['since']) or end > timestamp(collected['until']) or \
           set(args.pod_uid) - set(collected['podUIDs']) or set(args.pod_uid) & set(state.get('baselinePodUIDs', [])) or \
           collected['policy']['uid'] != state.get('policyUID'):
            raise ValueError('Completed collection, policy identity, time window and explicit UIDs must match verification')
        pinned = collected['policy']
        streams = [('bounded-enforcement', '\n'.join(json.dumps(r) for r in records))]
    else:
        if (observation / 'collector.json').exists() and 'maxTransferMiBPerMinute' in api['load'](observation / 'collector.json').get('plan', {}):
            raise ValueError('This workflow has resource limits: use prepare-verification, bounded monitor and --collection-session; no unbounded snapshot fallback')
        pods, policy = api['live_inventory'](state, expected)
        if any(policy['spec']['policy'].get(key) != value for key, value in expected['spec']['policy'].items()):
            raise RuntimeError('live policy differs from the supplied candidate configuration')
        selected = [p for p in pods if p['metadata']['uid'] in set(args.pod_uid)]
        if {p['metadata']['uid'] for p in selected} != set(args.pod_uid) or \
           set(args.pod_uid) & set(state.get('baselinePodUIDs', [])):
            raise ValueError('validation Pod UIDs must be currently injected and outside the observation baseline')
        pinned = {'uid': policy['metadata']['uid'], 'generation': policy['metadata'].get('generation'),
                  'specHash': fingerprint(policy['spec'])}
        streams = api['sources'](state, args, selected)
        current = api['get'](state['context'], 'varmorpolicies', state['namespace'], state['policy'])
        if pinned != {'uid': current['metadata']['uid'], 'generation': current['metadata'].get('generation'),
                      'specHash': fingerprint(current['spec'])}:
            raise RuntimeError('policy identity/configuration changed while verification evidence was read')
    state.update(startedAt=start, endedAt=end, podUIDs=sorted(set(args.pod_uid)),
                 purpose='verification', verifiedPodUIDs=sorted(set(args.pod_uid)), observationSession=str(observation))
    root.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(api['database'](root)) as con, con:
        stats = api['ingest'](con, state, streams)
        records = [json.loads(r[0]) for r in con.execute('SELECT record FROM events ORDER BY id')]
    complete_read = bool(not any(stats.get(k) for k in ('malformed', 'invalidEvent', 'missingTimestamp', 'identityMismatch', 'unknownPod'))
        and collected and collected.get('completeRead') and collected.get('requiredSources') and
        all(dt.datetime.fromisoformat(collected['observation'].get('sourceCapturedAt', {}).get(s, '1970-01-01T00:00:00Z').replace('Z', '+00:00')) >=
            dt.datetime.fromisoformat(args.until.replace('Z', '+00:00'))
            for s in collected['requiredSources']))
    results = check_results(checks, records, api, expected, state, complete_read) if checks is not None else []
    language = args.language or state.get('reportLanguage', 'en')
    report = {'kind': 'NetworkProxyVerification', 'observationSession': str(observation),
              'candidateHash': fingerprint(expected), 'policy': pinned, 'podUIDs': state['podUIDs'],
              'since': args.since, 'until': args.until, 'events': len(records), 'collection': stats,
              'continuity': collected['collectionHealth']['status'] if collected else 'not-assessed', 'checks': results,
              'summary': dict(collections.Counter(r['result'] for r in results)),
              'eventsHash': fingerprint(records), 'denials': api['refinement_module']().denied_items(records, state, api),
              'boundedCollection': collected, 'quietReadComplete': complete_read,
              'receiptMode': 'client/backend assertions supplied by user or assistant inspecting receipts',
              'reportLanguage': language, 'auditOnly': checks is None}
    api['write'](root / 'verification.json', report)
    api['write'](root / 'events.json', records)
    api['write'](root / 'denials.json', report['denials'])
    zh = language == 'zh-CN'
    lines = ['# 独立执行验证' if zh else '# Separate enforcement verification', '',
             ('审计窗口' if zh else 'Audit window') + ': ' + args.since + ' — ' + args.until,
             ('策略身份' if zh else 'Policy identity') + ': ' + pinned['uid'],
             'Pod UID: ' + ', '.join(state['podUIDs']), '',
             (('独立拦截采集，未参与成功观察建模；日志文件连续性：' + collected['collectionHealth']['status'] + '，无法排除写入前的上游事件丢失。' if zh
               else 'Independent bounded enforcement collection; log-source continuity: ' + collected['collectionHealth']['status'] + '. Upstream event loss before file writing remains unassessed.')
              if collected else ('未参与观察数据建模；快照不评估日志连续性。' if zh else 'Separate from observation/modeling. Snapshot continuity is not assessed.')),
             ('客户端与后端判断依赖所提供的结果，不能仅凭空响应证明拒绝。' if zh
              else 'Client/backend judgments rely on supplied receipts; empty output alone does not prove denial.'), '',
             '| 检查 | 预期 | 结果 | 匹配审计 |' if zh else '| Check | Expected | Result | Audit matches |', '|---|---|---|---|']
    for item in results:
        result = {'confirmed': '通过', 'contradicted': '结果冲突', 'insufficient': '证据不足'}[item['result']] if zh else item['result']
        lines.append('| ' + ' | '.join(str(x).replace('|', '\\|') for x in
                     (item['id'], item['expected'], result, item['auditMatches'])) + ' |')
    if not results:
        lines.append('仅保存审计证据，未提供验证检查清单。' if zh else 'Audit evidence only; no validation checklist supplied.')
    (root / 'verification.md').write_text('\n'.join(lines) + '\n')
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 2 if not results or any(r['result'] != 'confirmed' for r in results) else 0
