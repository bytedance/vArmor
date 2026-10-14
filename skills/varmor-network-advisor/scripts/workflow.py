# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""One business-facing summary of saved workflow state; no online truth claims."""
import json
from pathlib import Path


TEXT = {
    'verification-changed': ('已批准候选已变化，需重新审核并初始化验证。', 'The approved candidate changed; review it and initialize verification again.', 'assistant', 'Review the changed candidate and initialize a new verification workflow; local status does not prove deployment'),
    'verification-prepared': ('已批准策略的独立验证已准备，尚未开始采集。', 'Independent verification of the approved policy is prepared; collection has not started.', 'assistant', 'Prepare a separate bounded collection and check readiness; unchanged approved scope needs no repeated review'),
    'prepared': ('观察方案已准备，等待确认和启动。', 'Observation is prepared; confirm the plan before starting.', 'assistant', 'Confirm the plan, prepare policy and check collector readiness'),
    'observe-startup': ('采集器已就绪，等待创建或重建应用。', 'The collector is ready; create or recreate the application.', 'user', 'Create or recreate target Pods, then exercise representative business'),
    'observing': ('正在观察应用的网络行为。', 'Application network observation is running.', 'user', 'Exercise the agreed business scenarios before the deadline'),
    'collector-check': ('采集器状态需复核，暂缓应用操作。', 'Collector state needs checking; hold application actions.', 'assistant', 'Inspect current collector readiness or failure before asking for more user work'),
    'review': ('候选权限已生成，等待业务审核。', 'Candidate permissions are ready for business review.', 'user', 'Review necessary requests and permission scope'),
    'no-data': ('可用证据不足，尚未生成候选权限。', 'Usable evidence is insufficient to generate candidate permissions.', 'assistant', 'Explain missing coverage and prepare a new bounded session if needed'),
    'enforce-traffic': ('拦截采集已就绪，等待业务测试。', 'Enforcement collection is ready for business tests.', 'user', 'Test fresh allowed and denied requests on existing injected Pods'),
    'enforce-startup': ('启动验收采集已就绪，等待重建应用。', 'Startup acceptance collection is ready; recreate the application.', 'user', 'Recreate target Pods under enforcement and test startup and business'),
    'verify': ('拦截证据已保存，等待核对测试结果。', 'Enforcement evidence is saved; check test receipts next.', 'assistant', 'Verify client, backend, audit and configuration evidence'),
    'changed': ('候选权限已变化，需验证当前版本。', 'Candidate permissions changed; verify the current version.', 'assistant', 'Review and deploy the approved change, check active configuration and test it'),
    'denials': ('已有验证结果，仍有拒绝项等待审核。', 'Verification is saved; denied requests await business review.', 'user', 'Decide whether the denied requests are necessary; never approve them automatically'),
    'verified': ('当前候选的已保存检查通过。', 'Saved checks passed for the current candidate.', 'user', 'Review remaining business coverage and consider final startup acceptance'),
    'startup-verified': ('当前候选的已保存启动检查通过。', 'Saved startup checks passed for the current candidate.', 'user', 'Accept the tested scope or identify additional business scenarios'),
    'incomplete': ('验证证据不足或结果冲突，尚未验收。', 'Verification is insufficient or contradictory; acceptance is pending.', 'assistant', 'Explain missing or conflicting evidence and arrange one scoped retest'),
    'legacy-evidence': ('旧版人工确认记录需补充回执核验。', 'Legacy assertion-based verification needs source receipt checks.', 'assistant', 'Retain historical results and verify actual source receipts before claiming checked acceptance'),
}


def register_collection(original, collection, api):
    index = original / 'workflow-index.json'
    lock = original / '.workflow.lock'
    lock.mkdir(exist_ok=True)
    with api['locked'](lock):
        saved = api['load'](index) if index.exists() else {'collections': []}
        if str(collection) not in saved['collections']:
            saved['collections'].append(str(collection))
        api['write'](index, saved)


def intentional_denials(receipt, api):
    ids = set()
    for check in receipt.get('checks', []):
        if check.get('expected') != 'deny' or check.get('result') != 'confirmed' or check.get('intentionalDeny') is not True:
            continue
        ip, port = api['destination'](check['destination'])
        if check['layer'] == 'L7':
            layer, rule = 'HTTP/SNI', {'match': {'hosts': [api['http_host'](check['authority'], port)],
                'ports': [{'port': port}], 'methods': [check['method']], 'paths': [{'exact': check['path']}]}}
        elif check.get('sni'):
            layer, rule = 'HTTP/SNI', {'match': {'hosts': [check['sni']], 'ports': [{'port': port}]}}
        else:
            layer, rule = 'TCP', {'ip': ip, 'ports': [{'port': port}]}
        ids.add(api['refinement_module']().permission_id(layer, rule))
    return ids


def summary(root, api, collection=None, verification=None, language=None):
    root = Path(root).resolve()
    state = api['load'](root / 'session.json')
    if state.get('purpose') == 'verification':
        collection = root
        root = Path(state['observationSession']).resolve()
        state = api['load'](root / 'session.json')
    candidate = api['load'](root / 'candidate.yaml') if (root / 'candidate.yaml').exists() else None
    candidate_hash = api['evidence_module']().digest(candidate) if candidate else None
    index = api['load'](root / 'workflow-index.json') if (root / 'workflow-index.json').exists() else {}
    folders = [Path(p) for p in index.get('collections', [])]
    if collection:
        folders.append(Path(collection).resolve())
    chosen = None
    for folder in folders:
        if (folder / 'session.json').exists() and (folder / 'observe.yaml').exists():
            saved = api['load'](folder / 'session.json')
            if saved.get('observationSession') == str(root) and candidate_hash == api['evidence_module']().digest(api['load'](folder / 'observe.yaml')):
                chosen = (folder, saved)
    folder, active_state = chosen or (root, state)
    progress = api['load'](folder / 'collector.json') if (folder / 'collector.json').exists() else {}
    analysis = api['load'](root / 'analysis.json') if (root / 'analysis.json').exists() else {}
    stage = 'changed' if candidate and folders and not chosen else 'review' if candidate or analysis.get('pendingTcp') else \
        'no-data' if progress.get('phase') == 'stopped' or analysis else 'prepared'
    if state.get('purpose') == 'verification-only' and not chosen:
        stage = 'verification-prepared' if candidate_hash == state.get('initialCandidateHash') else 'verification-changed'
    ready = None
    if progress.get('phase') in ('initializing', 'ready', 'observing'):
        ready = api['collector_module']().handoff_status(folder, api)
        if not ready['readyForHandoff']:
            stage = 'collector-check'
        elif chosen:
            # Enrolled new identities end the recreation handoff, not startup acceptance.
            enrolled_uids = set(active_state.get('podUIDs', [])) & set(active_state.get('verifiedPodUIDs', []))
            new_uids = enrolled_uids - set(active_state.get('baselinePodUIDs', []))
            waiting_for_new_pods = active_state.get('verificationMode') == 'new-pods' and not new_uids
            stage = 'enforce-startup' if waiting_for_new_pods else 'enforce-traffic'
        else:
            stage = 'observing' if state.get('podUIDs') else 'observe-startup'
    elif chosen:
        stage = 'verify' if progress.get('phase') == 'stopped' else 'collector-check'
    receipt_path = verification or state.get('verificationFile')
    stale, receipt, receipt_error = False, None, None
    if receipt_path:
        path = Path(receipt_path).resolve()
        try:
            receipt = api['load'](path)
            events = api['load'](path.parent / 'events.json')
            stale = receipt.get('kind') != 'NetworkProxyVerification' or receipt.get('observationSession') != str(root) or \
                receipt.get('candidateHash') != candidate_hash or receipt.get('policy', {}).get('uid') != state.get('policyUID') or \
                receipt.get('eventsHash') != api['evidence_module']().digest(events)
            if (root / 'refinement.json').exists() and receipt.get('until'):
                decisions = api['load'](root / 'refinement.json')
                changes = decisions.get('permissionDecisions', []) + decisions.get('auditDecisions', []) + decisions.get('constraintDecisions', [])
                stale = stale or any(api['evidence_module']().instant(x['at']) > api['evidence_module']().instant(receipt['until'])
                                     for x in changes if x.get('at'))
        except (ValueError, OSError, KeyError) as exc:
            stale, receipt_error = True, str(exc)
        # A live collector always takes priority over a saved old result.
        current_collection = not chosen or receipt is not None and receipt.get('collectionSession') == str(folder.resolve())
        if not ready and current_collection:
            if stale:
                stage = 'changed'
            elif not receipt.get('checks') or any(c['result'] != 'confirmed' for c in receipt['checks']):
                stage = 'incomplete'
            elif not receipt.get('sourceReceipts') or receipt.get('sourceReceiptsHash') != api['evidence_module']().digest(receipt['sourceReceipts']):
                stage = 'legacy-evidence'
            else:
                decisions = api['load'](root / 'refinement.json').get('decisions', {}) if (root / 'refinement.json').exists() else {}
                intentional = intentional_denials(receipt, api)
                pending = [x for x in receipt.get('denials', []) if x['id'] not in intentional and
                    decisions.get(x['id'], {}).get('decision', x.get('decision', 'pending')) == 'pending']
                stage = 'denials' if pending else 'startup-verified' if (receipt.get('boundedCollection') or {}).get('verificationMode') == 'new-pods' else 'verified'
    selected_language = language or (active_state.get('reportLanguage') if chosen else None) or state.get('reportLanguage', 'en')
    if language is None and receipt and not ready and not stale:
        selected_language = receipt.get('reportLanguage', selected_language)
    zh = selected_language == 'zh-CN'
    chinese, english, actor, action = TEXT[stage]
    chinese_actions = {
        'verification-changed': '审核变化后的候选，并重新初始化验证。此本地状态不证明集群部署状态。',
        'verification-prepared': '准备独立验证采集窗口，再检查采集就绪。无需重新审核未变化的已批准范围。',
        'prepared': '确认观察方案，再准备策略和采集器。', 'observe-startup': '创建或重建目标 Pod，并运行代表性业务。',
        'observing': '在截止前运行约定的业务场景。', 'collector-check': '先核对采集器，再安排应用操作。',
        'review': '审核业务必需的请求及其权限范围。', 'no-data': '说明证据缺口，按需准备新的有界观察。',
        'enforce-traffic': '复用已注入的 Pod，用新连接测试允许和拒绝。', 'enforce-startup': '重建目标 Pod，测试启动和业务。',
        'verify': '核对客户端、后端、审计和配置证据。', 'changed': '审核并应用已批准的变更，检查配置后测试。',
        'denials': '判断被拒绝的请求是否为业务必需。', 'verified': '确认业务覆盖范围，按需做最终启动验收。',
        'startup-verified': '接受已测试的范围，或补充业务场景。', 'incomplete': '说明证据缺口或冲突，安排一次针对性复测。',
        'legacy-evidence': '保留历史结果，核对实际回执后再验收。'}
    result = {'kind': 'NetworkProxyWorkflowStatus', 'checkedAt': api['now'](), 'stage': stage,
        'message': chinese if zh else english, 'nextActor': actor, 'nextAction': chinese_actions[stage] if zh else action,
        'observationSession': str(root), 'currentCollection': str(folder), 'candidateHash': candidate_hash,
        'verificationFile': str(receipt_path) if receipt_path else None, 'verificationStale': stale, 'receiptError': receipt_error,
        'verificationAppliesToCurrentCollection': not chosen or receipt is not None and receipt.get('collectionSession') == str(folder.resolve()),
        'handoff': ready, 'deadline': progress.get('plan', {}).get('until'),
        'permissionCount': len(api['refinement_module']().permissions(api['network_rules'](candidate['spec']['policy']).get('egress', {}))) if candidate else 0,
        'deploymentState': 'not-queried',
        'basis': 'Saved workflow evidence; this summary does not establish current cluster configuration or complete business coverage',
        'reportLanguage': selected_language}
    if candidate:
        egress = api['network_rules'](candidate['spec']['policy']).get('egress', {})
        result['denyAll'] = egress.get('defaultAction') == 'deny' and not any('allow' in r.get('qualifiers', [])
            for key in ('rules', 'httpRules') for r in egress.get(key, []))
    return result


def write_summary(root, result, api):
    root = Path(root)
    api['write'](root / 'workflow-status.json', result)
    zh = result['reportLanguage'] == 'zh-CN'
    actor = ('用户' if result['nextActor'] == 'user' else '助手') if zh else result['nextActor']
    lines = ['# ' + ('当前进度' if zh else 'Current progress'), '', result['message'], '',
             ('下一步由' + actor + '执行：' if zh else 'Next actor: ' + actor + '. ') + result['nextAction'], '',
             ('依据已保存的记录，尚未查询当前集群状态。' if zh else 'Based on saved records; current cluster state has not been queried.')]
    if result.get('denyAll'):
        lines += ['', '候选将拒绝所有被代理的 TCP 流量。' if zh else 'The candidate denies all redirected TCP traffic.']
    if result['deadline'] and result.get('handoff'):
        lines += ['', ('截止时间：' if zh else 'Deadline: ') + result['deadline']]
        handoff = result['handoff']
        if handoff.get('readyForHandoff'):
            lines += [('检查时间：' if zh else 'Checked at: ') + handoff['checkedAt'],
                      ('剩余秒数：' if zh else 'Remaining seconds: ') + str(handoff.get('remainingSeconds'))]
    lines += ['', '[' + ('详细状态' if zh else 'Detailed status') + '](' + str((root / 'workflow-status.json').resolve()) + ')']
    (root / 'workflow-status.md').write_text('\n'.join(lines) + '\n')


def status(args, api):
    result = summary(args.session, api, args.collection_session, args.verification, args.language)
    write_summary(Path(result['observationSession']), result, api)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0
