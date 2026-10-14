# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Initialize approved-policy verification without importing observation evidence."""
import copy
import hashlib
from pathlib import Path
import uuid


RESOURCE_FIELDS = {
    'interval': 'intervalSeconds', 'discovery_interval': 'discoveryIntervalSeconds',
    'analysis_interval': 'analysisIntervalSeconds', 'max_session_mb': 'maxSessionMiB',
    'max_read_mb': 'maxReadMiB', 'min_interval': 'minIntervalSeconds',
    'max_transfer_mb_per_minute': 'maxTransferMiBPerMinute',
    'max_concurrent_reads': 'maxConcurrentReads', 'max_round_seconds': 'maxRoundSeconds',
    'source': 'source', 'agent_namespace': 'agentNamespace',
    'agent_selector': 'agentSelector', 'agent_container': 'agentContainer',
}


def pin(policy, api):
    return {'uid': policy['metadata']['uid'], 'generation': policy['metadata'].get('generation'),
            'specHash': api['evidence_module']().digest(policy['spec'])}


def limits(args, expected, api):
    defaults = api['parser']().parse_args(['monitor', '--session', args.session])
    budget_root = None
    if args.budget_session:
        folder = Path(args.budget_session).resolve()
        old = api['load'](folder / 'session.json')
        manifest = api['load'](folder / 'observe.yaml')
        if (old['context'], old['namespace'], old['policy']) != (args.context, args.namespace, args.name) or \
                manifest['spec']['target'] != expected['spec']['target']:
            raise ValueError('Budget continuation requires the same context, namespace, policy name and target')
        prior = api['load'](folder / 'collector.json')['plan']
        for field, key in RESOURCE_FIELDS.items():
            supplied = getattr(args, field)
            if supplied is not None and supplied != prior[key]:
                raise ValueError('Budget continuation cannot change agreed limits or log sources')
            setattr(defaults, field, prior[key])
        budget_root = Path(old.get('budgetSession', str(folder))).resolve()
        owner = api['load'](budget_root / 'session.json')
        if (owner['context'], owner['namespace'], owner['policy']) != (args.context, args.namespace, args.name):
            raise ValueError('Budget ledger owner has a different workflow identity')
    else:
        for field in RESOURCE_FIELDS:
            supplied = getattr(args, field)
            if supplied is not None:
                setattr(defaults, field, supplied)
    return api['collector_module']().resource_plan(defaults), budget_root


def initialize(args, api):
    root = Path(args.session).resolve()
    if root.exists() and (not root.is_dir() or any(root.iterdir())):
        raise ValueError('Verification initialization requires a new or empty directory')
    if not api['safe_text'](args.approval_evidence) or not args.approval_evidence.strip():
        raise ValueError('Supply explicit approval evidence for this deployed candidate and verification plan')
    source = Path(args.policy_file).resolve()
    source_bytes = source.read_bytes()
    expected = api['load'](source)
    if source.read_bytes() != source_bytes:
        raise ValueError('Candidate input changed during initialization')
    if expected.get('kind') != 'VarmorPolicy' or expected.get('apiVersion') != 'crd.varmor.org/v1beta1' or \
            expected.get('metadata', {}).get('name') != args.name or expected['metadata'].get('namespace') != args.namespace:
        raise ValueError('Use a namespaced VarmorPolicy candidate with this exact name and namespace')
    if expected['spec'].get('updateExistingWorkloads', False) or \
            api['network_rules'](copy.deepcopy(expected['spec']['policy']))['egress'].get('defaultAction') != 'deny':
        raise ValueError('Approved verification requires default deny and updateExistingWorkloads=false')
    planned, budget_root = limits(args, expected, api)
    if budget_root and (root == budget_root or root in budget_root.parents or budget_root in root.parents):
        raise ValueError('Use a new verification workflow separate from the existing budget owner')
    policy = api['get'](args.context, 'varmorpolicies', args.namespace, args.name)
    if policy.get('kind') != expected['kind'] or policy.get('apiVersion') != expected['apiVersion'] or \
            policy['spec'] != expected['spec']:
        raise ValueError('Current complete Policy spec differs from the approved candidate; review before initialization')
    identity = pin(policy, api)
    pods = api['get'](args.context, 'pods', args.namespace)['items']
    wanted = set(args.pod_uid or [])
    if len(wanted) != len(args.pod_uid or []):
        raise ValueError('Validation Pod UIDs must be unique')
    baseline = sorted({p['metadata']['uid'] for p in pods} - wanted)
    state = {'version': 2, 'purpose': 'verification-only', 'context': args.context,
        'namespace': args.namespace, 'policy': args.name, 'policyUID': identity['uid'],
        'profile': policy.get('status', {}).get('profileName', f'varmor-{args.namespace}-{args.name}'),
        'mitmDomains': copy.deepcopy(expected['spec']['policy'].get('networkProxyConfig', {}).get('mitm', {}).get('domains', [])),
        'createdAt': api['now'](), 'startedAt': int(api['dt'].datetime.now(api['dt'].timezone.utc).timestamp()),
        'sessionId': uuid.uuid4().hex, 'reportLanguage': args.language,
        'podUIDs': sorted(wanted), 'verifiedPodUIDs': sorted(wanted), 'baselinePodUIDs': baseline,
        'podHistory': {}, 'verificationTarget': expected['spec']['target'],
        'verificationMode': 'new-pods' if args.new_pods else 'existing-pods',
        'initialPolicy': identity, 'initialCandidateHash': api['evidence_module']().digest(expected),
        'verificationOrigin': 'approved-deployed-policy', 'resourcePlan': planned,
        'budgetSession': str(budget_root or root), 'modelingAllowed': False}
    for uid in wanted:
        matches = [p for p in pods if p['metadata']['uid'] == uid]
        if len(matches) != 1 or matches[0]['metadata'].get('namespace') != args.namespace or \
                matches[0]['metadata'].get('annotations', {}).get('pod.networkproxy.security.beta.varmor.org') != 'localhost/' + state['profile'] or \
                not any(c['name'] == 'varmor-network-proxy' for c in matches[0]['spec'].get('containers', [])) or \
                not api['collector_module']().startup_target_matches(state, matches[0], api):
            raise ValueError('Explicit Pod UID must be currently injected and owned by this target')
    if identity != pin(api['get'](args.context, 'varmorpolicies', args.namespace, args.name), api):
        raise ValueError('Policy identity or complete spec changed during initialization')
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    api['write'](root / 'session.json', state)
    api['write'](root / 'original-policy.json', policy)
    api['write'](root / 'candidate.yaml', expected)
    # The legacy filename is a frozen verification input, never an observation rollback.
    api['write'](root / 'observe.yaml', expected)
    api['write'](root / 'collector.json', {'phase': 'prepared', 'plan': planned})
    api['write'](root / 'candidate-provenance.json', {
        'kind': 'ApprovedDeployedPolicyVerification', 'recordedAt': api['now'](),
        'sourceFile': str(source), 'sourceByteHash': hashlib.sha256(source_bytes).hexdigest(),
        'candidateHash': api['evidence_module']().digest(expected), 'policy': identity,
        'approvalEvidence': args.approval_evidence, 'observationEventsImported': 0,
        'priorVerificationImported': False, 'basis': 'Current API identity and full spec equality; no loading or business success claim'})
    api['workflow_module']().write_summary(root, api['workflow_module']().summary(root, api), api)
    print(api['json'].dumps({'status': 'verification-workflow-initialized', 'session': str(root),
        'policy': identity, 'baselinePodUIDs': baseline, 'selectedPodUIDs': sorted(wanted),
        'next': 'Use prepare-verification in a separate directory, then bounded monitor and fresh ready-check',
        'noObservationOrDeployment': True}))
    return 0
