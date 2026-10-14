#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Kubernetes contract double for subprocess workflow tests; never validates real Envoy semantics."""
import json
import importlib.util
import os
from pathlib import Path
import sys
import time
from urllib.parse import urlsplit

path = Path(os.environ['ADVISOR_FAKE_CLUSTER'])
state = json.loads(path.read_text()) if path.exists() else {'calls': [], 'events': [], 'backend': []}
args = sys.argv[1:]
assert args[:2] == ['--context', 'test-context'], 'the workflow must pin the context'
assert args[2].startswith('--request-timeout=')
args = args[3:]
state['calls'].append(args)


def option(name, default=None):
    return args[args.index(name) + 1] if name in args else default


def emit(value):
    print(json.dumps(value) if not isinstance(value, str) else value)


def save():
    path.write_text(json.dumps(state))


def deny(message):
    save()
    print(message, file=sys.stderr)
    raise SystemExit(1)


ns = option('-n')
verb = args[0]
if verb == 'get':
    resource = args[1]
    if resource == 'nodes':
        emit({'items': [{'metadata': {'name': 'node-1'}, 'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}]})
    elif resource == 'crd':
        emit({'spec': {'versions': [{'name': 'v1beta1', 'served': True,
             'schema': {'openAPIV3Schema': {'properties': {'spec': {'properties': {
             'updateExistingWorkloads': {'type': 'boolean'}, 'policy': {'properties': {
             'networkProxyConfig': {'type': 'object'}, 'enhanceProtect': {'properties': {
             'networkProxyRawRules': {'properties': {'egress': {'properties': {
             'defaultAction': {'type': 'string'}, 'httpRules': {'type': 'array'},
             'rules': {'type': 'array'}}}}}}}}}}}}}}}]}})
    elif resource == 'mutatingwebhookconfigurations':
        emit({'items': [{'webhooks': [{'name': 'mutatepod.varmor.org', 'clientConfig': {'url': 'https://local/mutate'}}]}]})
    elif resource == 'varmorpolicies':
        emit(state['policy'])
    elif resource == 'pods':
        if ns == 'varmor':
            emit({'items': [{'metadata': {'name': 'varmor-agent-xyz'}, 'spec': {'nodeName': 'node-1',
                  'containers': [{'name': 'agent', 'command': ['/varmor/vArmor', '--agent']}]}}]})
        else:
            profile = 'varmor-' + ns + '-observe-client'
            emit({'items': [{'metadata': {'name': 'client-abc', 'uid': 'client-uid', 'labels': {'app': 'client'},
                  'annotations': {'pod.networkproxy.security.beta.varmor.org': 'localhost/' + profile}},
                  'spec': {'nodeName': 'node-1', 'containers': [{'name': 'app'}, {'name': 'varmor-network-proxy'}],
                           'volumes': [{'name': 'varmor-network-proxy-audit-als', 'hostPath': {'path': '/run/varmor'}}]}}]})
    else:
        deny('unsupported resource: ' + resource)
elif verb == 'create' and args[1] == 'namespace':
    state['namespace'] = args[2]
    assert state['namespace'].startswith('np-advisor-smoke-')
    emit('created')
elif verb == 'apply':
    skill_root = Path(os.environ.get('ADVISOR_FAKE_SKILL_ROOT', str(Path(__file__).resolve().parents[2])))
    spec = importlib.util.spec_from_file_location('policy_yaml_fixture', skill_root / 'scripts/yamlio.py')
    yamlio = importlib.util.module_from_spec(spec); spec.loader.exec_module(yamlio)
    manifest = yamlio.loads(Path(option('-f')).read_text())
    if manifest.get('kind') == 'VarmorPolicy':
        egress = manifest['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']
        if egress['defaultAction'] == 'deny' and os.environ.get('ADVISOR_FAKE_REJECT_CANDIDATE'):
            deny('candidate rejected by simulated admission')
        if '--dry-run=server' not in args:
            manifest['metadata']['uid'] = 'owned-policy-uid'
            manifest['metadata']['generation'] = 2 if egress['defaultAction'] == 'deny' else 1
            manifest['status'] = {'ready': True, 'profileName': 'varmor-' + state['namespace'] + '-observe-client'}
            state['policy'] = manifest
            state['enforcing'] = egress['defaultAction'] == 'deny'
    elif manifest.get('kind') == 'List':
        state['workloads'] = manifest
    else:
        deny('unexpected apply')
    emit('applied')
elif verb in ('wait', 'rollout'):
    emit('ready')
elif verb == 'exec':
    command = args[args.index('--') + 1:]
    if command == ['cat', '/tmp/hits.tsv']:
        emit('\n'.join('\t'.join([e['method'], e['path'], e['authority']]) for e in state['backend']))
    elif command[0] in ('cat', 'sh'):
        if os.environ.get('ADVISOR_FAKE_BAD_AUDIT'):
            emit('not normalized JSONL')
        else:
            emit('\n'.join(map(json.dumps, state['events'])))
    else:
        assert command[0] == 'curl'
        url = next(x for x in command if x.startswith('http://'))
        method = command[command.index('-X') + 1]
        authority = command[command.index('-H') + 1].removeprefix('Host: ') if '-H' in command else ''
        parsed = urlsplit(url)
        authority = authority or parsed.netloc
        normal_host = 'backend.' + state['namespace'] + '.svc.cluster.local:8080'
        allowed = not state.get('enforcing') or (authority == normal_host and
                   (method, parsed.path) in [('GET', '/read'), ('POST', '/write')])
        # One gate request reaches the old configuration during xDS propagation.
        if state.get('enforcing') and parsed.path == '/config-probe-unlisted' and not state.get('gateProbe'):
            allowed = True
            state['gateProbe'] = True
        code = 200 if allowed else 403
        event = {'enforcer': 'NetworkProxy', 'action': 'AUDIT' if allowed else 'DENIED',
                 'eventTimestamp': int(time.time()), 'profileName': 'varmor-' + state['namespace'] + '-observe-client',
                 'podNamespace': state['namespace'], 'podUID': 'client-uid', 'nodeName': 'node-1',
                 'event': {'layer': 'L7', 'filterChain': 'http_chain', 'dstAddress': '10.0.0.8:8080',
                           'authority': authority, 'method': method, 'path': parsed.path, 'responseCode': code}}
        state['events'].append(event)
        if allowed or os.environ.get('ADVISOR_FAKE_BACKEND_LEAK'):
            state['backend'].append({'authority': authority, 'method': method, 'path': parsed.path})
        emit((method + ' ' + parsed.path if allowed else 'denied') + '\n' + str(code))
elif verb == 'logs':
    emit('\n'.join(map(json.dumps, state['backend'])))
elif verb == 'delete' and args[1] == 'namespace':
    assert args[2] == state['namespace'], 'must only delete the owned namespace'
    if os.environ.get('ADVISOR_FAKE_FAIL_CLEANUP'):
        deny('simulated cleanup failure')
    state['deletedNamespace'] = args[2]
    emit('deleted')
else:
    deny('unsupported command: ' + repr(args))
save()
