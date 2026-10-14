#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Independent owned MITM/TCP regression using installed Skill receipt interfaces.

This is a maintainer operator, never a normal Skill lifecycle implementation.
All literal predicates are set before traffic. Secret bytes remain ephemeral.
"""
import argparse
import datetime as dt
import hashlib
from http.client import HTTPResponse
import importlib.util
import io
import os
import json
from pathlib import Path
import subprocess
import signal
import uuid
import sys
import time


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def admin_document(raw):
    """Decode the original HTTP bytes; text newline conversion breaks chunk framing."""
    if not isinstance(raw, bytes) or len(raw) > 4194304:
        raise ValueError('Admin response must be bounded original bytes')
    class Socket:
        def makefile(self, *unused):
            return io.BytesIO(raw)
    response = HTTPResponse(Socket())
    response.begin()
    if response.status != 200:
        raise RuntimeError('Bounded active version diagnostic did not return HTTP 200')
    return json.loads(response.read())


def tcp_denial_decision(report, address):
    """Select the actual exact denied scope, never substitute an observation approval."""
    selected = [d for d in report.get('denials', []) if d.get('origin') == 'DENIED' and
        d.get('reviewable') is True and d.get('layer') == 'TCP' and
        d.get('rule', {}).get('ip') == address and d['rule'].get('ports') == [{'port': 9090}]]
    if len(selected) != 1:
        raise ValueError('A unique reviewable exact TCP DENIED item is required')
    return {'id': selected[0]['id'], 'decision': 'approve',
        'reason': 'Owned required TCP endpoint; exact whole IP/port scope reviewed',
        'approvalEvidence': 'Authorized isolated maintainer approval of this actual DENIED item'}


def tcp_reply_confirmed(receipt):
    return receipt.get('exitCode') == 0 and 'probe_reply=matched\n' in receipt.get('stdout', '')


def main(cfg, output=None):
    cfg = dict(cfg)
    root = Path(cfg['root'])
    out = Path(output).resolve() if output else root / 'compat'
    if out.exists() and any(out.iterdir()):
        raise ValueError('Use a new or empty output directory')
    out.mkdir(parents=True,exist_ok=True)
    records = out / 'tool-records'
    records.mkdir(exist_ok=True)
    cli = Path(cfg['installedSkill']) / 'scripts/advisor.py'
    a = module('compat_advisor', cli)
    fixture_source=Path(__file__).resolve().parent
    smoke = module('compat_http_fixture', fixture_source/'smoke_cluster.py')
    tls = module('compat_tls_fixture', fixture_source/'smoke_tls_tcp.py')
    tls.a = a
    ns = 'np-advisor-tls-' + cfg['runId']
    session = out / 'observation'
    ctx = cfg['context']
    kubectl = ['kubectl', '--context', ctx]
    result = {'namespace': ns, 'scope': 'owned MITM HTTP and raw TCP; fresh closed connections',
              'status': 'running', 'startedAt': a.now(), 'phases': [], 'checks': [],
              'limitations': ['Controlled TLS upstream signed by temporary policy CA; no public PKI, mTLS, pinning, IPv6 or startup acceptance claim.',
                             'Separate snapshot continuity is not assessed; primary observation/enforcement use bounded monitors.',
                             'Receipt files bind real supplied command output, not independent source authenticity.']}
    monitors = []
    started = time.monotonic()

    def guard():
        if time.monotonic() - started > cfg['maxSeconds'] or dt.datetime.now(dt.timezone.utc) >= dt.datetime.fromisoformat(cfg['deadline']):
            raise RuntimeError('Authorized test deadline exhausted')

    def run(label, argv, allowed=(0,), data=None, sensitive=False, binary=False):
        cleanup_operation = label.startswith(('cleanup-','namespace-delete','namespace-deleted','namespace-absence'))
        if not cleanup_operation:
            guard()
        remaining = min(cfg['maxSeconds'] - (time.monotonic() - started),
            (dt.datetime.fromisoformat(cfg['deadline']) - dt.datetime.now(dt.timezone.utc)).total_seconds())
        timeout = 120 if sensitive else 180
        if not cleanup_operation:
            timeout = min(timeout, max(0.01, remaining))
        if sensitive:
            begun = a.now()
            try:
                r = subprocess.run(argv, input=data, text=not binary, capture_output=True, timeout=timeout)
            except subprocess.TimeoutExpired:
                a.write(records / (label + '.json'), {'argv': argv, 'startedAt': begun,
                    'endedAt': a.now(), 'exitCode': 124, 'reason': 'Sensitive operation timed out; output and input are not retained'})
                raise RuntimeError(label + ' sensitive operation timed out') from None
            saved = {'argv': argv, 'startedAt': begun, 'endedAt': a.now(), 'exitCode': r.returncode,
                     'stdoutSHA256': hashlib.sha256(r.stdout if binary else r.stdout.encode()).hexdigest(),
                     'stderrSHA256': hashlib.sha256(r.stderr if binary else r.stderr.encode()).hexdigest(),
                     'stdoutBytes': len(r.stdout if binary else r.stdout.encode()),
                     'reason': 'Secret/config output is not retained'}
            a.write(records / (label + '.json'), saved)
            if r.returncode not in allowed:
                raise RuntimeError(label + ' failed; sensitive output retained only as hash')
            return {'stdout': r.stdout, 'stderr': r.stderr, **saved}
        begun = a.now()
        try:
            r = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout)
            saved = {'argv': argv, 'startedAt': begun, 'endedAt': a.now(),
                     'exitCode': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr}
        except subprocess.TimeoutExpired as exc:
            saved = {'argv': argv, 'startedAt': begun, 'endedAt': a.now(), 'exitCode': 124,
                     'stdout': str(exc.stdout or ''), 'stderr': 'Maintainer operation deadline exceeded'}
        saved['receiptFile'] = str(records / (label + '.json'))
        a.write(records / (label + '.json'), saved)
        if saved['exitCode'] not in allowed:
            raise RuntimeError(label + ' failed: ' + saved['stderr'][-2000:])
        print(label + ': exit=' + str(saved['exitCode']), flush=True)
        return saved

    def skill(label, *argv, allowed=(0,)):
        return run(label, [sys.executable, str(cli), *argv], allowed)

    def kube(label, *argv, **kw):
        return run(label, [*kubectl, *argv], **kw)

    def read(label, kind, name=None):
        args = ['get', kind, '-n', ns]
        if name:
            args.append(name)
        return json.loads(kube(label, *args, '-o', 'json')['stdout'])

    def identity(label):
        p = read(label, 'pod', client)
        if p['metadata']['uid'] != uid:
            raise RuntimeError('Client Pod UID changed at execution')

    def http(label, path, method='GET'):
        identity(label+'-uid')
        return kube(label, 'exec', '-n', ns, client, '-c', 'app', '--', 'curl', '--noproxy', '*',
                    '-sS', '--max-time', '8', '--resolve', host+':8443:'+ip, '-X', method,
                    '-w', '\nHTTP %{http_code}\n', 'https://'+host+':8443'+path, allowed=(0,))

    def tcp(label, payload, denied=False, port=9090):
        identity(label+'-uid')
        # Require the real protocol reply, never a fabricated completion flag.
        probe = (Path(cfg['installedSkill']) / 'scripts/tcp_probe.sh').read_text()
        return kube(label, 'exec', '-i', '-n', ns, client, '-c', 'app', '--',
                    'sh', '-s', '--', ip, str(port), payload, 'tcp-ok', '8',
                    data=probe, allowed=(0, 3))

    def receipt(folder, check, raw, role, contains=(), absent=(), since=None, until=None, expected_exit=0):
        p = folder / (check['id']+'-'+role+'.json')
        content = {'kind': 'NetworkProxyCommandReceipt', 'checkId': check['id'], 'podUID': uid,
                   **{k: raw[k] for k in ('startedAt','endedAt','exitCode','stdout')},
                   'sourceToolRecord': raw['receiptFile']}
        if role == 'backend' and check['expected'] == 'deny':
            content.update(coverageSince=since, coverageUntil=until)
        a.write(p, content)
        return {'file': str(p), 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                'exitCode': expected_exit, 'stdoutContains': list(contains), 'stdoutAbsent': list(absent)}

    def start_monitor(label, collection):
        guard()
        remaining = min(420, cfg['maxSeconds'] - (time.monotonic() - started),
            (dt.datetime.fromisoformat(cfg['deadline']) - dt.datetime.now(dt.timezone.utc)).total_seconds())
        remaining = int(remaining)
        if remaining < 1:
            raise RuntimeError('Insufficient remaining time to launch a bounded collector')
        command = [sys.executable, str(cli), 'monitor', '--session', str(collection), '--duration', str(remaining),
                   '--interval', '10', '--min-interval', '5', '--analysis-interval', '30']
        a.write(collection.parent / (label+'-monitor-launch.json'), {'argv': command, 'startedAt': a.now()})
        log = (collection.parent/(label+'-monitor-recorder.json')).open('w')
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        monitors.append((proc, collection, log))
        for _ in range(90):
            progress = collection/'collector.json'
            if progress.exists() and a.load(progress).get('phase') in ('ready','observing'):
                break
            if proc.poll() is not None:
                raise RuntimeError('Monitor stopped before readiness: '+label)
            time.sleep(1)
        else:
            raise RuntimeError('Monitor readiness timeout: '+label)
        skill(label+'-ready', 'ready-check', '--session', str(collection))
        return proc, collection, log

    def stop_monitor(label, tracked):
        proc,collection,log=tracked
        skill(label+'-stop','stop','--session',str(collection))
        if proc.wait(timeout=60) != 0:
            raise RuntimeError('Collector exited with failure; retain its raw output and collection state')
        log.close()
        monitors.remove(tracked)

    def phase(name, checks, actions, expected_code, refine_denials=False):
        folder = out/name
        folder.mkdir()
        candidate = a.load(session/'candidate.yaml')
        current = read(name+'-approved-export','varmorpolicy',state['policy'])
        if candidate['spec'] != current['spec']:
            raise RuntimeError('Current full Policy spec differs from the reviewed fixture candidate')
        a.write(folder/'applied-policy.yaml', candidate)
        hub = folder / 'workflow'
        skill(name+'-init', 'init-verification', '--session', str(hub), '--context', ctx,
              '--namespace', ns, '--name', state['policy'], '--policy-file', str(folder/'applied-policy.yaml'),
              '--pod-uid', uid, '--budget-session', str(session), '--language', 'zh-CN',
              '--approval-evidence', 'Authorized isolated maintainer acceptance of this reviewed deployed candidate and inherited finite plan')
        # A verification-only hub cannot change permissions. DENIED refinement
        # belongs to the original observation owner, using its own fresh child.
        owner = session if refine_denials else hub
        skill(name+'-prepare', 'prepare-verification', '--session', str(folder/'collection'),
              '--observation-session', str(owner), '--policy-file', str(folder/'applied-policy.yaml'), '--pod-uid', uid)
        tracked=start_monitor(name,folder/'collection')
        skill(name+'-config-before', 'active-config', '--session', str(hub), '--policy-file',
              str(folder/'applied-policy.yaml'), '--pod-uid', uid, '--output', str(folder/'config-before.json'), allowed=(0,) if cfg.get('automaticProof') else (2,))
        offsets={}
        for container,path in [('app','/tmp/hits.tsv'),('tcp','/tmp/tcp-hits')]:
            offset=kube(name+'-offset-'+container,'exec','-n',ns,backend,'-c',container,'--','sh','-c',
                        'wc -l < "$1"','test',path)
            offsets[container]=int(offset['stdout'].strip())
        a.write(folder/'backend-offsets.json',{'pod':backend,'offsets':offsets,'capturedAt':a.now()})
        since = a.now()
        raw = [action() for action in actions]
        until = a.now()
        backend_http = kube(name+'-backend-http','exec','-n',ns,backend,'-c','app','--','tail','-n',
                            '+'+str(offsets['app']+1),'/tmp/hits.tsv')
        backend_tcp = kube(name+'-backend-tcp','exec','-n',ns,backend,'-c','tcp','--','tail','-n',
                           '+'+str(offsets['tcp']+1),'/tmp/tcp-hits')
        skill(name+'-config-after', 'active-config', '--session', str(hub), '--policy-file',
              str(folder/'applied-policy.yaml'), '--pod-uid', uid, '--output', str(folder/'config-after.json'), allowed=(0,) if cfg.get('automaticProof') else (2,))
        time.sleep(35)
        stop_monitor(name,tracked)
        pinned = a.load(folder/'collection/enforcement-collection.json')['policy']
        bundle = {'kind':'NetworkProxyCheckReceipts','candidateHash':a.evidence_module().digest(candidate),
                  'policy':pinned,'podUIDs':[uid],'since':since,'until':until,'checks':[]}
        for check, execution in zip(checks,raw):
            ref={'id':check['id'],'podUID':uid}
            if cfg.get('automaticProof'):
                ref['configuration'] = [{'file': str(folder/f), 'sha256': hashlib.sha256((folder/f).read_bytes()).hexdigest()}
                    for f in ('config-before.json', 'config-after.json')]
            if check['layer']=='L7':
                contains=['HTTP 200', 'GET /read'] if check['expected']=='allow' else ['HTTP 403']
                ref['client']=receipt(folder,check,execution,'client',contains=contains)
                marker=check['method']+'\t'+check['path']+'\t'+host+':8443'
                ref['backend']=receipt(folder,check,backend_http,'backend',
                    contains=[marker] if check['expected']=='allow' else [],
                    absent=[marker] if check['expected']=='deny' else [],since=since,until=until)
            else:
                ref['client']=receipt(folder,check,execution,'client',
                    contains=['tcp-ok', 'probe_reply=matched'] if check['expected']=='allow' else ['probe_reply=missing_or_mismatch'],
                    absent=['tcp-ok'] if check['expected']=='deny' else [],
                    expected_exit=0 if check['expected']=='allow' else 3)
                ref['backend']=receipt(folder,check,backend_tcp,'backend',
                    contains=[check['id']] if check['expected']=='allow' else [],
                    absent=[check['id']] if check['expected']=='deny' else [],since=since,until=until)
            bundle['checks'].append(ref)
        a.write(folder/'checks.json',{'checks':checks})
        a.write(folder/'receipts.json',bundle)
        status=skill(name+'-verify','verify','--session',str(folder/'verification'),'--observation-session',str(owner),
              '--collection-session',str(folder/'collection'),'--policy-file',str(folder/'applied-policy.yaml'),
              '--pod-uid',uid,'--since',since,'--until',until,'--checks',str(folder/'checks.json'),
              '--receipts',str(folder/'receipts.json'),'--language','zh-CN',allowed=(0,2))['exitCode']
        report=a.load(folder/'verification/verification.json')
        result['phases'].append({'name':name,'exitCode':status,'summary':report['summary'],
                                 'quietReadComplete':report['quietReadComplete'],'events':report['events']})
        result['checks'].extend(report['checks'])
        skill(name+'-workflow','workflow-status','--session',str(owner),'--verification',str(folder/'verification/verification.json'))
        a.write(out/'result.json',result)
        if status!=expected_code:
            raise RuntimeError('Unexpected verification result in '+name+': '+json.dumps(report['summary']))
        return report

    created=False
    try:
        if session.exists():
            raise RuntimeError('Fresh observation directory required')
        skill('preflight', 'doctor', '--context', ctx, '--output', str(out/'preflight.json'))
        kube('namespace-create','create','namespace',ns)
        created=True
        owned_uid=read('namespace-ownership','namespace',ns)['metadata']['uid']
        host='mitm.'+ns+'.test'
        skill('observe','observe','--session',str(session),'--context',ctx,'--namespace',ns,
              '--name','observe-client','--workload','client','--observe','both','--mitm-domain',host,'--language','zh-CN')
        kube('observe-dry-run','apply','--dry-run=server','-f',str(session/'observe.yaml'))
        kube('observe-apply','apply','-f',str(session/'observe.yaml'))
        kube('observe-ready','wait','-n',ns,'--for=condition=Ready','varmorpolicy/observe-client','--timeout=60s')
        state=a.load(session/'session.json')
        observation_monitor=start_monitor('observation',session)
        # Fixture certificate helper reads only this owned policy's CA; no key is persisted.
        cert=tls.fixture_certificate(ctx,ns,state['profile'],[host], secret_reader=lambda: json.loads(
            kube('fixture-owned-ca-read', 'get', 'secret', state['profile'], '-n', ns, '-o', 'json', sensitive=True)['stdout']))
        backend_session=out/'backend-policy'
        skill('backend-observe','observe','--session',str(backend_session),'--context',ctx,'--namespace',ns,
              '--name','backend-fixture','--workload','backend','--observe','both','--language','zh-CN')
        kube('backend-policy-apply','apply','-f',str(backend_session/'observe.yaml'))
        kube('backend-policy-ready','wait','-n',ns,'--for=condition=Ready','varmorpolicy/backend-fixture','--timeout=60s')
        server=smoke.workload(ns,'backend',cfg['image'],['sh','-c',smoke.SERVER])
        server['metadata']['labels']={'sandbox.varmor.org/enable':'true'}
        server['spec']['template']['metadata']['labels']['sandbox.varmor.org/enable']='true'
        spec=server['spec']['template']['spec']
        spec['containers'] += [{'name':'tcp','image':cfg['image'],'command':['sh','-c',tls.TCP_SERVER]}]
        service={'apiVersion':'v1','kind':'Service','metadata':{'name':'backend','namespace':ns},'spec':{'selector':{'app':'backend'},
                 'ports':[{'name':'tls','port':8443,'targetPort':8443},{'name':'tcp','port':9090,'targetPort':9090},
                          {'name':'tcp-neighbor','port':9091,'targetPort':9090}]}}
        a.write(out/'owned-workloads.yaml',{'apiVersion':'v1','kind':'List','items':[server,service,
                smoke.workload(ns,'client',cfg['image'],['sleep','3600'])]})
        kube('workloads-create','apply','-f',str(out/'owned-workloads.yaml'))
        for name in ('backend','client'):
            kube(name+'-ready','rollout','status','-n',ns,'deploy/'+name,'--timeout=90s')
        pods=read('pods-identity','pods')['items']
        client=next(p['metadata']['name'] for p in pods if p['metadata']['labels']['app']=='client')
        backend=next(p['metadata']['name'] for p in pods if p['metadata']['labels']['app']=='backend')
        uid=next(p['metadata']['uid'] for p in pods if p['metadata']['name']==client)
        ip=read('service-ip','service','backend')['spec']['clusterIP']
        backend_obj=next(p for p in pods if p['metadata']['name']==backend)
        proxy=next(c['name'] for c in backend_obj['spec']['containers'] if c['name']=='varmor-network-proxy')
        fixture_config=tls.tls_config()
        common=fixture_config['static_resources']['listeners'][0]['filter_chains'][0]['transport_socket']['typed_config']['common_tls_context']
        common['tls_certificates'][0]['certificate_chain']['filename']='/tmp/compat-fixture/tls.crt'
        common['tls_certificates'][0]['private_key']['filename']='/tmp/compat-fixture/tls.key'
        import base64
        fixture_payload='mkdir -p /tmp/compat-fixture\n'
        for name,value in [('tls.crt',cert['tls.crt']),('tls.key',cert['tls.key']),
                           ('envoy.json',base64.b64encode(json.dumps(fixture_config).encode()).decode())]:
            fixture_payload+='printf %s '+value+' | base64 -d > /tmp/compat-fixture/'+name+'\n'
        fixture_payload+='chmod 700 /tmp/compat-fixture; chmod 600 /tmp/compat-fixture/*; chown -R 1337:1337 /tmp/compat-fixture\n'
        fixture_payload+='nohup setpriv --reuid=1337 --regid=1337 --clear-groups envoy --base-id 1 -c /tmp/compat-fixture/envoy.json > /tmp/compat-fixture/envoy.log 2>&1 < /dev/null &\nprintf "fixture-process=%s\\n" "$!"\n'
        kube('fixture-tls-process','exec','-i','-n',ns,backend,'-c',proxy,'--','sh',
             data=fixture_payload,sensitive=True)
        time.sleep(2)
        result.update(clientPodUID=uid,clientPod=client,backendPod=backend,backendIP=ip,mitmHost=host)
        observed_http=http('observe-http','/read')
        if 'HTTP 200' not in observed_http['stdout']:
            kube('fixture-tls-diagnostic','exec','-n',ns,backend,'-c',proxy,'--','tail','-30','/tmp/compat-fixture/envoy.log')
            raise RuntimeError('Controlled TLS fixture observation failed; retained actual response and diagnostic')
        tcp('observe-tcp','observe-tcp')
        time.sleep(35)
        stop_monitor('observation',observation_monitor)
        skill('primary-analyze','analyze','--session',str(session),allowed=(0,2))
        primary=a.load(session/'analysis.json')
        if primary['candidateRules']<1 or not primary['pendingTcp']:
            raise RuntimeError('Primary bounded observation did not capture MITM and TCP')
        def lds_metadata(label):
            import base64
            raw=kube(label,'get','secret',state['profile'],'-n',ns,'-o','json',sensitive=True)
            lds=base64.b64decode(json.loads(raw['stdout'])['data']['lds.yaml'])
            version=next(line.split(':',1)[1].strip().strip('"') for line in lds.decode().splitlines() if line.startswith('version_info:'))
            meta={'sha256':hashlib.sha256(lds).hexdigest(),'version':version,'readEndedAt':raw['endedAt']}
            a.write(records/(label+'-projection.json'),meta)
            return meta

        def active_version(label):
            query='exec 3<>/dev/tcp/127.0.0.1/15000; printf "GET /config_dump HTTP/1.1\\r\\nHost: localhost\\r\\nConnection: close\\r\\n\\r\\n" >&3; head -c 4194305 <&3'
            raw=kube(label,'exec','-n',ns,client,'-c','varmor-network-proxy','--','timeout','15',
                     'setpriv','--reuid=1337','--regid=1337','--clear-groups','bash','-c',query,sensitive=True,binary=True)['stdout']
            dump=admin_document(raw)
            versions=[x['active_state']['version_info'] for block in dump.get('configs',[])
                      if block.get('@type','').endswith('ListenersConfigDump') for x in block.get('dynamic_listeners',[])
                      if x.get('name')=='varmor_outbound' and x.get('active_state') and not x.get('error_state')]
            errors=[{'lastUpdateAttempt': x.get('error_state', {}).get('last_update_attempt'),
                     'failedVersion': x.get('error_state', {}).get('version_info')}
                    for block in dump.get('configs', []) if block.get('@type', '').endswith('ListenersConfigDump')
                    for x in block.get('dynamic_listeners', []) if x.get('name') == 'varmor_outbound' and x.get('error_state')]
            actual=[x['active_state']['version_info'] for block in dump.get('configs', [])
                    if block.get('@type', '').endswith('ListenersConfigDump')
                    for x in block.get('dynamic_listeners', []) if x.get('name') == 'varmor_outbound' and x.get('active_state')]
            a.write(records/(label+'-projection.json'),{'activeVersions': versions, 'actualActiveVersions': actual, 'updateErrors': errors,
                    'scope':'Load-wait diagnostic only; not an automatic MITM/TCP permission proof'})
            if len(versions)!=1:
                raise RuntimeError('Unique error-free outbound active version is required')
            a.write(records/(label+'-projection.json'),{'activeVersion':versions[0], 'actualActiveVersions': actual, 'updateErrors': errors,
                    'scope':'Load-wait diagnostic only; not an automatic MITM/TCP permission proof'})
            return versions[0]

        def mounted_metadata(label):
            raw=kube(label, 'exec', '-n', ns, client, '-c', 'varmor-network-proxy', '--',
                     'head', '-c', '4194305', '/etc/envoy/lds.yaml', sensitive=True, binary=True)['stdout']
            if len(raw)>4194304:
                raise RuntimeError('Mounted diagnostic exceeds evidence byte limit')
            version=next(line.split(':',1)[1].strip().strip('"') for line in raw.decode().splitlines()
                         if line.startswith('version_info:'))
            value={'version':version, 'sha256':hashlib.sha256(raw).hexdigest(), 'readEndedAt':a.now()}
            a.write(records/(label+'-projection.json'),value)
            return value

        def deploy(label, tcp_expected=False):
            kube(label+'-dry','apply','--dry-run=server','-f',str(session/'candidate.yaml'))
            prior=lds_metadata(label+'-lds-before')
            kube(label+'-apply','apply','-f',str(session/'candidate.yaml'))
            # Policy.ready/apply is not effective enforcement. Keep probes separate
            # from the saved acceptance window and require fresh denied traffic.
            for attempt in range(30):
                guard()
                current=lds_metadata(label+'-lds-'+str(attempt))
                if attempt % 5 == 0 or attempt == 29:
                    mounted=mounted_metadata(label+'-mounted-'+str(attempt))
                active='not-queried: direct permission proof is used' if cfg.get('automaticProof') else active_version(label+'-active-version-'+str(attempt))
                # Admin version metadata is diagnostic, not a permission oracle.
                # Require the current projection plus fresh protocol probes; the
                # separate formal checks still bind audit/client/backend evidence.
                if current['sha256']==prior['sha256'] or mounted['sha256']!=current['sha256']:
                    time.sleep(2)
                    continue
                if cfg.get('automaticProof'):
                    proof=skill(label+'-permission-'+str(attempt), 'active-config', '--session', str(session),
                        '--policy-file', str(session/'candidate.yaml'), '--pod-uid', uid,
                        '--output', str(out/(label+'-permission-'+str(attempt)+'.json')), allowed=(0,2))
                    if proof['exitCode'] != 0:
                        time.sleep(2)
                        continue
                probe=http(label+'-propagation-http-'+str(attempt),'/candidate-propagation-unlisted')
                if 'HTTP 403' in probe['stdout']:
                    if not tcp_expected or tcp_reply_confirmed(tcp(label+'-propagation-tcp-'+str(attempt),'propagation-tcp')):
                        return
                time.sleep(2)
            raise RuntimeError('Candidate propagation timeout: '+json.dumps({'phase':label,
                'apiVersion':current['version'],'activeVersion':active,'mounted':mounted,
                'readOnlyDiagnostics':str(records),'noEffectivePermissionClaim':True}))
        deploy('audited-http')
        common={'layer':'L7','destination':ip+':8443','authority':host+':8443','method':'GET'}
        denied_report=phase('audit-deny',[dict(common,id='mitm-allow',path='/read',expected='allow'),
              dict(common,id='mitm-deny',path='/read-neighbor',expected='deny',intentionalDeny=True),
              dict(common,id='mitm-method-deny',method='POST',path='/read',expected='deny',intentionalDeny=True),
              {'id':'tcp-deny','layer':'L4','destination':ip+':9090','expected':'deny','intentionalDeny':True}],
              [lambda:http('audit-deny-mitm-allow','/read'),lambda:http('audit-deny-mitm-deny','/read-neighbor'),
               lambda:http('audit-deny-mitm-method','/read','POST'),
               lambda:tcp('audit-deny-tcp-deny','tcp-deny',True)],0,refine_denials=True)
        decision=tcp_denial_decision(denied_report, ip)
        a.write(out/'tcp-approval.json',{'decisions':[decision]})
        skill('tcp-approve-denied','refine','--session',str(session),'--decisions',str(out/'tcp-approval.json'),
              '--verification',str(out/'audit-deny/verification/verification.json'))
        saved=a.load(session/'refinement.json')['decisions'][decision['id']]
        if saved['origin']!='DENIED' or saved['observedSuccess'] is not False:
            raise RuntimeError('DENIED approval must retain its non-success origin')
        result['deniedApproval']={'id':decision['id'],'origin':saved['origin'],
            'observedSuccess':saved['observedSuccess'],'verificationFile':saved['verificationFile']}
        deploy('audited-tcp',tcp_expected=True)
        allow_checks=[dict(common,id='mitm-allow-2',path='/read',expected='allow'),
                      {'id':'tcp-allow','layer':'L4','destination':ip+':9090','expected':'allow'},
                      {'id':'tcp-neighbor-deny','layer':'L4','destination':ip+':9091','expected':'deny','intentionalDeny':True}]
        phase('audit-allow',allow_checks,[lambda:http('audit-allow-mitm','/read'),lambda:tcp('audit-allow-tcp','tcp-allow'),
              lambda:tcp('audit-allow-tcp-neighbor','tcp-neighbor-deny',True,9091)],0)
        if cfg.get('automaticProof'):
            permissions=a.load(session/'analysis.json')['permissions']
            ids=[p['id'] for p in permissions]
            a.write(out/'quiet-approval.json', {'silentRuleIds': ids,
                'approvalEvidence': 'Authorized isolated maintainer acceptance of silent confirmed HTTP/TCP grants'})
            skill('quiet-refine','refine','--session',str(session),'--decisions',str(out/'quiet-approval.json'))
            deploy('quiet',tcp_expected=True)
            phase('quiet',[dict(common,id='mitm-quiet',path='/read',expected='allow'),
                  {'id':'tcp-quiet','layer':'L4','destination':ip+':9090','expected':'allow'}],
                  [lambda:http('quiet-mitm','/read'),lambda:tcp('quiet-tcp','tcp-quiet')],0)
            a.write(out/'revoke-approval.json', {'revokeRuleIds': ids, 'reason': 'Owned test withdrawal acceptance',
                'approvalEvidence': 'Authorized isolated maintainer withdrawal of both approved grants'})
            skill('revoke-refine','refine','--session',str(session),'--decisions',str(out/'revoke-approval.json'))
            deploy('revoked')
            phase('revoked',[dict(common,id='mitm-revoked',path='/read',expected='deny',intentionalDeny=True),
                  {'id':'tcp-revoked','layer':'L4','destination':ip+':9090','expected':'deny','intentionalDeny':True}],
                  [lambda:http('revoked-mitm','/read'),lambda:tcp('revoked-tcp','tcp-revoked',True)],0)
        result['status']='passed'
    except Exception as exc:
        result.update(status='failed',error=str(exc))
    finally:
        collector_cleanup = []
        for proc,collection,log in monitors:
            cleanup = {'collection': str(collection), 'processId': proc.pid}
            try:
                skill('cleanup-stop-'+collection.parent.name,'stop','--session',str(collection),allowed=(0,2))
                proc.wait(timeout=60)
            except Exception as exc:
                result['collectorCleanupError']=str(exc)
                cleanup['error'] = str(exc)
                if proc.poll() is None:
                    try:
                        proc.terminate()
                        try:
                            proc.wait(timeout=15)
                        except subprocess.TimeoutExpired:
                            if hasattr(os, 'killpg'):
                                os.killpg(proc.pid, signal.SIGKILL)
                            else:
                                proc.kill()
                            proc.wait(timeout=15)
                    except (OSError, subprocess.TimeoutExpired) as force_error:
                        cleanup['terminationError'] = str(force_error)
            finally:
                cleanup.update(alive=proc.poll() is None, exitCode=proc.poll())
                log.close()
                collector_cleanup.append(cleanup)
        result['collectorCleanup'] = collector_cleanup
        if created:
            try:
                if read('cleanup-ownership','namespace',ns)['metadata']['uid'] != owned_uid:
                    raise RuntimeError('Owned namespace UID changed; refuse cleanup')
                kube('namespace-delete','delete','namespace',ns,'--wait=false')
                kube('namespace-deleted','wait','--for=delete','namespace/'+ns,'--timeout=90s')
                absent=kube('namespace-absence','get','namespace',ns,'--ignore-not-found','-o','json')
                if absent['stdout'].strip():
                    raise RuntimeError('Owned namespace still exists after deletion')
                result['cleanup']='owned namespace absence confirmed'
            except Exception as exc:
                result['cleanupError']=str(exc)
        if result.get('collectorCleanupError') or any(x['alive'] for x in collector_cleanup) or result.get('cleanupError'):
            result.update(testStatus=result['status'], status='cleanup-incomplete')
        result.update(endedAt=a.now(),elapsedSeconds=round(time.monotonic()-started,3))
        a.write(out/'result.json',result)
        print(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['status']=='passed' else 2


def run(args):
    output = Path(args.output).resolve()
    cfg = {'root': str(output), 'installedSkill': str(Path(getattr(args, 'skill_dir', None) or Path(__file__).resolve().parents[1])),
           'context': args.context, 'image': args.image, 'runId': uuid.uuid4().hex[:8],
           'automaticProof': True,
           'maxSeconds': 1800, 'deadline': (dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=1800)).isoformat()}
    return main(cfg, output=str(output))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--context', required=True)
    p.add_argument('--output', required=True)
    p.add_argument('--image', required=True, help='User-approved curl image with BusyBox nc')
    p.add_argument('--skill-dir', help='Extracted distribution Skill directory; source default')
    sys.exit(run(p.parse_args()))
