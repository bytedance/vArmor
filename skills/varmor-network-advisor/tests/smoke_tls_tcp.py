#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Maintainer TLS/TCP E2E using curl clients, a BusyBox backend and a TLS Envoy fixture."""
import argparse
import base64
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import uuid

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('smoke_cluster.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)
a = smoke.advisor

TCP_SERVER = r'''cat > /tmp/respondtcp <<'SH'
#!/bin/sh
IFS= read -r line
printf '%s\n' "$line" >> /tmp/tcp-hits
printf 'tcp-ok\n'
SH
chmod +x /tmp/respondtcp
touch /tmp/tcp-hits
exec busybox nc -lk -p 9090 -e /tmp/respondtcp
'''


def tls_config():
    return {'static_resources': {
        'listeners': [{'name': 'tls', 'address': {'socket_address': {'address': '0.0.0.0', 'port_value': 8443}},
            'filter_chains': [{'transport_socket': {'name': 'envoy.transport_sockets.tls', 'typed_config': {
                '@type': 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext',
                'common_tls_context': {'alpn_protocols': ['http/1.1'], 'tls_certificates': [{
                    'certificate_chain': {'filename': '/fixture/tls.crt'}, 'private_key': {'filename': '/fixture/tls.key'}}]}}},
                'filters': [{'name': 'envoy.filters.network.http_connection_manager', 'typed_config': {
                    '@type': 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                    'stat_prefix': 'fixture', 'route_config': {'name': 'local', 'virtual_hosts': [{'name': 'all',
                        'domains': ['*'], 'routes': [{'match': {'prefix': '/'}, 'route': {'cluster': 'backend'}}]}]},
                    'http_filters': [{'name': 'envoy.filters.http.router', 'typed_config': {
                        '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'}}]}}]}]}],
        'clusters': [{'name': 'backend', 'type': 'STATIC', 'connect_timeout': '2s',
            'load_assignment': {'cluster_name': 'backend', 'endpoints': [{'lb_endpoints': [{'endpoint': {
                'address': {'socket_address': {'address': '127.0.0.1', 'port_value': 8080}}}}]}]}}]}}


def fixture_certificate(context, namespace, profile, names):
    # Only the CA of THIS test's freshly-created policy is read. Never print or persist its key as evidence.
    secret = a.get(context, 'secret', namespace, profile)['data']
    with tempfile.TemporaryDirectory(prefix='np-advisor-cert-') as folder:
        root = Path(folder)
        os.chmod(root, 0o700)
        for filename in ('mitm-ca.crt', 'mitm-ca.key'):
            p = root / filename
            p.write_bytes(base64.b64decode(secret[filename]))
            p.chmod(0o600)
        ext = root / 'ext.cnf'
        ext.write_text('subjectAltName=' + ','.join('DNS:' + n for n in names) + '\n')
        def openssl(*args):
            result = subprocess.run(['openssl', *args], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise RuntimeError('Fixture certificate generation failed: ' + result.stderr)
        openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=' + names[0],
                '-keyout', str(root/'key.pem'), '-out', str(root/'request.pem'))
        openssl('x509', '-req', '-in', str(root/'request.pem'), '-CA', str(root/'mitm-ca.crt'),
                '-CAkey', str(root/'mitm-ca.key'), '-set_serial', '1', '-days', '1', '-extfile', str(ext),
                '-out', str(root/'cert.pem'))
        return {'tls.crt': base64.b64encode((root/'cert.pem').read_bytes()).decode(),
                'tls.key': base64.b64encode((root/'key.pem').read_bytes()).decode()}


def run(args):
    output = Path(args.output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    namespace = 'np-advisor-tls-' + uuid.uuid4().hex[:8]
    report = {'at': a.now(), 'context': args.context, 'namespace': namespace, 'status': 'running',
              'scope': 'owned-mitm-sni-tcp', 'image': args.image,
              'limitations': ['Fixture upstream is signed with this temporary policy CA; public-PKI providers, '
                              'certificate pinning, mTLS, UDP, IPv6 and micro-VM are not tested.']}
    created = False
    try:
        if a.doctor(argparse.Namespace(context=args.context, output=str(output/'preflight.json'))):
            raise RuntimeError('Cluster preflight failed')
        if (output/'session').exists():
            raise ValueError('use a fresh output directory')
        a.kube(args.context, 'create', 'namespace', namespace)
        created = True
        session = output/'session'
        mitm = 'mitm.' + namespace + '.test'
        sni = 'sni.' + namespace + '.test'
        a.observe(a.parser().parse_args(['observe', '--session', str(session), '--context', args.context,
            '--namespace', namespace, '--name', 'observe-client', '--workload', 'client',
            '--observe', 'both', '--mitm-domain', mitm]))
        a.kube(args.context, 'apply', '--dry-run=server', '-f', str(session/'observe.yaml'))
        a.kube(args.context, 'apply', '-f', str(session/'observe.yaml'))
        a.kube(args.context, 'wait', '-n', namespace, '--for=condition=Ready',
               'varmorpolicy/observe-client', '--timeout=60s')
        state = a.load(session/'session.json')
        # TLS fixture uses the deployed proxy image, independent of the curl application image.
        managers = a.get(args.context, 'deployments', 'varmor')['items']
        proxy_image = args.proxy_image or next(e['value'] for d in managers
            for c in d['spec']['template']['spec']['containers'] for e in c.get('env', []) if e['name']=='PROXY_IMAGE')
        report['fixtureProxyImage'] = proxy_image
        cert = fixture_certificate(args.context, namespace, state['profile'], [mitm, sni, 'unknown.'+namespace+'.test'])
        a.kube(args.context, 'create', '-f', '-', data=json.dumps({'apiVersion':'v1','kind':'Secret',
            'metadata':{'name':'backend-tls','namespace':namespace}, 'data':cert}))
        a.kube(args.context, 'create', '-f', '-', data=json.dumps({'apiVersion':'v1','kind':'ConfigMap',
            'metadata':{'name':'backend-config','namespace':namespace}, 'data':{'envoy.json':json.dumps(tls_config())}}))
        backend = smoke.workload(namespace, 'backend', args.image, ['sh','-c',smoke.SERVER])
        bs = backend['spec']['template']['spec']
        bs['volumes'] = [{'name':'cert','secret':{'secretName':'backend-tls'}},
                         {'name':'config','configMap':{'name':'backend-config'}}]
        bs['containers'] += [{'name':'tls','image':proxy_image,'command':['envoy','-c','/fixture-config/envoy.json'],
            'volumeMounts':[{'name':'cert','mountPath':'/fixture','readOnly':True},
                            {'name':'config','mountPath':'/fixture-config','readOnly':True}]},
            {'name':'tcp','image':args.image,'command':['sh','-c',
              TCP_SERVER]}]
        svc = {'apiVersion':'v1','kind':'Service','metadata':{'name':'backend','namespace':namespace},
            'spec':{'selector':{'app':'backend'}, 'ports':[{'name':'tls','port':8443,'targetPort':8443},
                                                       {'name':'tcp','port':9090,'targetPort':9090}]}}
        client = smoke.workload(namespace,'client',args.image,['sleep','3600'])
        a.write(output/'workloads.yaml',{'apiVersion':'v1','kind':'List','items':[backend,svc,client]})
        a.kube(args.context,'apply','-f',str(output/'workloads.yaml'))
        for name in ('backend','client'):
            a.kube(args.context,'rollout','status','-n',namespace,'deploy/'+name,'--timeout=60s')
        pods,_ = a.live_inventory(state,a.load(session/'observe.yaml'))
        pod = pods[0]['metadata']['name']
        ip = a.get(args.context,'service',namespace,'backend')['spec']['clusterIP']
        report.update({'backendIP':ip, 'mitmHost':mitm, 'sniHost':sni,'clientPodUID':pods[0]['metadata']['uid']})
        def request(host, method='GET', path='/read'):
            # curl automatically uses the injected CURL_CA_BUNDLE; never disable certificate validation.
            cmd = ['curl','--noproxy','*','-sS','--max-time','8','--resolve',host+':8443:'+ip,
                   '-X',method,'-w','\n%{http_code}','https://'+host+':8443'+path]
            try:
                raw=a.kube(args.context,'exec','-n',namespace,pod,'-c','app','--',*cmd)
                body,code=raw.rstrip('\n').rsplit('\n',1)
                return {'status':int(code),'body':body}
            except RuntimeError as exc:
                return {'status':0,'error':str(exc)}
        def tcp(payload):
            return a.kube(args.context,'exec','-n',namespace,pod,'-c','app','--','sh','-c',
                          '{ printf "%s\\n" "$1"; sleep 3; } | busybox nc -w 8 "$2" 9090','test',payload,ip)
        obs=[request(mitm),request(mitm,'POST','/write'),request(mitm,path='/api/objects/1'),request(sni,'GET','/read')]
        if any(r['status']!=200 for r in obs):
            raise RuntimeError('TLS observation failed: '+json.dumps(obs))
        if 'tcp-ok' not in tcp('observe-tcp'):
            raise RuntimeError('TCP backend observation failed: '+a.kube(args.context,'exec','-n',namespace,'deploy/backend','-c','tcp','--','cat','/tmp/tcp-hits'))
        report['observationRequests']=obs
        collect=a.parser().parse_args(['collect','--session',str(session)])
        for _ in range(8):
            if a.collect(collect): raise RuntimeError('Audit collection failed')
            a.analyze(a.parser().parse_args(['analyze','--session',str(session)]))
            analysis=a.load(session/'analysis.json')
            if analysis['candidateRules']==4 and analysis['pendingTcp']: break
            time.sleep(2)
        else: raise RuntimeError('Missing MITM, SNI or pending TCP evidence')
        report['initialAnalysis']=analysis
        def apply_candidate():
            a.kube(args.context,'apply','--dry-run=server','-f',str(session/'candidate.yaml'))
            a.kube(args.context,'apply','-f',str(session/'candidate.yaml'))
            for _ in range(35):
                if request(mitm,path='/probe-unlisted')['status']==403: return
                time.sleep(2)
            raise RuntimeError('Enforcement config propagation timeout')
        apply_candidate()
        results={'mitmRead':request(mitm), 'mitmWrite':request(mitm,'POST','/write'),
            'wrongMethod':request(mitm,'POST','/read'),'neighbor':request(mitm,path='/read-neighbor'),
            'sniRead':request(sni), 'sniOtherPath':request(sni,path='/all-other-paths'),
            'unknownSni':request('unknown.'+namespace+'.test')}
        report['enforcementRequests']=results
        for key in ('mitmRead','mitmWrite','sniRead','sniOtherPath'):
            if results[key]['status']!=200: raise RuntimeError('Positive TLS control failed: '+key)
        for key in ('wrongMethod','neighbor'):
            if results[key]['status']!=403: raise RuntimeError('MITM denial failed: '+key)
        if results['unknownSni']['status']!=0: raise RuntimeError('Unknown SNI reached backend')
        with contextlib.suppress(RuntimeError):
            if 'tcp-ok' in tcp('denied-tcp'): raise ValueError('Unreviewed TCP reached backend')
        # Approve TCP with saved review, then widen HTTPS path to a depth-1 subtree on existing observations.
        review={'approvedTcp':[ip+':9090'],'domains':{mitm:{'path':'prefix','depth':1,'methods':True}}}
        a.write(session/'user-review.json',review)
        a.analyze(a.parser().parse_args(['analyze','--session',str(session),'--review',str(session/'user-review.json')]))
        a.kube(args.context,'apply','-f',str(session/'candidate.yaml'))
        for _ in range(35):
            try:
                if 'tcp-ok' in tcp('approved-tcp'): break
            except RuntimeError: pass
            time.sleep(2)
        else: raise RuntimeError('Approved TCP not allowed')
        report['approvedTcp']='passed'
        prefix={'subtree':request(mitm,path='/api/objects/2'),
                'neighbor':request(mitm,path='/apix/objects/2'),
                'wrongMethod':request(mitm,'POST','/api/objects/2')}
        if [prefix[k]['status'] for k in ('subtree','neighbor','wrongMethod')]!=[200,403,403]:
            raise RuntimeError('Path prefix boundary or method failed: '+json.dumps(prefix))
        report['prefixRequests']=prefix
        hits=a.kube(args.context,'exec','-n',namespace,'deploy/backend','-c','app','--','cat','/tmp/hits.tsv')
        (output/'backend.log').write_text(hits)
        if any('\t/read-neighbor\t' in l or l.startswith('POST\t/read\t') or '\t/apix/objects/2\t' in l or l.startswith('POST\t/api/objects/2\t') or 'unknown.' in l for l in hits.splitlines()):
            raise RuntimeError('Denied TLS control reached backend')
        tcp_hits=a.kube(args.context,'exec','-n',namespace,'deploy/backend','-c','tcp','--','cat','/tmp/tcp-hits')
        (output/'tcp-backend.log').write_text(tcp_hits)
        if 'denied-tcp' in tcp_hits: raise RuntimeError('Denied TCP reached backend')
        needed={(mitm+':8443','POST','/read'),(mitm+':8443','GET','/read-neighbor'),
                (mitm+':8443','GET','/apix/objects/2'),(mitm+':8443','POST','/api/objects/2')}
        audits=[]
        for _ in range(8):
            audits=[]
            for _,raw in a.sources(state,collect,pods):
                for line in raw.splitlines():
                    r=json.loads(line)
                    if r.get('podUID')==report['clientPodUID'] and r.get('profileName')==state['profile']:
                        audits.append(r)
            found={(r['event'].get('authority'),r['event'].get('method'),r['event'].get('path'))
                   for r in audits if r['action']=='DENIED'}
            tcp_deny=any(r['action']=='DENIED' and r['event'].get('dstAddress')==ip+':9090' for r in audits)
            sni_deny=any(r['action']=='DENIED' and r['event'].get('sni')=='unknown.'+namespace+'.test' for r in audits)
            if needed<=found and tcp_deny and sni_deny: break
            time.sleep(2)
        else: raise RuntimeError('Missing DENIED MITM/TCP/SNI audit controls')
        a.write(output/'normalized-audits.json',audits)
        report['auditControls']='MITM, TCP and SNI denial confirmed'
        report['status']='passed'
        return 0
    except (RuntimeError,ValueError,OSError,KeyError,StopIteration,subprocess.TimeoutExpired) as exc:
        report.update({'status':'failed','error':str(exc)})
        if created and 'state' in locals():
            try:
                config=a.get(args.context,'secret',namespace,state['profile'])['data']
                (output/'diagnostic-lds.yaml').write_bytes(base64.b64decode(config['lds.yaml']))
                (output/'tcp-backend.log').write_text(a.kube(args.context,'exec','-n',namespace,
                    'deploy/backend','-c','tcp','--','cat','/tmp/tcp-hits'))
            except Exception as diagnostic:
                report['diagnosticError']=str(diagnostic)
        return 2
    finally:
        cleanup_failed=False
        if created and not args.keep:
            try:
                a.kube(args.context,'delete','namespace',namespace,'--wait=false')
                a.kube(args.context,'wait','--for=delete','namespace/'+namespace,'--timeout=60s')
                report['cleanup']='owned namespace deletion confirmed'
            except Exception as exc:
                report.update({'cleanupError':str(exc),'testStatus':report['status'],'status':'cleanup-incomplete'})
                cleanup_failed=True
        elif created:
            report['cleanup']='retained by --keep; delete only this owned namespace after inspection'
        a.write(output/'result.json',report)
        print(json.dumps(report,ensure_ascii=False,indent=2))
        if cleanup_failed: return 2


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--context',required=True)
    p.add_argument('--output',required=True)
    p.add_argument('--image', required=True, help='approved curl image with sh, cat and BusyBox nc')
    p.add_argument('--proxy-image',help='TLS fixture Envoy; otherwise discover deployed PROXY_IMAGE')
    p.add_argument('--keep',action='store_true',help='retain owned namespace for diagnosis; requires later cleanup')
    sys.exit(run(p.parse_args()))
