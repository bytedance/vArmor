# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Independent installed-package MITM/TCP receipt boundary regression."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest


class CompatibilityReceiptBoundaries(unittest.TestCase):
    def setUp(self):
        path=Path(os.environ.get('COMPAT_INSTALLED_SKILL',str(Path(__file__).resolve().parents[1])))/'scripts/advisor.py'
        spec=importlib.util.spec_from_file_location('compat_installed_advisor',path)
        self.a=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.a)
        self.e=self.a.evidence_module()
        verification_spec=importlib.util.spec_from_file_location('compat_installed_verification',path.with_name('verification.py'))
        self.v=importlib.util.module_from_spec(verification_spec)
        verification_spec.loader.exec_module(self.v)
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.since='2026-10-13T10:00:00Z'
        self.until='2026-10-13T10:01:00Z'
        self.uid='owned-client-uid'
        self.p={'kind':'VarmorPolicy','metadata':{'name':'compat','namespace':'owned'},'spec':{
            'target':{'kind':'Deployment','name':'client'},'updateExistingWorkloads':False,'policy':{
                'mode':'EnhanceProtect','enforcer':'NetworkProxy','networkProxyConfig':{'mitm':{'domains':['mitm.owned.test']}},
                'enhanceProtect':{'networkProxyRawRules':{'egress':{'defaultAction':'deny','httpRules':[
                    {'qualifiers':['allow','audit'],'match':{'hosts':['mitm.owned.test'],'ports':[{'port':8443}],
                    'methods':['GET'],'paths':[{'exact':'/read'}]}}]}}}}}}
        self.check={'id':'mitm-read','layer':'L7','destination':'10.0.0.8:8443','authority':'mitm.owned.test:8443',
                    'method':'GET','path':'/read','expected':'allow'}

    def source(self,role,stdout,contains):
        receipt={'kind':'NetworkProxyCommandReceipt','checkId':self.check['id'],'podUID':self.uid,
                 'startedAt':'2026-10-13T10:00:01Z' if role=='client' else '2026-10-13T10:01:01Z',
                 'endedAt':'2026-10-13T10:00:02Z' if role=='client' else '2026-10-13T10:01:02Z',
                 'exitCode':0,'stdout':stdout}
        path=self.root/(role+'.json')
        path.write_text(json.dumps(receipt))
        return {'file':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),
                'exitCode':0,'stdoutContains':contains}

    def evaluate(self,client='HTTP 200 GET /read',predicate=None):
        pinned={'uid':'owned-policy-uid','generation':2,'specHash':self.e.digest(self.p['spec'])}
        item={'id':self.check['id'],'podUID':self.uid,'client':self.source('client',client,predicate or ['HTTP 200']),
              'backend':self.source('backend','GET /read mitm.owned.test:8443',['GET /read'])}
        bundle={'kind':'NetworkProxyCheckReceipts','candidateHash':self.e.digest(self.p),'policy':pinned,
                'podUIDs':[self.uid],'since':self.since,'until':self.until,'checks':[item]}
        return self.e.evaluate_bundle(bundle,[self.check],self.p,pinned,[self.uid],self.since,self.until,vars(self.a))

    def results(self,receipts,action='AUDIT'):
        event={'layer':self.check['layer'],'dstAddress':self.check['destination']}
        if self.check['layer']=='L7':
            event.update({k:self.check[k] for k in ('authority','method','path')})
            event.update(responseCode=200,reason='via_upstream')
        else:
            event.update(reason='-')
        return self.v.check_results([self.check],[{'action':action,'podUID':self.uid,'event':event}],
            vars(self.a),self.p,{'context':'test','namespace':'owned'},True,receipts)[0]

    def tcp(self):
        self.p['spec']['policy'].pop('networkProxyConfig', None)
        self.p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']={
            'defaultAction':'deny','rules':[{'qualifiers':['allow','audit'],'ip':'10.0.0.8','ports':[{'port':9090}]}]}
        self.check={'id':'tcp-read','layer':'L4','destination':'10.0.0.8:9090','expected':'allow'}

    def test_audited_mitm_receipts_and_audit_confirm_without_automatic_config(self):
        result=self.results(self.evaluate())
        self.assertEqual(result['result'],'confirmed')
        self.assertIsNone(result['receiptChecks']['configurationConfirmed'])

    def test_mitm_quiet_success_remains_insufficient(self):
        self.p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['httpRules'][0]['qualifiers']=['allow']
        result=self.v.check_results([self.check],[],vars(self.a),self.p,{},True,self.evaluate())[0]
        self.assertEqual(result['result'],'insufficient')
        self.assertIn('quiet-read/configuration',result['missing'])

    def test_raw_tcp_audit_and_actual_protocol_output_confirm(self):
        self.tcp()
        self.assertEqual(self.results(self.evaluate('tcp-ok',['tcp-ok']))['result'],'confirmed')

    def test_raw_tcp_quiet_success_remains_insufficient(self):
        self.tcp()
        self.p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['rules'][0]['qualifiers']=['allow']
        result=self.v.check_results([self.check],[],vars(self.a),self.p,{},True,self.evaluate('tcp-ok',['tcp-ok']))[0]
        self.assertEqual(result['result'],'insufficient')

    def test_client_conflict_is_not_hidden_by_matching_audit(self):
        self.assertEqual(self.results(self.evaluate('HTTP 503 upstream failure'))['result'],'contradicted')

    def test_true_assertions_and_unsupported_scope_do_not_confirm(self):
        self.check.update(clientConfirmed=True,backendConfirmed=True,configurationConfirmed=True)
        self.assertEqual(self.results({})['result'],'insufficient')
        plain = copy.deepcopy(self.p)
        plain['spec']['policy'].pop('networkProxyConfig', None)
        self.assertTrue(self.e.supported_rules(plain, vars(self.a)))
        self.assertTrue(self.e.supported_rules(self.p, vars(self.a)))
        self.p['spec']['policy']['networkProxyConfig']['mitm']['headerMutations'] = [{'domain': 'mitm.owned.test'}]
        with self.assertRaisesRegex(ValueError, 'header mutations'):
            self.e.supported_rules(self.p, vars(self.a))
        self.tcp()
        self.assertEqual(self.e.supported_rules(self.p, vars(self.a)), [])
        rule = self.p['spec']['policy']['enhanceProtect']['networkProxyRawRules']['egress']['rules'][0]
        rule['cidr'] = '10.0.0.0/8'
        with self.assertRaisesRegex(ValueError, 'CIDRs'):
            self.e.supported_rules(self.p, vars(self.a))


if __name__=='__main__':
    unittest.main()
