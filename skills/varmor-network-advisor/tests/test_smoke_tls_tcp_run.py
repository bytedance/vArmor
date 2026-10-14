# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Maintainer safety boundaries before any owned resources are created."""
import contextlib
import importlib.util
import io
import http.client
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

s = importlib.util.spec_from_file_location('tls_runner', Path(__file__).with_name('smoke_tls_tcp_run.py'))
r = importlib.util.module_from_spec(s)
s.loader.exec_module(r)


class TLSRunnerBoundaries(unittest.TestCase):
    def test_denied_approval_requires_actual_unique_reviewable_exact_scope(self):
        item={'id':'a'*64,'origin':'DENIED','reviewable':True,'layer':'TCP',
            'rule':{'ip':'10.0.0.1','ports':[{'port':9090}]}}
        self.assertEqual(r.tcp_denial_decision({'denials':[item]},'10.0.0.1')['id'],item['id'])
        for report in ({'denials':[]},{'denials':[item,item]},
                {'denials':[{**item,'origin':'AUDIT'}]}, {'denials':[{**item,'reviewable':False}]}):
            with self.assertRaises(ValueError):r.tcp_denial_decision(report,'10.0.0.1')
        with self.assertRaises(ValueError):r.tcp_denial_decision({'denials':[item]},'10.0.0.2')

    def test_chunked_admin_requires_original_crlf_bytes(self):
        raw = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nE\r\n{"configs":[]}\r\n0\r\n\r\n'
        self.assertEqual(r.admin_document(raw), {'configs': []})
        with self.assertRaises(http.client.HTTPException):
            r.admin_document(raw.replace(b'\r\n', b'\n'))

    def test_truncated_or_oversized_admin_is_not_loaded_evidence(self):
        with self.assertRaises((http.client.HTTPException, ValueError)):
            r.admin_document(b'HTTP/1.1 200 OK\r\nContent-Length: 30\r\n\r\n{"configs":[]}')
        with self.assertRaises(ValueError):
            r.admin_document(b'x' * 4194305)

    def config(self, folder):
        return {'root': str(folder), 'installedSkill': str(Path(__file__).resolve().parents[1]),
            'context': 'unit-only', 'image': 'approved-user-image', 'runId': 'unit-owned',
            'maxSeconds': 1800, 'deadline': '2099-01-01T00:00:00Z'}

    def test_failed_preflight_cannot_create_cluster_resources(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'new'
            with patch.object(r.subprocess, 'run', return_value=SimpleNamespace(returncode=2, stdout='', stderr='preflight failed')) as run, \
                    patch.object(r.subprocess, 'Popen') as popen, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(r.main(self.config(out), str(out)), 2)
            self.assertEqual(run.call_count, 1)
            self.assertIn('doctor', run.call_args.args[0])
            popen.assert_not_called()
            result = json.loads((out / 'result.json').read_text())
            self.assertEqual(result['status'], 'failed')
            self.assertNotIn('cleanupError', result)

    def test_expired_deadline_stops_before_first_operation(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder) / 'new'; cfg = self.config(out); cfg['deadline'] = '2000-01-01T00:00:00Z'
            with patch.object(r.subprocess, 'run') as run, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(r.main(cfg, str(out)), 2)
            run.assert_not_called()
            self.assertIn('deadline exhausted', json.loads((out/'result.json').read_text())['error'])

    def test_old_output_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            out = Path(folder); marker = out / 'previous.json'; marker.write_text('{"keep": true}')
            with self.assertRaisesRegex(ValueError, 'new or empty'), patch.object(r.subprocess, 'run') as run:
                r.main(self.config(out), str(out))
            run.assert_not_called()
            self.assertEqual(marker.read_text(), '{"keep": true}')


if __name__ == '__main__':
    unittest.main()
