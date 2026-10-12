# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ClusterContractTests(unittest.TestCase):
    def exercise(self, **environment):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        binary = base / 'kubectl'
        shutil.copyfile(ROOT / 'tests/fixtures/fake_kubectl.py', binary)
        binary.chmod(0o755)
        statefile = base / 'cluster.json'
        output = base / 'evidence'
        env = {**os.environ, 'PATH': str(base) + os.pathsep + os.environ['PATH'],
               'ADVISOR_FAKE_CLUSTER': str(statefile), 'ADVISOR_FAKE_SKILL_ROOT': str(ROOT), **environment}
        result = subprocess.run([sys.executable, str(ROOT / 'tests/smoke_cluster.py'), '--context', 'test-context',
               '--image', 'user-provided-test-image', '--output', str(output)], env=env, text=True, capture_output=True, timeout=30)
        self.assertTrue((output / 'result.json').exists(), result.stderr)
        return result, json.loads((output / 'result.json').read_text()), json.loads(statefile.read_text())

    def test_complete_smoke_orchestration_using_actual_subprocesses(self):
        result, report, state = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(report['status'], 'passed')
        self.assertEqual(report['analysis']['candidateRules'], 2)
        self.assertEqual(state['deletedNamespace'], state['namespace'])
        self.assertTrue(state['gateProbe'])
        self.assertEqual(len(report['deniedAuditControls']), 4)  # gate + three formal controls
        self.assertFalse(any(e['path'] == '/read-neighbor' for e in state['backend']))

    def test_bad_audit_stops_before_enforcement_and_cleans_up(self):
        result, report, state = self.exercise(ADVISOR_FAKE_BAD_AUDIT='1')
        self.assertEqual(result.returncode, 2)
        self.assertIn('audit', report['error'])
        self.assertFalse(state.get('enforcing'))
        self.assertEqual(state['deletedNamespace'], state['namespace'])

    def test_admission_rejection_does_not_apply_candidate(self):
        result, report, state = self.exercise(ADVISOR_FAKE_REJECT_CANDIDATE='1')
        self.assertEqual(result.returncode, 2)
        self.assertIn('admission', report['error'])
        self.assertFalse(state.get('enforcing'))
        self.assertEqual(state['deletedNamespace'], state['namespace'])

    def test_backend_evidence_detects_leak_despite_frontend_403(self):
        result, report, state = self.exercise(ADVISOR_FAKE_BACKEND_LEAK='1')
        self.assertEqual(result.returncode, 2)
        self.assertIn('reached the backend', report['error'])
        self.assertEqual(state['deletedNamespace'], state['namespace'])

    def test_cleanup_failure_is_actionable_instead_of_reported_as_success(self):
        result, report, state = self.exercise(ADVISOR_FAKE_FAIL_CLEANUP='1')
        self.assertEqual(result.returncode, 2)
        self.assertEqual(report['status'], 'cleanup-incomplete')
        self.assertEqual(report['testStatus'], 'passed')
        self.assertIn('cleanup failure', report['cleanupError'])
        self.assertNotIn('deletedNamespace', state)


if __name__ == '__main__':
    unittest.main()
