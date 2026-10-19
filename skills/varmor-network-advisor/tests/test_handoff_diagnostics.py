# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import contextlib
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from test_advisor import advisor as a
import test_collector as monitor_fixtures

c = a.collector_module()


class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.leases = [self.root / '.collector.lock', self.root / '.workflow-collector.lock']
        for path in self.leases:
            path.mkdir()
        current = dt.datetime.now(dt.timezone.utc)
        self.progress = {'phase': 'observing', 'processId': os.getpid(), 'startedAt': current.isoformat(),
                         'readyAt': current.isoformat(), 'lastHeartbeatAt': current.isoformat(),
                         'plan': {'until': (current + dt.timedelta(minutes=10)).isoformat(),
                                  'maxRoundSeconds': 30, 'intervalSeconds': 30, 'discoveryIntervalSeconds': 5}}
        a.write(self.root / 'collector.json', self.progress)
        a.write(self.root / 'session.json', {})

    def check(self, reserve=None):
        with contextlib.ExitStack() as stack:
            for path in self.leases:
                stack.enter_context(a.locked(path))
            return c.handoff_status(self.root, vars(a), reserve)

    def test_live_check_is_local_read_only_and_does_not_change_deadline(self):
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(a, 'kube', side_effect=AssertionError('Must not access cluster')):
            receipt = self.check()
        self.assertTrue(receipt['readyForHandoff'])
        self.assertEqual(receipt['minimumRemainingSeconds'], 60)
        self.assertEqual(before, {p: p.read_bytes() for p in before})

    def test_alive_reused_pid_without_leases_is_not_ready(self):
        for path in self.leases:
            with a.locked(path):
                pass
        result = c.handoff_status(self.root, vars(a))
        self.assertTrue(result['processAlive'])
        self.assertFalse(result['readyForHandoff'])
        self.assertIn('collector-lease-not-held', result['reasons'])

    def test_continued_budget_checks_actual_owner_lease(self):
        owner = self.root / 'prior-budget'
        owner.mkdir()
        shared = owner / '.workflow-collector.lock'
        shared.mkdir()
        a.write(self.root / 'session.json', {'budgetSession': str(owner)})
        with a.locked(self.root / '.collector.lock'), a.locked(shared):
            self.assertTrue(c.handoff_status(self.root, vars(a))['readyForHandoff'])
        with a.locked(self.root / '.collector.lock'), a.locked(self.root / '.workflow-collector.lock'):
            self.assertFalse(c.handoff_status(self.root, vars(a))['readyForHandoff'])

    def test_stale_heartbeat_expired_and_short_windows(self):
        current = dt.datetime.now(dt.timezone.utc)
        for changes, reason in [({'lastHeartbeatAt': (current-dt.timedelta(seconds=60)).isoformat()}, 'heartbeat-not-current'),
                                ({'plan': {**self.progress['plan'], 'until': (current-dt.timedelta(seconds=1)).isoformat()}}, 'deadline-passed'),
                                ({'plan': {**self.progress['plan'], 'until': (current+dt.timedelta(seconds=10)).isoformat()}}, 'insufficient-handoff-time'),
                                ({'phase': 'stopped'}, 'collector-not-active'),
                                ({'readyAt': None}, 'collector-not-active'),
                                ({'lastHeartbeatAt': 'invalid'}, 'invalid-clock-state'),
                                ({'plan': {**self.progress['plan'], 'intervalSeconds': float('nan')}}, 'invalid-clock-state')]:
            with self.subTest(reason=reason, changes=changes):
                a.write(self.root / 'collector.json', {**self.progress, **changes})
                result = self.check()
                self.assertFalse(result['readyForHandoff'])
                self.assertIn(reason, result['reasons'])

    def test_short_prepared_override_and_stop_request(self):
        self.progress['plan']['until'] = (dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=10)).isoformat()
        a.write(self.root / 'collector.json', self.progress)
        self.assertTrue(self.check(0)['readyForHandoff'])
        a.write(self.root / 'stop-request.json', {})
        self.assertIn('stop-requested', self.check(0)['reasons'])
        for invalid in (-1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                self.check(invalid)

    def test_dead_process_stale_file_is_rejected_by_real_cli(self):
        child = subprocess.Popen([__import__('sys').executable, '-c', 'pass'])
        child.wait(timeout=5)
        self.progress['processId'] = child.pid
        a.write(self.root / 'collector.json', self.progress)
        completed = subprocess.run([__import__('sys').executable, str(Path(a.__file__)), 'ready-check',
                                    '--session', str(self.root)], capture_output=True, text=True, timeout=5)
        self.assertEqual(completed.returncode, 2)
        self.assertIn('process-not-confirmed-alive', json.loads(completed.stdout)['reasons'])

    def test_changed_state_and_permission_failure_fail_closed(self):
        original = a.load
        reads = 0
        def load(path):
            nonlocal reads
            result = original(path)
            if Path(path).name == 'collector.json':
                reads += 1
                if reads == 2:
                    result['phase'] = 'stopped'
            return result
        with patch.object(a, 'load', load), patch.object(c.os, 'kill', side_effect=PermissionError()):
            result = self.check()
        self.assertFalse(result['readyForHandoff'])
        self.assertIn('collector-state-changed', result['reasons'])
        self.assertIn('process-not-confirmed-alive', result['reasons'])


    def test_concurrent_deadline_or_stop_rejects_handoff(self):
        original = a.load
        for mode, reason in [('deadline', 'collector-state-changed'), ('stop', 'stop-requested')]:
            with self.subTest(mode=mode):
                reads = 0
                def load(path):
                    nonlocal reads
                    result = original(path)
                    if Path(path).name == 'collector.json':
                        reads += 1
                        if reads == 2:
                            if mode == 'deadline':
                                result['plan']['until'] = dt.datetime.now(dt.timezone.utc).isoformat()
                            else:
                                a.write(self.root / 'stop-request.json', {})
                    return result
                with patch.object(a, 'load', load):
                    receipt = self.check()
                self.assertFalse(receipt['readyForHandoff'])
                self.assertIn(reason, receipt['reasons'])


class WindowsLivenessTests(unittest.TestCase):
    def test_query_only_handle_never_calls_kill_and_always_closes(self):
        import ctypes
        from unittest.mock import Mock
        kernel = Mock()
        kernel.OpenProcess.return_value = 999
        def exit_code(handle, pointer):
            pointer._obj.value = 259
            return 1
        kernel.GetExitCodeProcess.side_effect = exit_code
        with patch.object(c.os, 'name', 'nt'), patch.object(ctypes, 'WinDLL', return_value=kernel, create=True), \
             patch.object(c.os, 'kill', side_effect=AssertionError('Must never kill on Windows')):
            self.assertTrue(c.process_alive(1234))
            kernel.OpenProcess.assert_called_once_with(0x1000, False, 1234)
            kernel.CloseHandle.assert_called_once_with(999)
            kernel.OpenProcess.return_value = None
            self.assertFalse(c.process_alive(1234))
            self.assertFalse(c.process_alive(True))


    def test_exited_or_unqueryable_windows_process_is_not_ready(self):
        import ctypes
        from unittest.mock import Mock
        kernel = Mock()
        kernel.OpenProcess.return_value = 999
        def exit_code(handle, pointer):
            pointer._obj.value = 0
            return 1
        kernel.GetExitCodeProcess.side_effect = exit_code
        with patch.object(c.os, 'name', 'nt'), patch.object(ctypes, 'WinDLL', return_value=kernel, create=True):
            self.assertFalse(c.process_alive(1234))
            kernel.GetExitCodeProcess.side_effect = None
            kernel.GetExitCodeProcess.return_value = 0
            self.assertFalse(c.process_alive(1234))
            self.assertEqual(kernel.CloseHandle.call_count, 2)


class TimeoutTests(unittest.TestCase):
    def test_safe_original_diagnostic_omits_credentials_and_remote_data(self):
        secret = 'SECRET_CANARY_DO_NOT_PERSIST'
        failure = subprocess.TimeoutExpired(['kubectl', secret], 20, output=secret, stderr=secret)
        with patch.object(a, 'KUBE_DEADLINE', time.monotonic()+5), patch.object(a.subprocess, 'run', side_effect=failure):
            with self.assertRaises(a.KubeTimeoutError) as caught:
                a.kube(secret, 'exec', 'agent', '-n', 'scope', '-c', 'agent', '--', 'sh', '-c', secret, data=secret)
        details = c.failure_details(caught.exception, 'audit-source-read')
        self.assertNotIn(secret, json.dumps(details))
        self.assertEqual(details['errorDetails']['command'], ['kubectl', 'exec', '-n', 'scope', '-c', 'agent', '--', '[remote command omitted]'])
        self.assertEqual(details['errorDetails']['exceptionType'], 'TimeoutExpired')
        self.assertGreater(details['errorDetails']['timeoutSeconds'], 0)
        self.assertLessEqual(details['errorDetails']['timeoutSeconds'], 5)

    def test_elapsed_deadline_does_not_dispatch(self):
        with patch.object(a, 'KUBE_DEADLINE', time.monotonic()-1), patch.object(a.subprocess, 'run') as call:
            with self.assertRaises(a.KubeDeadlineError) as caught:
                a.kube('context', 'get', 'pods', '-n', 'scope')
        call.assert_not_called()
        self.assertEqual(caught.exception.diagnostic['kind'], 'deadline-before-dispatch')

    def test_plain_native_timeout_does_not_persist_raw_command_or_output(self):
        details = c.failure_details(subprocess.TimeoutExpired(['PRIVATE_COMMAND'], 3, output='PRIVATE_OUTPUT'), 'pod-inventory')
        self.assertNotIn('PRIVATE', json.dumps(details))
        self.assertEqual(details['errorDetails'], {'stage': 'pod-inventory', 'exceptionType': 'TimeoutExpired', 'timeoutSeconds': 3})

    def test_monitor_preserves_timeout_stage_and_health_issue(self):
        harness = monitor_fixtures.MonitorTests('test_bounded_handoff_excludes_old_pod_and_captures_deleted_new_pod')
        harness.setUp()
        try:
            harness.arguments.duration = 5
            harness.handoff_action = lambda: None
            original = a.live_inventory
            def inventory(*args, **kwargs):
                if (harness.root / 'collector.json').exists() and a.load(harness.root / 'collector.json').get('phase') in ('ready', 'observing'):
                    raise a.KubeTimeoutError({'command': ['kubectl', 'get', 'pods', '-n', 'demo'],
                                             'timeoutSeconds': 2, 'deadlineBounded': True,
                                             'deadlineRemainingSeconds': 2, 'kind': 'subprocess-timeout',
                                             'exceptionType': 'TimeoutExpired'})
                return original(*args, **kwargs)
            with patch.object(a, 'live_inventory', inventory):
                self.assertEqual(harness.run_monitor(), 2)
            result = a.load(harness.root / 'collector.json')
            self.assertEqual(result['stopReason'], 'failure')
            self.assertEqual(result['errorDetails']['stage'], 'pod-inventory')
            self.assertEqual(result['errorDetails']['exceptionType'], 'TimeoutExpired')
            self.assertIn('errorDetails', json.dumps(result['collectionHealth']))
        finally:
            harness.doCleanups()


if __name__ == '__main__':
    unittest.main()
