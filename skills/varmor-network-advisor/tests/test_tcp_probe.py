# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


PROBE = Path(__file__).resolve().parents[1] / 'scripts' / 'tcp_probe.sh'


class TCPProbeTests(unittest.TestCase):
    def run_probe(self, reply='', transport=0, args=None):
        with tempfile.TemporaryDirectory() as folder:
            busybox = Path(folder) / 'busybox'
            busybox.write_text('''#!/bin/sh
command=$1; shift
case "$command" in
    timeout) shift 3; exec "$@";;
    nc) printf '%s' "$FIXTURE_REPLY"; exit "$FIXTURE_TRANSPORT";;
    *) exec "$command" "$@";;
esac
''')
            busybox.chmod(0o755)
            env = dict(os.environ, PATH=folder + os.pathsep + os.environ['PATH'],
                       FIXTURE_REPLY=reply, FIXTURE_TRANSPORT=str(transport))
            return subprocess.run(['sh', str(PROBE), *(args or ['127.0.0.1', '9090', 'probe', 'tcp-ok', '1'])],
                                  capture_output=True, text=True, env=env, timeout=12)

    def test_exact_reply_is_business_success(self):
        result = self.run_probe('tcp-ok\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('probe_reply=matched', result.stdout)

    def test_empty_or_wrong_reply_is_failure_even_when_transport_exits_zero(self):
        for reply in ('', 'different\n', 'tcp-ok\nextra\n'):
            with self.subTest(reply=reply):
                result = self.run_probe(reply)
                self.assertEqual(result.returncode, 3)
                self.assertIn('probe_transport_exit=0', result.stdout)
                self.assertIn('probe_reply=missing_or_mismatch', result.stdout)

    def test_transport_error_does_not_pass_with_a_partial_matching_reply(self):
        result = self.run_probe('tcp-ok\n', 143)
        self.assertEqual(result.returncode, 4)
        self.assertIn('probe_transport_exit=143', result.stdout)

    def test_reply_limit_is_not_business_success(self):
        result = self.run_probe('x' * 5000)
        self.assertEqual(result.returncode, 5)
        self.assertLess(len(result.stdout), 4300)

    def test_invalid_or_multiline_input_is_rejected_before_network(self):
        for args in (['-v', '9090', 'probe', 'tcp-ok'],
                     ['127.0.0.1', '0', 'probe', 'tcp-ok'],
                     ['127.0.0.1', '9090', 'probe\nnext', 'tcp-ok'],
                     ['127.0.0.1', '9090', 'probe', 'tcp-ok', '31']):
            with self.subTest(args=args):
                result = self.run_probe(args=args)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
