# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('smoke', Path(__file__).with_name('smoke_cluster.py'))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTests(unittest.TestCase):
    def test_unhealthy_cluster_cannot_create_or_mutate_resources(self):
        with tempfile.TemporaryDirectory() as root:
            args = argparse.Namespace(context='test', output=root, image='approved-curl')
            with patch.object(smoke.advisor, 'doctor', return_value=2), patch.object(smoke.advisor, 'kube') as call:
                self.assertEqual(smoke.run(args), 2)
                call.assert_not_called()
            report = json.loads((Path(root) / 'result.json').read_text())
            self.assertEqual(report['status'], 'blocked-or-failed')
            self.assertEqual(report['cleanup'], 'no cluster resources created')


if __name__ == '__main__':
    unittest.main()
