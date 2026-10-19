# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import json
from pathlib import Path
import tempfile
import unittest

from test_advisor import advisor as a


class PolicyYAMLTests(unittest.TestCase):
    def test_generated_policies_round_trip_with_legacy_json(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            args = a.parser().parse_args(['observe', '--session', str(root), '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--language', 'zh-CN'])
            a.observe(args)
            text = (root/'observe.yaml').read_text()
            self.assertTrue(text.startswith('apiVersion: '))
            obj = a.load(root/'observe.yaml')
            self.assertIs(obj['spec']['updateExistingWorkloads'], False)
            legacy = root/'legacy.yaml'; legacy.write_text(json.dumps(obj))
            self.assertEqual(a.load(legacy), obj)
            self.assertEqual(a.refinement_module().fingerprint(a.load(legacy)),
                             a.refinement_module().fingerprint(a.load(root/'observe.yaml')))
            self.assertTrue((root/'session.json').read_text().startswith('{'))

    def test_scalars_and_string_keys_retain_types_and_content(self):
        obj = {'label': 'true', 'true': 'off', 'yes': 'null', 'port': 8080, 'enabled': False,
               'nullValue': None, 'stringNumber': '0123', 'date': '2026-10-12', 'small': 1e-6,
               'large': 1e20, '中文': '中文报告', 'odd': '\\"\n\t\r\u0085\u2028\u2029',
               'list': [[], {}, ['GET', '/v1/a?key=x:y#z'], 0, -1, True],
               '<<': '&anchor', 'colon:key': '*alias', 'empty': ''}
        y = a.yaml_module(); text = y.dumps(obj)
        self.assertEqual(y.loads(text), obj)
        self.assertNotIn('\u0085', text)
        self.assertNotIn('\u2028', text)
        self.assertNotIn('\u2029', text)
        try:
            import yaml  # QA only; runtime does not import or require PyYAML.
        except ImportError:
            return
        self.assertEqual(yaml.safe_load(text), obj)

    def test_untrusted_scalar_cannot_add_yaml_fields(self):
        obj = {'description': 'hello\nadmin: true\n!!python/object:danger',
               'paths': ['"\n- exact: /admin', ': # & * | > \n']}
        text = a.yaml_module().dumps(obj)
        self.assertEqual(a.yaml_module().loads(text), obj)
        self.assertEqual(len([x for x in text.splitlines() if x.startswith('description:')]), 1)
        try:
            import yaml
        except ImportError:
            return
        self.assertEqual(yaml.safe_load(text), obj)

    def test_unsupported_syntax_and_duplicate_keys_fail_closed(self):
        y = a.yaml_module()
        for text in ['a: 1\na: 2\n', 'a: !!python/object:danger\n', 'a: &anchor foo\n',
                     'a: *anchor\n', 'a: |\n  hello\n', 'a:\n   b: 1\n']:
            with self.subTest(text=text), self.assertRaises(ValueError): y.loads(text)

    def test_invalid_objects_do_not_replace_existing_file(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'candidate.yaml'; a.write(path, {'safe': True})
            before = path.read_bytes()
            for obj in [{'bad': float('nan')}, {'bad': float('inf')}, {1: 'wrong key'}]:
                with self.subTest(obj=obj), self.assertRaises(ValueError): a.write(path, obj)
                self.assertEqual(path.read_bytes(), before)

    def test_policy_matches_independent_yaml_reader(self):
        try:
            import yaml
        except ImportError:
            self.skipTest('Independent PyYAML reader unavailable in test environment')
        with tempfile.TemporaryDirectory() as folder:
            a.observe(a.parser().parse_args(['observe', '--session', folder, '--context', 'test',
                '--namespace', 'demo', '--name', 'learn', '--workload', 'app', '--mitm-domain', 'api.example.com']))
            path = Path(folder)/'observe.yaml'
            obj = a.load(path)
            self.assertEqual(yaml.safe_load(path.read_text()), obj)


if __name__ == '__main__': unittest.main()
