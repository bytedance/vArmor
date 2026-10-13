# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_skill', SOURCE / 'package.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def copy_source(self, destination):
        shutil.copytree(SOURCE, destination, ignore=shutil.ignore_patterns('evidence', 'dist', '*.zip', '__pycache__'))

    def test_slim_excludes_local_artifacts_and_runs_after_extraction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            self.copy_source(source)
            for relative in ('evidence/audit.json', 'session/events.sqlite', 'scripts/token.txt', 'old.zip'):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('private canary')
            output = root / 'release.zip'
            subprocess.run([sys.executable, str(source / 'package.py'), '--output', str(output)],
                           cwd=root, check=True, capture_output=True, text=True)
            with zipfile.ZipFile(output) as archive:
                names = archive.namelist()
                self.assertEqual(len(names), len(package.RUNTIME_FILES))
                self.assertIn('varmor-network-advisor/scripts/collector.py', names)
                self.assertIn('varmor-network-advisor/scripts/advisor.py', names)
                self.assertIn('varmor-network-advisor/README.zh_CN.md', names)
                self.assertNotIn('varmor-network-advisor/SKILL.zh_CN.md', names)
                self.assertTrue(all(name.startswith('varmor-network-advisor/') for name in names))
                self.assertTrue(all(b'private canary' not in archive.read(name) for name in names))
                for filename in ('README.md', 'README.zh_CN.md'):
                    readme = archive.read('varmor-network-advisor/' + filename).decode()
                    self.assertNotIn('python3 install.py', readme)
                    self.assertNotIn('python3 tests/smoke_cluster.py', readme)
                    self.assertNotIn('python3 package.py', readme)
                    self.assertNotIn('<!-- package:', readme)
                    self.assertIn('cp -R', readme)
                archive.extractall(root / 'installed')
            shutil.rmtree(source)
            result = subprocess.run([sys.executable, str(root / 'installed/varmor-network-advisor/scripts/advisor.py'), '--help'],
                                    cwd=root, check=True, capture_output=True, text=True)
            self.assertIn('observe', result.stdout)
            self.assertIn('analyze', result.stdout)

    def test_full_contains_development_tools_and_repackages(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / 'full.zip'
            package.build_package(SOURCE, output, full=True)
            with zipfile.ZipFile(output) as archive:
                for relative in ('install.py', 'package.py', 'tests/smoke_cluster.py', 'tests/smoke_tls_tcp.py', 'tests/test_packaging.py'):
                    self.assertIn('varmor-network-advisor/' + relative, archive.namelist())
                for path in (SOURCE / 'tests').rglob('*.py'):
                    relative = path.relative_to(SOURCE).as_posix()
                    self.assertIn('varmor-network-advisor/' + relative, archive.namelist())
                for filename in ('README.md', 'README.zh_CN.md'):
                    readme = archive.read('varmor-network-advisor/' + filename)
                    self.assertIn(package.SOURCE_ONLY_START.encode(), readme)
                    self.assertIn(b'python3 package.py --full', readme)
                archive.extractall(root / 'extracted')
            for script in ('smoke_cluster.py', 'smoke_tls_tcp.py', 'smoke_collector.py'):
                subprocess.run([sys.executable, str(root / 'extracted/varmor-network-advisor/tests' / script), '--help'],
                               cwd=root, check=True, capture_output=True, text=True)
            repackaged = root / 'repackaged.zip'
            subprocess.run([sys.executable, str(root / 'extracted/varmor-network-advisor/package.py'), '--full', '--output', str(repackaged)],
                           cwd=root, check=True, capture_output=True, text=True)
            self.assertEqual(output.read_bytes(), repackaged.read_bytes())
            slim = root / 'slim-from-full.zip'
            subprocess.run([sys.executable, str(root / 'extracted/varmor-network-advisor/package.py'),
                            '--output', str(slim)], cwd=root, check=True, capture_output=True, text=True)
            direct_slim = root / 'direct-slim.zip'
            package.build_package(SOURCE, direct_slim)
            self.assertEqual(direct_slim.read_bytes(), slim.read_bytes())
            with zipfile.ZipFile(slim) as archive:
                for filename in ('README.md', 'README.zh_CN.md'):
                    readme = archive.read('varmor-network-advisor/' + filename)
                    self.assertNotIn(package.SOURCE_ONLY_START.encode(), readme)
                    self.assertNotIn(b'python3 install.py', readme)
                    self.assertNotIn(b'python3 package.py', readme)

    def test_repeated_build_is_identical(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / 'skill.zip'
            package.build_package(SOURCE, output)
            initial = output.read_bytes()
            package.build_package(SOURCE, output)
            self.assertEqual(initial, output.read_bytes())

    def test_missing_required_file_preserves_previous_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            self.copy_source(source)
            (source / 'references/networkproxy.md').unlink()
            output = root / 'skill.zip'
            output.write_bytes(b'previous archive')
            with self.assertRaisesRegex(ValueError, 'required package file is missing'):
                package.build_package(source, output)
            self.assertEqual(output.read_bytes(), b'previous archive')

    def test_symlinked_input_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'source'
            self.copy_source(source)
            outside = root / 'private.md'
            outside.write_text('private data')
            original = source / 'references/networkproxy.md'
            original.unlink()
            original.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'refusing to package a symlink'):
                package.build_package(source, root / 'skill.zip')
            self.assertFalse((root / 'skill.zip').exists())

    def test_output_symlink_and_non_zip_destination_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / 'existing.zip'
            original.write_bytes(b'keep this')
            link = root / 'output.zip'
            link.symlink_to(original)
            with self.assertRaisesRegex(ValueError, 'output symlink'):
                package.build_package(SOURCE, link)
            self.assertEqual(original.read_bytes(), b'keep this')
            with self.assertRaisesRegex(ValueError, '.zip extension'):
                package.build_package(SOURCE, root / 'notes.md')


if __name__ == '__main__':
    unittest.main()
