# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Cluster-free delivery checks for the standalone skill."""

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile


SKILL_NAME = "varmor-diagnosis"
SMOKE_SCRIPT = "inspect-injection.py"
SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("package_diagnosis", SOURCE / "package.py")
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


class PackagingTests(unittest.TestCase):
    def test_slim_excludes_unlisted_data_and_runs_independently(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(SOURCE, source, ignore=shutil.ignore_patterns("__pycache__", "dist"))
            for name in ("evidence/audit.json", "sessions/events.sqlite", "scripts/private.txt", "old.zip"):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("private canary")
            output = root / "skill.zip"
            package.build_package(source, output)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(set(archive.namelist()),
                                 {SKILL_NAME + "/" + name for name in package.RUNTIME_FILES})
                for name in archive.namelist():
                    self.assertNotIn(b"private canary", archive.read(name))
                for name in ("README.md", "README.zh_CN.md"):
                    content = archive.read(SKILL_NAME + "/" + name)
                    self.assertNotIn(b"<!-- package:", content)
                    self.assertNotIn(b"python3 package.py", content)
                    self.assertNotIn(b"python3 install.py", content)
                    self.assertIn(b"LICENSE", content)
                self.assertIn(SKILL_NAME + "/agents/openai.yaml", archive.namelist())
                archive.extractall(root / "extracted")
            shutil.rmtree(source)
            result = subprocess.run(
                [sys.executable, str(root / "extracted" / SKILL_NAME / "scripts" / SMOKE_SCRIPT), "--help"],
                cwd=root, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("usage:", result.stdout)

    def test_full_is_self_contained_and_repackages_identically(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            full = root / "full.zip"
            package.build_package(SOURCE, full, full=True)
            with zipfile.ZipFile(full) as archive:
                self.assertEqual(set(archive.namelist()), {
                    SKILL_NAME + "/" + name
                    for name in package.RUNTIME_FILES + package.DEVELOPMENT_FILES
                })
                archive.extractall(root / "extracted")
            installed = root / "extracted" / SKILL_NAME
            rebuilt = root / "rebuilt.zip"
            result = subprocess.run(
                [sys.executable, str(installed / "package.py"), "--full", "--output", str(rebuilt)],
                cwd=root, capture_output=True, text=True,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(full.read_bytes(), rebuilt.read_bytes())
            slim = root / "slim.zip"
            direct = root / "direct.zip"
            package.build_package(installed, slim)
            package.build_package(SOURCE, direct)
            self.assertEqual(slim.read_bytes(), direct.read_bytes())

    def test_missing_file_preserves_previous_archive(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(SOURCE, source, ignore=shutil.ignore_patterns("__pycache__", "dist"))
            (source / "SKILL.md").unlink()
            output = root / "skill.zip"
            output.write_bytes(b"previous archive")
            with self.assertRaisesRegex(ValueError, "required package file is missing"):
                package.build_package(source, output)
            self.assertEqual(output.read_bytes(), b"previous archive")

    def test_input_and_output_symlinks_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            shutil.copytree(SOURCE, source, ignore=shutil.ignore_patterns("__pycache__", "dist"))
            outside = root / "private.md"
            outside.write_text("private data")
            (source / "SKILL.md").unlink()
            (source / "SKILL.md").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "refusing to package a symlink"):
                package.build_package(source, root / "skill.zip")
            previous = root / "previous.zip"
            previous.write_bytes(b"keep this")
            link = root / "output.zip"
            link.symlink_to(previous)
            with self.assertRaisesRegex(ValueError, "output symlink"):
                package.build_package(SOURCE, link)
            self.assertEqual(previous.read_bytes(), b"keep this")
            with self.assertRaisesRegex(ValueError, ".zip extension"):
                package.build_package(SOURCE, root / "notes.md")


class InstallationTests(unittest.TestCase):
    def install(self, project):
        return subprocess.run(
            [sys.executable, str(SOURCE / "install.py"), "--tool", "both", "--project", str(project)],
            capture_output=True, text=True,
        )

    def test_project_links_are_relative_and_install_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            for _ in range(2):
                result = self.install(project)
                self.assertEqual(result.returncode, 0, result.stderr)
            for assistant in (".agents", ".claude"):
                target = project / assistant / "skills" / SKILL_NAME
                self.assertTrue(target.is_symlink())
                self.assertFalse(os.path.isabs(os.readlink(target)))
                self.assertEqual(target.resolve(), SOURCE)

    def test_collision_is_detected_before_either_installation(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            existing = project / ".claude/skills" / SKILL_NAME
            existing.mkdir(parents=True)
            (existing / "keep.md").write_text("original")
            result = self.install(project)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("refusing to overwrite", result.stderr)
            self.assertEqual((existing / "keep.md").read_text(), "original")
            self.assertFalse((project / ".agents/skills" / SKILL_NAME).exists())


if __name__ == "__main__":
    unittest.main()
