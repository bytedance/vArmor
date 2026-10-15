#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Install a portable local skill; refuse to replace a different installation."""
import argparse
import os
from pathlib import Path

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--tool', choices=['codex', 'claude', 'both'], default='both')
p.add_argument('--project', type=Path, help='install to project .agents/skills and .claude/skills')
a = p.parse_args()
source = Path(__file__).resolve().parent
if not (source / 'SKILL.md').is_file():
    raise SystemExit('skill source is missing: ' + str(source))
base = a.project.resolve() if a.project else Path.home()
dirs = []
if a.tool in ('codex', 'both'):
    dirs.append(base / '.agents' / 'skills')
if a.tool in ('claude', 'both'):
    dirs.append(base / '.claude' / 'skills')
for directory in dirs:
    target = directory / 'varmor-diagnosis'
    if target.exists() or target.is_symlink():
        if target.resolve() != source:
            raise SystemExit('refusing to overwrite existing skill: ' + str(target))
for directory in dirs:
    target = directory / 'varmor-diagnosis'
    if not target.exists():
        directory.mkdir(parents=True, exist_ok=True)
        target.symlink_to(os.path.relpath(source, directory), target_is_directory=True)
    print(target)
