#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Build a portable slim (default) or full skill ZIP from an explicit file list."""
import argparse
from pathlib import Path
import tempfile
import zipfile


SKILL_NAME = 'varmor-policy-optimization'
RUNTIME_FILES = (
    'LICENSE',
    'README.md',
    'README.zh_CN.md',
    'SKILL.md',
    'agents/openai.yaml',
    'playbooks/README.md',
    'playbooks/author-policy.md',
    'playbooks/optimize-policy.md',
    'references/builtin-rules-semantics.md',
    'references/enhance-protect-semantics.md',
    'references/incremental-collection.md',
    'references/optimization-loop.md',
    'references/policy-crd-lifecycle.md',
    'references/raw-rules-syntax.md',
    'references/violation-log.md',
    'requirements.txt',
    'scripts/apply_removals.py',
    'scripts/build_agent_inventory.py',
    'scripts/build_manifest.py',
    'scripts/collect_violations.py',
    'scripts/data/builtin-rules-catalog.json',
    'scripts/finalize_node_log.py',
    'scripts/guard_removal.py',
    'scripts/hash_policy.py',
    'scripts/monitor_violations.py',
    'scripts/pathnorm.py',
    'scripts/preprocess_aggregate.py',
    'scripts/seccomp_plan.py',
    'scripts/validate_attribution.py',
    'scripts/validate_policy.py',
    'scripts/vopt_common.py',
    'templates/attribution.json',
    'templates/observation-policy-skeleton.yaml',
    'templates/observation-task.json',
    'templates/optimization-analysis.md',
)
DEVELOPMENT_FILES = (
    '.gitignore',
    'install.py',
    'package.py',
    'tests/__init__.py',
    'tests/fixtures/fake_kubectl.py',
    'tests/test_intent_contract.py',
    'tests/test_monitor_violations.py',
    'tests/test_packaging.py',
    'tests/test_review_regressions.py',
    'tests/test_script_logic.py',
)
SOURCE_ONLY_START = '<!-- package:source-only:start -->'
SOURCE_ONLY_END = '<!-- package:source-only:end -->'


def package_readme(text, full):
    """Remove marked development instructions from the slim README."""
    parts = []
    while SOURCE_ONLY_START in text:
        before, remaining = text.split(SOURCE_ONLY_START, 1)
        if SOURCE_ONLY_END in before or SOURCE_ONLY_END not in remaining:
            raise ValueError('unbalanced source-only markers in README.md')
        source_only, text = remaining.split(SOURCE_ONLY_END, 1)
        if SOURCE_ONLY_START in source_only:
            raise ValueError('nested source-only markers in README.md')
        parts.append(before)
        if full:
            # Keep hidden boundaries so a portable full package can build slim.
            parts.append(SOURCE_ONLY_START + source_only + SOURCE_ONLY_END)
    if SOURCE_ONLY_END in text:
        raise ValueError('unbalanced source-only markers in README.md')
    parts.append(text)
    return ''.join(parts)


def build_package(source, output, full=False):
    source = Path(source).resolve()
    # Keep an output symlink visible instead of resolving and overwriting its target.
    output = Path(output).absolute()
    if output.suffix.lower() != '.zip':
        raise ValueError('output must use the .zip extension')
    selected = RUNTIME_FILES + (DEVELOPMENT_FILES if full else ())
    entries = {}
    for relative in selected:
        path = source / relative
        if any(item.is_symlink() for item in (path, *path.parents) if item != source and source in item.parents):
            raise ValueError('refusing to package a symlink: ' + relative)
        if not path.is_file():
            raise ValueError('required package file is missing: ' + relative)
        if output.resolve() == path.resolve():
            raise ValueError('output would overwrite a source file: ' + relative)
        content = path.read_bytes()
        if relative in ('README.md', 'README.zh_CN.md'):
            content = package_readme(content.decode('utf-8'), full).encode('utf-8')
        entries[relative] = content
    if output.is_symlink():
        raise ValueError('refusing to overwrite an output symlink: ' + str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    # Replace an older ZIP only after every required input was checked and read.
    with tempfile.NamedTemporaryFile(dir=output.parent, suffix='.zip', delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        with zipfile.ZipFile(temporary_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for relative, content in sorted(entries.items()):
                info = zipfile.ZipInfo(SKILL_NAME + '/' + relative, date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, content)
        temporary_path.replace(output)
    finally:
        temporary_path.unlink(missing_ok=True)
    return len(entries)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--full', action='store_true', help='include installation, packaging, and regression tools')
    parser.add_argument('--output', type=Path, help='output ZIP path; default: dist/varmor-policy-optimization-{skill,full}.zip')
    args = parser.parse_args()
    source = Path(__file__).resolve().parent
    filename = SKILL_NAME + ('-full.zip' if args.full else '-skill.zip')
    output = args.output or source / 'dist' / filename
    try:
        count = build_package(source, output, args.full)
    except (OSError, ValueError) as error:
        parser.exit(1, 'Packaging failed: ' + str(error) + '\n')
    print(f'Created {output.absolute()} ({count} files; {"full" if args.full else "slim"})')


if __name__ == '__main__':
    main()
