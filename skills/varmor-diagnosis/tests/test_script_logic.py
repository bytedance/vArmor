#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0

"""Cluster-free unit tests for the pure logic embedded in the diagnostic scripts.

The script filenames contain hyphens, so they are loaded explicitly by path
with importlib. Only deterministic, side-effect-free functions are exercised.
"""

import importlib.util
import unittest
from pathlib import Path


SKILL_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = SKILL_ROOT / "scripts"


def load_script(module_name, filename):
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


match = load_script("match_policy_target", "match-policy-target.py")
compat = load_script("check_enforcer_compatibility", "check-enforcer-compatibility.py")
analyze = load_script("analyze_built_in_rules", "analyze-built-in-rules.py")
inspect = load_script("inspect_injection", "inspect-injection.py")


class LabelSelectorTests(unittest.TestCase):
    SELECTOR = {
        "matchLabels": {"app": "web"},
        "matchExpressions": [
            {"key": "tier", "operator": "In", "values": ["fe"]},
            {"key": "env", "operator": "NotIn", "values": ["dev"]},
            {"key": "track", "operator": "Exists"},
            {"key": "legacy", "operator": "DoesNotExist"},
        ],
    }

    def test_full_match(self):
        labels = {"app": "web", "tier": "fe", "env": "prod", "track": "stable"}
        matched, failures = match.evaluate_selector(self.SELECTOR, labels)
        self.assertTrue(matched)
        self.assertEqual(failures, [])
        self.assertTrue(match.selector_matches(self.SELECTOR, labels))

    def test_label_mismatch_is_reported(self):
        labels = {"app": "api", "tier": "fe", "env": "prod", "track": "stable"}
        matched, failures = match.evaluate_selector(self.SELECTOR, labels)
        self.assertFalse(matched)
        self.assertIn("matchLabels:app", failures)

    def test_each_expression_operator_is_checked(self):
        labels = {"app": "web", "tier": "fe", "env": "dev", "legacy": "1"}
        matched, failures = match.evaluate_selector(self.SELECTOR, labels)
        self.assertFalse(matched)
        self.assertIn("matchExpressions:1:NotIn:env", failures)
        self.assertIn("matchExpressions:2:Exists:track", failures)
        self.assertIn("matchExpressions:3:DoesNotExist:legacy", failures)

    def test_invalid_expressions_raise(self):
        bad_in = {"matchExpressions": [{"key": "x", "operator": "In", "values": []}]}
        bad_op = {"matchExpressions": [{"key": "x", "operator": "Between", "values": ["1"]}]}
        with self.assertRaises(ValueError):
            match.evaluate_selector(bad_in, {})
        with self.assertRaises(ValueError):
            match.evaluate_selector(bad_op, {})


class VersionTests(unittest.TestCase):
    def test_version_tuple(self):
        self.assertEqual(compat.version_tuple("v5.10.12-foo"), (5, 10))
        self.assertIsNone(compat.version_tuple("unknown"))
        self.assertIsNone(compat.version_tuple(None))


class EnforcerAndContextTests(unittest.TestCase):
    def test_policy_enforcers(self):
        self.assertEqual(analyze.policy_enforcers("AppArmor,BPF"), {"apparmor", "bpf"})
        self.assertEqual(analyze.policy_enforcers("AppArmorSeccomp"), {"apparmor", "seccomp"})
        self.assertEqual(analyze.policy_enforcers(None), set())

    def test_parse_csv(self):
        self.assertEqual(analyze.parse_csv(" a, b ,, c "), {"a", "b", "c"})
        self.assertEqual(analyze.parse_csv(""), set())
        self.assertIsNone(analyze.parse_csv(None))


class BehaviorRetrievalTests(unittest.TestCase):
    APM = {
        "data": {
            "dynamicResult": {
                "appArmor": {
                    "capabilities": ["CAP_SYS_ADMIN"],
                    "executions": ["/usr/bin/curl"],
                    "files": [{"oldPath": "/x", "permissions": ["r"]}],
                },
                "bpf": {"capabilities": ["cap_bpf"], "executions": ["/bin/bash"]},
                "seccomp": {"syscalls": ["unshare"]},
            }
        }
    }

    def test_retrieve_behavior(self):
        behavior = analyze.retrieve_behavior(self.APM)
        self.assertEqual(behavior["capabilities"], {"cap_sys_admin", "cap_bpf"})
        self.assertEqual(behavior["syscalls"], {"unshare"})
        self.assertEqual(behavior["executions"], {"curl", "bash"})
        self.assertEqual(len(behavior["files"]), 1)


class ProfileValueTests(unittest.TestCase):
    def test_profile_value(self):
        self.assertEqual(inspect.profile_value(None), "UNSET")
        self.assertEqual(inspect.profile_value({}), "UNSET")
        self.assertEqual(inspect.profile_value({"type": "RuntimeDefault"}), "RuntimeDefault")
        self.assertEqual(
            inspect.profile_value({"type": "Localhost", "localhostProfile": "varmor/x.json"}),
            "Localhost/varmor/x.json",
        )


if __name__ == "__main__":
    unittest.main()
