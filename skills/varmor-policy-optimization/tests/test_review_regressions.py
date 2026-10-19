#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Regression tests for the compact workflow's failure and decision paths."""

import gzip
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import test_script_logic as fixtures

import build_manifest
import collect_violations
import finalize_node_log
import guard_removal
import hash_policy
import preprocess_aggregate
import seccomp_plan
import validate_attribution
import vopt_common as common


class ReviewRegressions(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, name, content):
        path = self.root / name
        path.write_text(content, encoding="utf-8")
        return str(path)

    def cli(self, script, *arguments, input=None):
        return subprocess.run(
            [sys.executable, os.path.join(fixtures.SCRIPTS_DIR, script), *arguments],
            input=input, text=True, capture_output=True,
        )

    def record(self, timestamp=12, **extra):
        return {
            "eventTimestamp": timestamp, "profileName": "prof",
            "enforcer": "AppArmor", "event": {"operation": "umount"},
            **extra,
        }

    def inventories(self):
        helper = fixtures.BuildManifestTests()
        return (
            helper._inventory(["n1"], captured_at=5),
            helper._inventory(["n1"], captured_at=20),
        )

    def test_snapshot_rv_failure_has_empty_stdout_and_stops_shell(self):
        doc = fixtures.HashPolicyTests()._live_policy()
        snapshot = hash_policy.create_snapshot(common.dump_yaml(doc), captured_at=5)
        doc["metadata"]["uid"] = "recreated"
        policy_path = self.write("current.yaml", common.dump_yaml(doc))
        snapshot_path = self.write("snapshot.json", json.dumps(snapshot))
        result = self.cli(
            "hash_policy.py", "verify-snapshot", "--file", policy_path,
            "--snapshot", snapshot_path, "--window-start", "10", "--resource-version-only",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")
        self.assertIn("mismatches", result.stderr)
        shell = subprocess.run(
            ["bash", "-c",
             'set -euo pipefail\nRV="$("$@")" || exit 1\nprintf "continued"',
             "review", sys.executable, os.path.join(fixtures.SCRIPTS_DIR, "hash_policy.py"),
             "verify-snapshot", "--file", policy_path, "--snapshot", snapshot_path,
             "--window-start", "10", "--resource-version-only"],
            capture_output=True, text=True,
        )
        self.assertNotEqual(shell.returncode, 0)
        self.assertNotIn("continued", shell.stdout)

    def test_failed_pipeline_cannot_be_masked_by_chmod(self):
        path = str(self.root / "inventory.json")
        result = subprocess.run(
            ["bash", "-c",
             'set -euo pipefail\n(printf "{}"; exit 7) | cat > "$1"\nchmod 600 "$1"\nprintf continued',
             "review", path],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("continued", result.stdout)

    def test_live_spec_cli_rejects_retained_raw_rules(self):
        candidate = fixtures.policy(
            enhance={"appArmorRawRules": [], "bpfRawRules": {}}
        )
        candidate_path = self.write("candidate.yaml", common.dump_yaml(candidate))
        live_path = self.write("live.yaml", common.dump_yaml(candidate))
        result = self.cli(
            "guard_removal.py",
            "--verify-live",
            "--candidate",
            candidate_path,
            "--live",
            live_path,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["liveSpecVerified"])

        live = common.load_yaml_doc(Path(live_path).read_text(encoding="utf-8"))
        live["spec"]["policy"]["enhanceProtect"]["appArmorRawRules"] = [
            {"targets": [], "rules": "deny /tmp/retained r,"}
        ]
        Path(live_path).write_text(common.dump_yaml(live), encoding="utf-8")
        result = self.cli(
            "guard_removal.py",
            "--verify-live",
            "--candidate",
            candidate_path,
            "--live",
            live_path,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("live spec", result.stderr)

    def test_keep_does_not_resolve_original_seccomp_ambiguity(self):
        doc = fixtures.policy(enhance={"attackProtectionRules": [
            {"rules": ["disable-chmod-x-bit", "disable-chmod-s-bit"]}
        ]})
        plan = seccomp_plan.build_plan(
            doc, ["chmod"],
            remove_builtin_rules=["disable-chmod-s-bit"],
            keep_builtin_rules=["disable-chmod-x-bit"],
        )
        self.assertEqual(plan["ambiguousSyscalls"], ["chmod"])
        candidate = seccomp_plan.apply_plan(doc, plan)
        pre = {"collectionComplete": True, "retentionCovered": True,
               "seccompSyscalls": ["chmod"], "failures": []}
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(
                doc, candidate, [], pre=pre,
                remove_seccomp_rules=["disable-chmod-s-bit"],
                keep_seccomp_rules=["disable-chmod-x-bit"],
            )
        self.assertEqual(guard_removal.guard(
            doc, candidate, [], pre=pre,
            remove_seccomp_rules=["disable-chmod-s-bit"],
            keep_seccomp_rules=["disable-chmod-x-bit"],
            allow_ambiguous=True,
        )["totalRemoved"], 1)

    def test_keep_syscall_retains_raw_and_shared_builtin_atoms(self):
        raw = {"names": ["chmod", "keyctl"], "action": "SCMP_ACT_ERRNO"}
        doc = fixtures.policy(enhance={
            "attackProtectionRules": [{"rules": ["disable-chmod-x-bit"]}],
            "syscallRawRules": [raw],
        })
        plan = seccomp_plan.build_plan(
            doc, ["chmod", "fchmod", "keyctl"],
            keep_builtin_rules=["disable-chmod-x-bit"],
            remove_syscalls=["keyctl"],
            keep_syscalls=["chmod"],
        )
        self.assertEqual(plan["builtinRemovals"], [])
        self.assertEqual(plan["keptSyscalls"], ["chmod"])
        self.assertEqual(plan["keptCustomRules"][0]["rule"]["names"], ["chmod"])
        updated = seccomp_plan.apply_plan(doc, plan)
        enhance = updated["spec"]["policy"]["enhanceProtect"]
        self.assertEqual(enhance["syscallRawRules"][0]["names"], ["chmod"])
        self.assertEqual(enhance["attackProtectionRules"], doc["spec"]["policy"]["enhanceProtect"]["attackProtectionRules"])

    def test_keep_syscall_cli_and_guard_share_decisions(self):
        doc = fixtures.policy(enhance={
            "syscallRawRules": [{"names": ["keyctl"], "action": "SCMP_ACT_ERRNO"}]
        })
        pre = {"collectionComplete": True, "retentionCovered": True,
               "seccompSyscalls": ["keyctl"], "failures": [],
               "aggregatedEvents": []}
        baseline = self.write("baseline.yaml", common.dump_yaml(doc))
        pre_path = self.write("pre.json", json.dumps(pre))
        attribution = self.write("attribution.json", "[]")
        planned = self.cli(
            "seccomp_plan.py", "--policy", baseline, "--pre", pre_path, "--apply",
            "--keep-seccomp-syscall", "keyctl",
        )
        self.assertEqual(planned.returncode, 0, planned.stderr)
        self.assertEqual(common.load_yaml_doc(planned.stdout), doc)
        candidate = self.write("candidate.yaml", planned.stdout)
        guarded = self.cli(
            "guard_removal.py", "--baseline", baseline, "--candidate", candidate,
            "--pre", pre_path, "--attribution", attribution,
            "--keep-seccomp-syscall", "keyctl",
        )
        self.assertEqual(guarded.returncode, 0, guarded.stderr)
        self.assertEqual(json.loads(guarded.stdout)["totalRemoved"], 0)

    def test_invalid_keep_values_fail_closed(self):
        doc = fixtures.policy()
        for values in ([""], [None], "chmod"):
            with self.subTest(values=values), self.assertRaises(common.ValidationError):
                seccomp_plan.build_plan(doc, ["chmod"], keep_syscalls=values)
        with self.assertRaises(common.ValidationError):
            seccomp_plan.build_plan(doc, ["chmod"], keep_syscalls=["keyctl"])

    def test_no_custom_removal_preserves_empty_raw_field(self):
        doc = fixtures.policy(enhance={
            "syscallRawRules": [], "hardeningRules": ["disallow-create-user-ns"]
        })
        plan = seccomp_plan.build_plan(
            doc, ["unshare"], remove_builtin_rules=["disallow-create-user-ns"]
        )
        updated = seccomp_plan.apply_plan(doc, plan)
        self.assertEqual(updated["spec"]["policy"]["enhanceProtect"]["syscallRawRules"], [])

    def test_finalize_plain_gzip_permissions_and_no_overwrite(self):
        first = self.write("violations.log", json.dumps(self.record()))
        rotated = self.root / "violations-1.log.gz"
        with gzip.open(rotated, "wt") as handle:
            handle.write(json.dumps(self.record(5)) + "\n")
        output = self.root / "logs/n1.log"
        result = self.cli("finalize_node_log.py", "--file", first, "--file", str(rotated),
                          "--output", str(output), "--window-end", "0",
                          "--started-at", "0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(output.read_text().splitlines()), 2)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(common.ValidationError):
            finalize_node_log.finalize([first], str(output), 0, 0)

    def test_finalize_bad_inputs_publish_nothing(self):
        valid = self.write("valid.log", json.dumps(self.record()))
        bad = self.write("truncated.log", '{"eventTimestamp":')
        gzip_path = self.root / "bad.log.gz"
        gzip_path.write_bytes(b"not gzip")
        for source in (bad, str(gzip_path), str(self.root / "missing.log")):
            output = self.root / "logs/n1.log"
            result = self.cli(
                "finalize_node_log.py", "--file", valid, "--file", source,
                "--output", str(output), "--window-end", "0", "--started-at", "0"
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(output.exists())
            self.assertEqual(list(output.parent.glob(".node-log-*")), [])

    def test_pre_window_copy_cannot_be_laundered_by_late_preprocess(self):
        source = self.write("copied.log", json.dumps(self.record(5)))
        os.utime(source, (21, 21))
        output = self.root / "logs/n1.log"
        result = self.cli(
            "finalize_node_log.py", "--file", source, "--output", str(output),
            "--window-end", "20", "--started-at", "19",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())

        os.utime(source, (19, 19))
        start, end = self.inventories()
        manifest, _ = build_manifest.build(
            start, end, [("n1", source, 0)], 10, 20, manifest_built_at=30
        )
        self.assertFalse(manifest["windowComplete"])
        self.assertFalse(manifest["logsCollectedAfterWindow"])
        self.assertEqual(
            manifest["nodes"][0]["retention"]["basis"],
            "log-collected-before-window-end",
        )

    def test_manifest_cannot_reuse_one_log_for_two_nodes(self):
        log = self.write("n1.log", json.dumps(self.record(5)))
        alias = self.root / "n2.log"
        os.link(log, alias)
        helper = fixtures.BuildManifestTests()
        with self.assertRaises(common.ValidationError):
            build_manifest.build(
                helper._inventory(["n1", "n2"], captured_at=5),
                helper._inventory(["n1", "n2"], captured_at=20),
                [("n1", log, 0), ("n2", str(alias), 0)], 10, 20, manifest_built_at=20,
            )

    def test_wrong_node_identity_and_bad_encoding_block_manifest(self):
        start, end = self.inventories()
        path = self.write("n1.log", json.dumps(self.record(5, nodeName="n2")))
        manifest, _ = build_manifest.build(start, end, [("n1", path, 0)], 10, 20, manifest_built_at=20)
        self.assertFalse(manifest["retentionCovered"])
        Path(path).write_bytes(b"\xff")
        manifest, _ = build_manifest.build(start, end, [("n1", path, 0)], 10, 20, manifest_built_at=20)
        self.assertFalse(manifest["nodes"][0]["read"])

    def test_bad_timestamps_count_and_fractional_boundary_is_exact(self):
        records = [self.record(ts) for ts in (5, float("nan"), float("inf"), -1, True, 20.5)]
        result = collect_violations.collect(
            "\n".join(map(json.dumps, records)), 0, 20, profile_name="prof"
        )
        self.assertEqual(result["counts"]["parseErrors"], 4)
        self.assertEqual(result["counts"]["outsideWindow"], 1)
        self.assertEqual(result["counts"]["matched"], 1)

    def test_missing_profile_and_vcp_namespace_diagnostics(self):
        records = [self.record(profileName=None), self.record(
            policyKind="VarmorClusterPolicy", policyName="demo", policyNamespace="unexpected"
        )]
        result = collect_violations.collect(
            "\n".join(map(json.dumps, records)), 0, 20,
            kind="VarmorClusterPolicy", name="demo", profile_name="prof",
        )
        self.assertEqual(result["counts"]["missingIdentity"], 1)
        self.assertEqual(result["counts"]["policyIdentityMismatch"], 1)
        self.assertEqual(result["counts"]["matched"], 0)

    def test_compact_scope_derived_from_policy_and_conflicts_rejected(self):
        start, end = self.inventories()
        path = self.write("n1.log", "\n".join(json.dumps(self.record(ts)) for ts in (5, 12)))
        doc = fixtures.policy(enforcer="AppArmor")
        doc["status"] = {"profileName": "prof"}
        args = (start, end, [("n1", path)], 10, 20, doc, fixtures.CATALOG, "not-applicable")
        result = preprocess_aggregate.preprocess_node_logs(*args, manifest_built_at=20)
        self.assertTrue(result["collectionComplete"])
        with self.assertRaises(common.ValidationError):
            preprocess_aggregate.preprocess_node_logs(*args, profile_name="another", manifest_built_at=20)

    def test_catalog_respects_policy_enforcers(self):
        doc = fixtures.policy(enforcer="AppArmor", enhance={"hardeningRules": ["disallow-umount"]})
        entries = preprocess_aggregate.build_rule_catalog(doc, fixtures.CATALOG)
        self.assertEqual(entries[0]["enforcers"], ["AppArmor"])

    def test_invalid_event_enforcers_and_syscall_types_are_failures(self):
        for record in ({"enforcer": "typo", "event": {}},
                       {"enforcer": 1, "event": {}},
                       {"enforcer": "Seccomp", "event": {"syscall": ["keyctl"]}}):
            result = preprocess_aggregate.preprocess([record], fixtures.CATALOG)
            self.assertTrue(result["failures"])
            self.assertFalse(result["collectionComplete"])

    def test_attribution_rejects_truthy_gate_and_false_matches(self):
        helper = fixtures.ValidateAttributionTests()
        pre = helper._pre()
        pre["collectionComplete"] = "false"
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(pre, helper._catalog(), [])
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(
                helper._pre(), helper._catalog(),
                [{"eventId": "evt-000001", "matches": False}],
            )

    def test_seccomp_candidates_require_explicit_decisions(self):
        doc = fixtures.policy(
            enhance={"hardeningRules": ["disallow-create-user-ns"]}
        )
        pending = seccomp_plan.build_plan(doc, ["unshare"])
        self.assertFalse(pending["decisionsComplete"])
        self.assertEqual(pending["builtinRemovals"], [])
        with self.assertRaises(common.ValidationError):
            seccomp_plan.apply_plan(doc, pending)
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "seccompSyscalls": ["unshare"],
            "failures": [],
        }
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(doc, doc, [], pre=pre)
        decided = seccomp_plan.build_plan(
            doc, ["unshare"], remove_builtin_rules=["disallow-create-user-ns"]
        )
        self.assertTrue(decided["decisionsComplete"])
        self.assertEqual(len(decided["builtinRemovals"]), 1)

    def test_attribution_requires_exact_unique_event_coverage(self):
        helper = fixtures.ValidateAttributionTests()
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(helper._pre(), helper._catalog(), [])
        duplicate = [
            {"eventId": "evt-000001", "matches": []},
            {"eventId": "evt-000001", "matches": []},
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(helper._pre(), helper._catalog(), duplicate)
        result = validate_attribution.validate(
            helper._pre(), helper._catalog(),
            [{"eventId": "evt-000001", "matches": []}],
        )
        self.assertEqual(result["authorized"], [])

    def test_attribution_malformed_pre_catalog_context_are_validation_errors(self):
        helper = fixtures.ValidateAttributionTests()
        cases = [
            (dict(helper._pre(), aggregatedEvents=["bad"]), helper._catalog(), []),
            (helper._pre(), {"ruleCatalog": ["bad"]},
             [{"eventId": "evt-000001", "matches": []}]),
            (helper._pre(), helper._catalog(), [{
                "eventId": "evt-000001",
                "matches": [{
                    "source": "hardeningRules",
                    "rule": "disallow-umount",
                    "context": "bad",
                }],
            }]),
        ]
        for pre, catalog, attribution in cases:
            with self.subTest(pre=pre, catalog=catalog, attribution=attribution):
                with self.assertRaises(common.ValidationError):
                    validate_attribution.validate(pre, catalog, attribution)


if __name__ == "__main__":
    unittest.main()
