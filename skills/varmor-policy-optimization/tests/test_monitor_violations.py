# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Incremental collection regressions; fake sources, no live cluster access."""

import argparse
import copy
import gzip
import json
import os
import shutil
import sqlite3
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import test_script_logic as fixtures
import monitor_violations as monitor
import hash_policy
import preprocess_aggregate
import validate_attribution
import vopt_common as common


def line(timestamp=12):
    return (json.dumps({"eventTimestamp": timestamp, "profileName": "prof",
                       "nodeName": "n1", "enforcer": "AppArmor",
                       "event": {"operation": "umount"}}) + "\n").encode()


class MemoryReader:
    def __init__(self, files):
        self.files = files

    def manifest(self):
        return {key: {"path": path, "identity": key, "size": len(raw)}
                for key, (path, raw) in self.files.items()}

    def read(self, entry, offset, length):
        return self.files[entry["identity"]][1][offset:offset + length]


class CursorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.con = monitor.database(self.tmp.name)
        self.addCleanup(self.con.close)
        self.path = "/var/log/varmor/violations.log"

    def scan(self, reader, budget=2 * 1024 * 1024, at=5):
        with self.con:
            return monitor.scan(self.con, "n1", reader, budget, at)

    def count(self):
        return self.con.execute("SELECT count(*) FROM records").fetchone()[0]

    def test_append_rotation_dedup_preserves_identical_real_events(self):
        raw = line()
        reader = MemoryReader({"1:1": (self.path, raw * 3)})
        self.scan(reader, budget=len(raw))
        self.assertEqual(self.count(), 1)
        reader.files = {"1:1": ("/var/log/varmor/violations-old.log", raw * 3),
                        "1:2": (self.path, raw)}
        self.scan(reader)
        self.scan(reader)
        self.assertEqual(self.count(), 4)
        self.assertEqual(monitor.issues(self.con), [])
        del reader.files["1:1"]  # Fully drained backup expiry is harmless.
        self.scan(reader)
        self.assertEqual(monitor.issues(self.con), [])

    def test_partial_lines_are_revisited_without_duplication(self):
        raw = line()
        reader = MemoryReader({"1:1": (self.path, raw + raw[:-3])})
        _, receipt = self.scan(reader)
        self.assertGreater(receipt["backlogBytes"], 0)
        self.assertEqual(self.count(), 1)
        reader.files["1:1"] = (self.path, raw * 2)
        self.scan(reader)
        self.assertEqual(self.count(), 2)

    def test_unread_backup_expiry_records_a_gap(self):
        reader = MemoryReader({"1:1": (self.path, line() * 3)})
        self.scan(reader, budget=len(line()))
        reader.files = {"1:2": (self.path, line())}
        self.scan(reader)
        self.assertIn("unread-file-disappeared", [x["reason"] for x in monitor.issues(self.con)])

    def test_truncation_or_rewrite_changes_generation_and_records_gap(self):
        reader = MemoryReader({"1:1": (self.path, line(12))})
        self.scan(reader)
        reader.files["1:1"] = (self.path, line(13))
        self.scan(reader)
        self.assertEqual(self.count(), 2)
        self.assertEqual(monitor.issues(self.con)[0]["reason"], "file-reset")

    def test_compressed_rename_keeps_cursor_on_subsequent_scans(self):
        raw = line()
        path = "/var/log/varmor/violations-old.log"
        reader = MemoryReader({"1:1": (path, raw * 2), "1:2": (self.path, b"")})
        self.scan(reader)
        reader.files = {"1:3": (path + ".gz", raw * 2), "1:2": (self.path, b"")}
        self.scan(reader)
        self.scan(reader)
        self.assertEqual(self.count(), 2)
        self.assertEqual(monitor.issues(self.con), [])

    def test_short_read_rolls_back_events_and_cursors(self):
        class ShortReader(MemoryReader):
            def read(self, entry, offset, length):
                return super().read(entry, offset, length)[:-1]
        with self.assertRaises(common.ValidationError):
            self.scan(ShortReader({"1:1": (self.path, line())}))
        self.assertEqual(self.count(), 0)
        self.assertEqual(self.con.execute("SELECT count(*) FROM cursors").fetchone()[0], 0)

    def test_hard_issue_cannot_be_unblocked_by_adding_a_resolution_timestamp(self):
        with self.con:
            monitor.issue(self.con, "n1", "file-reset", resolvedAt=25)
            monitor.issue(self.con, "n1", "unread-file-disappeared", severity="hard", resolvedAt=25)
        self.assertEqual(len(monitor.blocking_issues(self.con)), 2)

    def test_read_completion_controls_coverage_start(self):
        times = iter([5, 11])
        reader = MemoryReader({"1:1": (self.path, b"")})
        _, receipt = self.scan(reader, at=lambda: next(times))
        self.assertEqual(receipt["coveredFrom"], 11)
        self.assertEqual(receipt["lastReadStartedAt"], 5)

    def test_pre_window_initialization_skips_old_history_then_collects_new_bytes(self):
        reader = MemoryReader({"1:1": (self.path, line(1) * 1000)})
        with self.con:
            monitor.scan(self.con, "n1", reader, 2 * 1024 * 1024, 5, initialize=True)
        self.assertEqual(self.count(), 0)
        reader.files["1:1"] = (self.path, line(1) * 1000 + line(12))
        self.scan(reader, at=15)
        self.assertEqual(self.count(), 1)

    def test_initialization_does_not_skip_an_unfinished_tail(self):
        reader = MemoryReader({"1:1": (self.path, line(1) * 10 + line(12)[:-1])})
        with self.con:
            _, receipt = monitor.scan(self.con, "n1", reader, 2 * 1024 * 1024, 5, initialize=True)
        self.assertNotIn("coveredFrom", receipt)
        reader.files["1:1"] = (self.path, line(1) * 10 + line(12))
        self.scan(reader, at=8)
        self.assertEqual(self.count(), 1)
        self.assertEqual(monitor.state_get(self.con, "node:n1")["coveredFrom"], 8)

    def test_empty_continuous_node_can_prove_coverage_but_snapshot_cannot(self):
        reader = MemoryReader({"1:1": (self.path, b"")})
        self.scan(reader, at=5)
        self.scan(reader, at=20)
        with self.con:
            monitor.state_set(self.con, "settleInterval", 5)
            monitor.confirm_final(self.con, "n1", 20, 5)
        self.scan(reader, at=25)
        with self.con:
            monitor.confirm_final(self.con, "n1", 20, 5)
        helper = fixtures.BuildManifestTests()
        policy = live_policy()
        pre = monitor.export_pre(self.con, Path(self.tmp.name), helper._inventory(["n1"], 4),
                                 helper._inventory(["n1"], 25), policy, 10, 20, "not-applicable")
        self.assertTrue(pre["collectionComplete"])
        self.assertEqual(pre["collectionManifest"]["collectionMode"], "incremental")
        self.assertEqual(pre["aggregatedEvents"], [])
        manifest = copy.deepcopy(pre["collectionManifest"])
        manifest["nodes"][0]["incremental"]["coveredFrom"] = 10
        self.assertFalse(preprocess_aggregate.preprocess(
            [], common.load_catalog(), manifest=manifest)["collectionComplete"])
        manifest = copy.deepcopy(pre["collectionManifest"])
        manifest["collectionIssues"] = [{"node": "n1", "reason": "unread-file-disappeared",
                                         "resolvedAt": 25}]
        self.assertFalse(preprocess_aggregate.preprocess(
            [], common.load_catalog(), manifest=manifest)["collectionComplete"])
        manifest["collectionIssues"][0]["severity"] = "hard"
        self.assertFalse(preprocess_aggregate.preprocess(
            [], common.load_catalog(), manifest=manifest)["collectionComplete"])
        manifest["collectionIssues"] = [{"node": "n1", "reason": "source-read-failed",
                                         "severity": "suspected", "resolvedAt": 25}]
        self.assertTrue(preprocess_aggregate.preprocess(
            [], common.load_catalog(), manifest=manifest)["collectionComplete"])

    def test_gap_or_late_initialization_blocks_attribution(self):
        reader = MemoryReader({"1:1": (self.path, line())})
        self.scan(reader, at=11)
        self.scan(reader, at=20)
        helper = fixtures.BuildManifestTests()
        pre = monitor.export_pre(self.con, Path(self.tmp.name), helper._inventory(["n1"], 4),
                                 helper._inventory(["n1"], 20), live_policy(), 10, 20, "not-applicable")
        self.assertFalse(pre["collectionComplete"])
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(pre, {"ruleCatalog": []}, [])

    def test_claimed_finalization_without_source_receipts_does_not_pass(self):
        manifest = {"collectionMode": "incremental", "finalReadComplete": True,
                    "window": {"start": 10, "end": 20}, "windowComplete": True,
                    "collectedAt": 20, "manifestBuiltAt": 20,
                    "agentInventoryComplete": True, "nodeSetComplete": True,
                    "expectedNodes": ["n1"], "retentionCovered": True,
                    "nodes": [{"node": "n1", "read": True,
                               "retention": {"status": "covered"}}]}
        pre = preprocess_aggregate.preprocess([], common.load_catalog(), manifest=manifest)
        self.assertFalse(pre["collectionComplete"])


def live_policy():
    policy = fixtures.policy(enforcer="AppArmor", enhance={"auditViolations": True,
                             "allowViolations": True, "hardeningRules": ["disallow-umount"]})
    policy["metadata"].update(uid="policy-uid", generation=1, resourceVersion="100")
    policy["status"] = {"profileName": "prof"}
    return policy


class RunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.now = 5
        self.policy = live_policy()
        self.inventory = fixtures.BuildManifestTests()._inventory(["n1"], 4)
        monitor.save(self.root / "inventory.json", self.inventory)
        monitor.save(self.root / "snapshot.json", hash_policy.create_snapshot(common.dump_yaml(self.policy), 4))
        task = {"taskVersion": 1, "taskType": "varmor-policy-optimization", "status": "observing",
                "clusterContext": "test", "policy": {"kind": "VarmorPolicy", "namespace": "app", "name": "demo"},
                "policySnapshotFile": str(self.root / "snapshot.json"),
                "agentInventoryStartFile": str(self.root / "inventory.json"),
                "window": {"start": 10, "end": 20, "plannedEnd": 20}, "outputs": {}}
        monitor.save(self.root / "task.json", task)
        self.args = argparse.Namespace(task=str(self.root / "task.json"), output=str(self.root / "run"),
            agent_namespace="varmor", daemonset="varmor-agent", container="agent",
            log_directory="/var/log/varmor", interval=5, max_read_mb=2, max_local_mb=100,
            request_timeout=30, final_read_seconds=60, network_proxy_evidence="not-applicable")
        owner = self
        class Kube:
            def policy(self, identity):
                return copy.deepcopy(owner.policy)
            def inventory(self, namespace, daemonset):
                inv = copy.deepcopy(owner.inventory)
                inv["capturedAt"] = int(owner.now)
                return inv
        self.kube = Kube()

    def sleep(self, seconds):
        self.now += seconds

    def factory(self, *args):
        raw = line() * 2 if self.now >= 12 else b""
        return MemoryReader({"1:1": ("/var/log/varmor/violations.log", raw)})

    def run_monitor(self, factory=None):
        return monitor.run(self.args, self.kube, factory or self.factory,
                           clock=lambda: self.now, sleep=self.sleep, monotonic=lambda: self.now)

    def interrupt_monitor(self, factory=None):
        class Crash(BaseException):
            pass
        def crash(seconds):
            if self.now >= 15:
                self.now = 18
                raise Crash()
            self.now += seconds
        self.sleep = crash
        with self.assertRaises(Crash):
            self.run_monitor(factory)
        self.sleep = lambda seconds: setattr(self, "now", self.now + seconds)

    def test_confirmation_scan_collects_late_written_window_events(self):
        def factory(*args):
            raw = line() * (3 if self.now >= 25 else 2) if self.now >= 12 else b""
            return MemoryReader({"1:1": ("/var/log/varmor/violations.log", raw)})
        self.assertEqual(self.run_monitor(factory), 0)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertEqual(pre["collectionCounts"]["matched"], 3)
        receipt = pre["collectionManifest"]["nodes"][0]["incremental"]
        self.assertGreaterEqual(receipt["confirmationReadStartedAt"], receipt["firstCleanCompletedAt"] + 5)

    def test_one_transport_failure_is_recovered_only_with_retained_checkpoints(self):
        failed = False
        def factory(*args):
            nonlocal failed
            if self.now == 15 and not failed:
                failed = True
                raise TimeoutError("transient")
            return self.factory(*args)
        self.assertEqual(self.run_monitor(factory), 0)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        problem = next(x for x in pre["collectionManifest"]["collectionIssues"] if x["reason"] == "source-read-failed")
        self.assertEqual(problem["severity"], "suspected")
        self.assertIn("resolvedAt", problem)

    def test_a_successful_read_does_not_clear_a_missing_file_gap(self):
        failed = False
        def factory(*args):
            nonlocal failed
            if self.now == 15 and not failed:
                failed = True
                raise TimeoutError("transient")
            identity = "1:2" if self.now >= 20 else "1:1"
            raw = line() * 2 if self.now >= 20 else b""
            return MemoryReader({identity: ("/var/log/varmor/violations.log", raw)})
        self.assertEqual(self.run_monitor(factory), 2)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertFalse(pre["collectionComplete"])
        self.assertTrue(any(x["reason"] == "active-file-disappeared" for x in pre["collectionManifest"]["collectionIssues"]))

    def test_same_uid_not_ready_flap_can_recover_but_end_inventory_must_be_ready(self):
        original = self.sleep
        def flap(seconds):
            original(seconds)
            ready = self.now != 15
            self.inventory["agents"][0]["ready"] = ready
            self.inventory["daemonSet"]["numberReady"] = 1 if ready else 0
        self.sleep = flap
        self.assertEqual(self.run_monitor(), 0)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertTrue(pre["collectionComplete"])
        self.assertTrue(all(x.get("resolvedAt") for x in pre["collectionManifest"]["collectionIssues"]))

    def test_multi_node_initialization_crossing_start_stops_before_later_nodes(self):
        self.inventory = fixtures.BuildManifestTests()._inventory(["n1", "n2"], 4)
        monitor.save(self.root / "inventory.json", self.inventory)
        visited = []
        owner = self
        class SlowReader(MemoryReader):
            def manifest(self):
                owner.now = 11
                return super().manifest()
        def factory(kube, namespace, agent, *args):
            visited.append(agent["node"])
            return SlowReader({"1:1": ("/var/log/varmor/violations.log", line(1) * 1000)})
        self.assertEqual(self.run_monitor(factory), 2)
        self.assertEqual(visited, ["n1"])
        self.assertIn("initialization", monitor.load(self.root / "run/collector.json")["errorReason"])

    def test_database_exception_records_failed_state_without_database_reentry_failure(self):
        def broken_database(con, *args, **kwargs):
            con.close()
            raise sqlite3.DatabaseError("synthetic db error")
        with patch.object(monitor, "scan", side_effect=broken_database):
            self.assertEqual(self.run_monitor(), 2)
        progress = monitor.load(self.root / "run/collector.json")
        self.assertEqual(progress["phase"], "failed")
        # The transaction exit itself reports the closed connection.
        self.assertEqual(progress["errorType"], "ProgrammingError")

    def test_missing_profile_stops_before_inventory_or_log_reads(self):
        self.policy.pop("status")
        with patch.object(self.kube, "inventory") as inventory:
            self.assertEqual(self.run_monitor(), 2)
            inventory.assert_not_called()
        progress = monitor.load(self.root / "run/collector.json")
        self.assertEqual(progress["phase"], "failed")
        self.assertIn("profileName", progress["errorReason"])
        self.assertFalse(progress["partialPreAvailable"])

    def test_missing_status_is_structured_and_claims_are_atomic(self):
        self.assertEqual(monitor.local_status(self.root / "not-started")["phase"], "not-started")
        self.assertEqual(self.run_monitor(), 0)
        task = self.root / "task.json"
        self.assertTrue(monitor.claim_task(task, "invocation-a")["claimed"])
        self.assertFalse(monitor.claim_task(task, "invocation-b")["claimed"])
        self.assertTrue(monitor.claim_task(task, "invocation-a")["resumed"])
        with self.assertRaises(common.ValidationError):
            monitor.claim_task(task, "invocation-b", release=True)
        monitor.claim_task(task, "invocation-a", release=True)
        self.assertTrue(monitor.claim_task(task, "invocation-b")["claimed"])

    def test_abandoned_claim_requires_authorized_owner_checked_reset_and_keeps_audit(self):
        self.assertEqual(self.run_monitor(), 0)
        path = self.root / "task.json"
        first = monitor.claim_task(path)
        self.assertTrue(first["claimed"])
        self.assertEqual(monitor.load(path)["analysisClaim"]["owner"], first["owner"])
        second = monitor.claim_task(path)
        self.assertFalse(second["claimed"])
        self.assertNotEqual(first["owner"], second["owner"])
        before = monitor.load(path)
        for expected, reason, authorized in ((first["owner"], "abandoned", False),
                                            ("wrong-owner", "abandoned", True),
                                            (first["owner"], " ", True)):
            with self.assertRaises(common.ValidationError):
                monitor.force_release_task(path, expected, reason, authorized)
            self.assertEqual(monitor.load(path), before)
        result = monitor.force_release_task(path, first["owner"], "Analysis session ended", True)
        self.assertEqual(result["status"], "collected")
        after = monitor.load(path)
        self.assertNotIn("analysisClaim", after)
        self.assertEqual(after["window"], before["window"])
        self.assertEqual(after["outputs"], before["outputs"])
        audit = after["analysisClaimHistory"][-1]
        self.assertEqual(audit["owner"], first["owner"])
        self.assertEqual(audit["claimedAt"], before["analysisClaim"]["claimedAt"])
        self.assertEqual(audit["reason"], "Analysis session ended")
        self.assertTrue(monitor.claim_task(path, second["owner"])["claimed"])
        with self.assertRaises(common.ValidationError):
            monitor.claim_task(path, first["owner"], release=True)
        # A reset based on an earlier observation cannot release a new owner.
        with self.assertRaises(common.ValidationError):
            monitor.force_release_task(path, first["owner"], "stale request", True)

    def test_force_release_restores_snapshot_and_refuses_later_decision_states(self):
        path = self.root / "task.json"
        with patch.object(monitor.time, "time", return_value=25):
            self.assertTrue(monitor.claim_task(path, "snapshot-owner")["claimed"])
            self.assertEqual(monitor.force_release_task(
                path, "snapshot-owner", "interrupted snapshot analysis", True)["status"], "observing")
            self.assertTrue(monitor.claim_task(path, "new-owner")["claimed"])
        task = monitor.load(path)
        task["status"] = "awaiting-decision"
        monitor.save(path, task)
        self.assertFalse(monitor.claim_task(path, "new-owner")["claimed"])
        with self.assertRaises(common.ValidationError):
            monitor.force_release_task(path, "new-owner", "already finished analysis", True)
        self.assertEqual(monitor.load(path)["status"], "awaiting-decision")

    def test_claim_cli_generates_owner_and_force_release_requires_explicit_authorization_flag(self):
        self.assertEqual(self.run_monitor(), 0)
        path = self.root / "task.json"
        command = [sys.executable, monitor.__file__]
        result = subprocess.run([*command, "claim", "--task", str(path)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = json.loads(result.stdout)
        self.assertTrue(first["claimed"])
        release = [*command, "force-release", "--task", str(path),
                   "--expected-owner", first["owner"], "--reason", "User approved recovery"]
        denied = subprocess.run(release, capture_output=True, text=True)
        self.assertNotEqual(denied.returncode, 0)
        self.assertEqual(monitor.load(path)["analysisClaim"]["owner"], first["owner"])
        reset = subprocess.run([*release, "--authorized-analysis-reset"], capture_output=True, text=True)
        self.assertEqual(reset.returncode, 0, reset.stderr)
        self.assertTrue(json.loads(reset.stdout)["released"])

    def test_deadline_runs_existing_preprocessor_and_preserves_task_decisions(self):
        self.assertEqual(self.run_monitor(), 0)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertTrue(pre["collectionComplete"])
        self.assertEqual(pre["collectionCounts"]["matched"], 2)
        self.assertEqual(len(pre["aggregatedEvents"]), 1)
        self.assertEqual(monitor.load(self.root / "task.json")["status"], "collected")
        self.assertEqual(monitor.load(self.root / "run/collector.json")["phase"], "finished")
        self.assertFalse((self.root / "run/2.1.6-candidate.yaml").exists())
        for path in (self.root / "run").rglob("*"):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_reader_failure_retains_partial_pre_and_blocks_deletions(self):
        def factory(*args):
            if self.now >= 15:
                raise common.ValidationError("stream interrupted")
            return self.factory(*args)
        self.assertEqual(self.run_monitor(factory), 2)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertFalse(pre["collectionComplete"])
        self.assertEqual(monitor.load(self.root / "run/collector.json")["phase"], "failed")

    def test_initialization_after_start_rejects_before_any_cluster_read(self):
        self.now = 11
        with patch.object(self.kube, "policy") as get:
            with self.assertRaisesRegex(common.ValidationError, "initialization is late"):
                self.run_monitor()
            get.assert_not_called()
        self.assertFalse((self.root / "run/2.1.4-pre.json").exists())

    def test_agent_restart_blocks_removal_even_if_node_name_is_unchanged(self):
        original = self.sleep
        def restart(seconds):
            original(seconds)
            if self.now >= 15:
                self.inventory["agents"][0]["uid"] = "replacement"
        self.sleep = restart
        self.assertEqual(self.run_monitor(), 2)
        self.assertFalse(monitor.load(self.root / "run/2.1.4-pre.json")["collectionComplete"])

    def test_agent_count_change_or_new_node_still_blocks_whole_policy_removals(self):
        baseline = copy.deepcopy(self.inventory)
        for expand in (False, True):
            with self.subTest(new_node=expand):
                self.now = 5
                self.args.output = str(self.root / ("run-new-node" if expand else "run-count"))
                self.inventory = copy.deepcopy(baseline)
                task = monitor.load(self.root / "task.json")
                task.update(status="observing", outputs={})
                monitor.save(self.root / "task.json", task)
                def scale(seconds):
                    self.now += seconds
                    if self.now >= 15:
                        if expand:
                            self.inventory = fixtures.BuildManifestTests()._inventory(["n1", "n2"], 4)
                        else:
                            self.inventory["daemonSet"]["desiredNumberScheduled"] = 2
                self.sleep = scale
                self.assertEqual(self.run_monitor(), 2)
                pre = monitor.load(Path(self.args.output) / "2.1.4-pre.json")
                self.assertFalse(pre["collectionComplete"])
                self.assertIn("agent-inventory-changed-or-incomplete",
                              [item["reason"] for item in pre["collectionManifest"]["collectionIssues"]])

    def test_policy_change_prevents_complete_result(self):
        original = self.sleep
        def change(seconds):
            original(seconds)
            if self.now >= 15:
                self.policy["metadata"]["generation"] = 2
        self.sleep = change
        self.assertEqual(self.run_monitor(), 2)
        self.assertFalse(monitor.load(self.root / "run/2.1.4-pre.json")["collectionComplete"])

    def test_expired_task_does_not_query_cluster(self):
        self.now = 21
        with self.assertRaises(common.ValidationError):
            self.run_monitor()
        self.assertFalse((self.root / "run/2.1.4-pre.json").exists())

    def test_only_one_collector_can_own_a_task_across_output_directories(self):
        with monitor.locked(self.root, "task.json.collector.lock"):
            with self.assertRaises(common.ValidationError):
                self.run_monitor()

    def test_early_close_is_acknowledged_and_runs_final_preprocessing(self):
        original = self.sleep
        def close(seconds):
            original(seconds)
            if self.now == 15:
                monitor.save(self.root / "run/close-request.json",
                             {"end": 15, "reason": "User completed the scenarios"})
        self.sleep = close
        self.assertEqual(self.run_monitor(), 0)
        task = monitor.load(self.root / "task.json")
        self.assertEqual(task["window"]["plannedEnd"], 20)
        self.assertEqual(task["window"]["end"], 15)
        self.assertEqual(monitor.load(self.root / "run/2.1.4-pre.json")["window"]["end"], 15)

    def test_resume_recovers_interruption_only_after_verified_checkpoint_catchup(self):
        self.interrupt_monitor()
        self.assertEqual(self.run_monitor(), 0)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertEqual(pre["collectionCounts"]["matched"], 2)
        self.assertTrue(pre["collectionComplete"])
        interrupted = [item for item in pre["collectionManifest"]["collectionIssues"]
                       if item["reason"] == "collector-interrupted"]
        self.assertEqual(len(interrupted), 1)
        self.assertEqual(interrupted[0]["node"], "n1")
        self.assertEqual(interrupted[0]["severity"], "suspected")
        self.assertGreaterEqual(interrupted[0]["resolvedAt"], 18)
        self.assertEqual(interrupted[0]["recoveryBasis"], "retained-file-checkpoints-and-drained-cursors")

    def test_resume_does_not_clear_disappeared_file(self):
        self.interrupt_monitor()
        def replacement(*args):
            return MemoryReader({"1:2": ("/var/log/varmor/violations.log", line() * 2)})
        self.assertEqual(self.run_monitor(replacement), 2)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertFalse(pre["collectionComplete"])
        self.assertIn("active-file-disappeared", [item["reason"]
                      for item in pre["collectionManifest"]["collectionIssues"]])
        self.assertTrue(any(item["reason"] == "collector-interrupted" and "resolvedAt" not in item
                            for item in pre["collectionManifest"]["collectionIssues"]))

    def test_resume_with_changed_agent_still_stops_before_new_log_reads(self):
        self.interrupt_monitor()
        self.inventory["agents"][0]["uid"] = "replacement"
        with patch.object(self, "factory") as factory:
            self.assertEqual(self.run_monitor(), 2)
            factory.assert_not_called()
        self.assertFalse(monitor.load(self.root / "run/2.1.4-pre.json")["collectionComplete"])

    def test_resume_cannot_use_a_later_created_file_as_the_interruption_checkpoint(self):
        self.interrupt_monitor(lambda *args: MemoryReader({}))
        self.assertEqual(self.run_monitor(), 2)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertFalse(pre["collectionComplete"])
        interrupted = next(item for item in pre["collectionManifest"]["collectionIssues"]
                           if item["reason"] == "collector-interrupted")
        self.assertEqual(interrupted["checkpoints"], [])
        self.assertNotIn("resolvedAt", interrupted)

    def test_resume_requires_checkpoints_for_every_node(self):
        self.inventory = fixtures.BuildManifestTests()._inventory(["n1", "n2"], 4)
        monitor.save(self.root / "inventory.json", self.inventory)
        def factory(*args):
            return self.factory(*args) if args[2]["node"] == "n1" else MemoryReader({})
        self.interrupt_monitor(factory)
        self.assertEqual(self.run_monitor(factory), 2)
        pre = monitor.load(self.root / "run/2.1.4-pre.json")
        self.assertFalse(pre["collectionComplete"])
        interrupted = {item["node"]: item for item in pre["collectionManifest"]["collectionIssues"]
                       if item["reason"] == "collector-interrupted"}
        self.assertIn("resolvedAt", interrupted["n1"])
        self.assertNotIn("resolvedAt", interrupted["n2"])

    def test_resume_cannot_change_limits_or_extend_window(self):
        class Crash(BaseException):
            pass
        def crash(seconds):
            raise Crash()
        self.sleep = crash
        with self.assertRaises(Crash):
            self.run_monitor()
        self.args.max_read_mb = 8
        with self.assertRaises(common.ValidationError):
            self.run_monitor()
        self.args.max_read_mb = 2
        task = monitor.load(self.root / "task.json")
        task["window"]["end"] = 30
        monitor.save(self.root / "task.json", task)
        with self.assertRaises(common.ValidationError):
            self.run_monitor()

    def test_existing_snapshot_artifacts_are_not_overwritten(self):
        run = self.root / "run"
        run.mkdir()
        old = run / "2.1.1-current.yaml"
        old.write_text("reviewed policy")
        with self.assertRaises(common.ValidationError):
            self.run_monitor()
        self.assertEqual(old.read_text(), "reviewed policy")

    def test_ready_requires_process_lease_and_current_heartbeat(self):
        run = self.root / "run"
        run.mkdir()
        now = time.time()
        status = {"phase": "ready", "processId": os.getpid(), "startedAt": now,
                  "lastHeartbeatAt": now, "window": {"start": now, "end": now + 600},
                  "plan": {"interval": 30, "requestTimeout": 30}}
        monitor.save(run / "collector.json", status)
        with monitor.locked(run):
            self.assertTrue(monitor.local_status(run)["readyForWindow"])
            status["lastHeartbeatAt"] = now - 1000
            monitor.save(run / "collector.json", status)
            self.assertFalse(monitor.local_status(run)["readyForWindow"])
        status["lastHeartbeatAt"] = time.time()
        monitor.save(run / "collector.json", status)
        self.assertFalse(monitor.local_status(run)["readyForWindow"])


class RemoteReaderTests(unittest.TestCase):
    """Execute the remote sh snippets locally with real tail/head/gzip tools.

    A portable stat shim emulates GNU stat on the macOS development host. No
    actual kubectl or host audit file is used.
    """
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.logs = self.root / "logs with spaces $literal"
        self.logs.mkdir()
        (self.logs / "violations.log").write_bytes(line() * 2)
        (self.logs / "violations-old.log.gz").write_bytes(gzip.compress(line(8)))
        binary = self.root / "bin"
        binary.mkdir()
        stat = binary / "stat"
        stat.write_text("#!" + sys.executable + "\nimport os, sys\n"
                        "s=os.stat(sys.argv[-1])\n"
                        "f=sys.argv[2]\n"
                        "print(str(s.st_dev)+':'+str(s.st_ino) if f=='%d:%i' else "
                        "str(s.st_size)+':'+str(s.st_mtime_ns)+':'+str(s.st_ctime_ns) if f=='%s:%y:%z' else s.st_size)\n")
        stat.chmod(0o700)
        class Kube:
            uid = "agent-uid"
            transfer_budget = None
            audit_call = monitor.Kubernetes.audit_call
            calls = []
            def call(self, *args):
                self.calls.append(args)
                if args[0] == "get":
                    return json.dumps({"metadata": {"uid": self.uid}}).encode()
                cmd = list(args[args.index("--") + 1:])
                result = subprocess.run(cmd, capture_output=True, timeout=5,
                        env={**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"]})
                if result.returncode:
                    raise common.ValidationError("local fixture exec failed: " + result.stderr.decode())
                return result.stdout
        self.kube = Kube()
        self.binary = binary
        self.reader = monitor.AgentReader(self.kube, "varmor", {"pod": "agent", "uid": "agent-uid"},
                                          "agent-container", str(self.logs))

    def test_actual_shell_lists_plain_and_gzip_files_and_reads_exact_byte_ranges(self):
        files = self.reader.manifest()
        self.assertEqual(len(files), 2)
        active = next(entry for entry in files.values() if entry["path"].endswith("violations.log"))
        archive = next(entry for entry in files.values() if entry["path"].endswith(".gz"))
        self.assertEqual(active["size"], len(line()) * 2)
        self.assertEqual(self.reader.read(active, len(line()), len(line())), line())
        self.assertEqual(self.reader.read(archive, 3, 20), line(8)[3:23])
        self.assertEqual(archive["size"], len(line(8)))

    def test_name_reused_by_another_agent_is_rejected_before_log_read(self):
        self.kube.uid = "replacement"
        with self.assertRaises(common.ValidationError):
            self.reader.manifest()

    def test_corrupt_compressed_archive_fails_instead_of_appearing_empty(self):
        (self.logs / "violations-old.log.gz").write_bytes(b"not-gzip")
        with self.assertRaises(common.ValidationError):
            files = self.reader.manifest()
            entry = next(entry for entry in files.values() if entry["path"].endswith(".gz"))
            self.reader.read(entry, 0, 1)

    def test_log_symlink_is_rejected_during_listing_and_after_listing(self):
        target = self.root / "outside.log"
        target.write_bytes(line())
        active = self.logs / "violations.log"
        active.unlink()
        active.symlink_to(target)
        with self.assertRaises(common.ValidationError):
            self.reader.manifest()
        active.unlink()
        active.write_bytes(line())
        files = self.reader.manifest()
        entry = next(item for item in files.values() if item["path"] == str(active))
        active.unlink()
        active.symlink_to(target)
        with self.assertRaises(common.ValidationError):
            self.reader.read(entry, 0, 1)

    def test_drained_gzip_backup_is_metadata_only_and_active_read_uses_one_batch(self):
        gzip_binary = shutil.which("gzip")
        counter = self.root / "gzip-calls.txt"
        shim = self.binary / "gzip"
        shim.write_text("#!" + sys.executable + "\nimport subprocess, sys\n"
                        "with open(" + repr(str(counter)) + ", 'a') as f: f.write('call\\n')\n"
                        "sys.exit(subprocess.call([" + repr(gzip_binary) + ", *sys.argv[1:]]))\n")
        shim.chmod(0o700)
        with monitor.database(self.root) as con:
            monitor.scan(con, "n1", self.reader, 2 * 1024 * 1024, 5)
            gzip_calls = counter.read_text().splitlines()
            execs = sum(args[0] == "exec" for args in self.kube.calls)
            monitor.scan(con, "n1", self.reader, 2 * 1024 * 1024, 15)
            self.assertEqual(counter.read_text().splitlines(), gzip_calls)
            self.assertEqual(sum(args[0] == "exec" for args in self.kube.calls) - execs, 2)
            self.assertEqual(con.execute("SELECT count(*) FROM records").fetchone()[0], 3)

    def test_real_budget_wrapper_keeps_paths_literal_and_records_actual_stdout(self):
        self.kube.transfer_budget = monitor.TransferBudget(self.root, 16 * 1024 * 1024)
        files = self.reader.manifest()
        entry = next(entry for entry in files.values() if entry["path"].endswith("violations.log"))
        self.assertEqual(self.reader.read(entry, 0, len(line())), line())
        self.assertGreater(self.kube.transfer_budget.summary()["totalBytes"], len(line()))

    def test_empty_readable_directory_is_valid_but_seen_active_disappearance_is_a_gap(self):
        (self.logs / "violations.log").unlink()
        (self.logs / "violations-old.log.gz").unlink()
        with monitor.database(self.root) as con:
            _, receipt = monitor.scan(con, "n1", self.reader, 2 * 1024 * 1024, 5)
            self.assertEqual(receipt["coveredFrom"], 5)
            (self.logs / "violations.log").write_bytes(line())
            monitor.scan(con, "n1", self.reader, 2 * 1024 * 1024, 15)
            (self.logs / "violations.log").unlink()
            monitor.scan(con, "n1", self.reader, 2 * 1024 * 1024, 20)
            self.assertIn("active-file-disappeared", [item["reason"] for item in monitor.issues(con)])


class TransferTests(unittest.TestCase):
    def test_failed_reservation_survives_restart_and_quota_releases_only_after_60_seconds(self):
        with tempfile.TemporaryDirectory() as root:
            now = [5]
            budget = monitor.TransferBudget(root, 2 * 1024 * 1024, lambda: now[0])
            budget.reserve(2 * 1024 * 1024)  # Simulate a failed transfer/crash without finish.
            recovered = monitor.TransferBudget(root, 2 * 1024 * 1024, lambda: now[0])
            with self.assertRaises(monitor.TransferPressure):
                recovered.reserve(65536)
            now[0] = 65
            key, _ = recovered.reserve(65536)
            recovered.finish(key, 128)
            self.assertEqual(recovered.summary()["windowBytes"], 128)

    def test_supplied_oversized_response_cannot_erase_a_reservation(self):
        with tempfile.TemporaryDirectory() as root:
            budget = monitor.TransferBudget(root, 2 * 1024 * 1024)
            key, cap = budget.reserve(65536)
            with self.assertRaises(monitor.EvidenceError):
                budget.finish(key, cap + 1)
            self.assertEqual(budget.summary()["windowBytes"], cap)


class KubernetesContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        binary = self.root / "bin"
        binary.mkdir()
        shutil.copyfile(Path(__file__).parent / "fixtures/fake_kubectl.py", binary / "kubectl")
        (binary / "kubectl").chmod(0o700)
        helper = fixtures.AgentInventoryTests()
        pod = helper._pod("agent-a", "n1")
        pod["kind"] = "Pod"
        cluster_policy = live_policy()
        cluster_policy["kind"] = "VarmorClusterPolicy"
        cluster_policy["metadata"].pop("namespace")
        self.config = {"context": "fixture-context", "policy": live_policy(), "clusterPolicy": cluster_policy,
                       "pod": pod, "inventory": {"kind": "List", "items": [helper._daemonset(1, 1, 1), pod]}}
        monitor.save(self.root / "config.json", self.config)
        self.env = {**os.environ, "PATH": str(binary) + os.pathsep + os.environ["PATH"],
                    "VOPT_TEST_CONFIG": str(self.root / "config.json"), "VOPT_TEST_CALLS": str(self.root / "calls.jsonl")}
        self.kube = monitor.Kubernetes("fixture-context", 3)

    def calls(self):
        return [json.loads(line) for line in (self.root / "calls.jsonl").read_text().splitlines()]

    def test_real_subprocess_pins_context_and_policy_scope_and_preserves_binary_exec(self):
        with patch.dict(os.environ, self.env, clear=True):
            self.kube.policy({"kind": "VarmorPolicy", "name": "demo", "namespace": "app"})
            self.kube.policy({"kind": "VarmorClusterPolicy", "name": "demo", "namespace": ""})
            self.assertTrue(self.kube.inventory("varmor", "varmor-agent")["inventoryComplete"])
            raw = self.kube.call("exec", "-n", "varmor", "agent-a", "-c", "agent-container", "--",
                                 "sh", "-c", "printf '\\377\\000'")
        self.assertEqual(raw, b"\xff\x00")
        calls = self.calls()
        self.assertTrue(all(call[:2] == ["--context", "fixture-context"] for call in calls))
        self.assertIn("-n", calls[0])
        self.assertEqual(calls[0][calls[0].index("-n") + 1], "app")
        self.assertNotIn("-n", calls[1])
        self.assertEqual(calls[-1][calls[-1].index("-c") + 1], "agent-container")

    def test_failed_subprocess_redacts_remote_error_and_expired_deadline_does_not_dispatch(self):
        self.config["fail"] = True
        monitor.save(self.root / "config.json", self.config)
        with patch.dict(os.environ, self.env, clear=True):
            with self.assertRaises(common.ValidationError) as result:
                self.kube.call("get", "vpol", "demo")
            self.assertNotIn("synthetic-private", str(result.exception))
            self.kube.deadline = time.monotonic() - 1
            with self.assertRaises(TimeoutError):
                self.kube.call("get", "vpol", "demo")
        self.assertEqual(len(self.calls()), 1)


if __name__ == "__main__":
    unittest.main()
