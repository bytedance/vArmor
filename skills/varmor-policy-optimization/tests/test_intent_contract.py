# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Contract tests for progressive interaction in the policy optimization Skill."""

import json
from pathlib import Path
import unittest


SKILL_ROOT = Path(__file__).resolve().parents[1]


class IntentContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        cls.author = (
            SKILL_ROOT / "playbooks" / "author-policy.md"
        ).read_text(encoding="utf-8")
        cls.optimize = (
            SKILL_ROOT / "playbooks" / "optimize-policy.md"
        ).read_text(encoding="utf-8")
        cls.contract = (
            SKILL_ROOT / "playbooks" / "README.md"
        ).read_text(encoding="utf-8")
        cls.loop = (
            SKILL_ROOT / "references" / "optimization-loop.md"
        ).read_text(encoding="utf-8")
        cls.task = json.loads(
            (SKILL_ROOT / "templates" / "observation-task.json").read_text(
                encoding="utf-8"
            )
        )

    def test_workflow_is_introduced_before_execution_details(self):
        self.assertIn("## Two asynchronous phases", self.skill)
        self.assertIn("they do not need to run linearly in one invocation", self.skill)
        self.assertIn("Expand phase-specific details only after entering that phase", self.skill)
        self.assertIn("Defer commands, artifacts, and fail-closed conditions until the relevant execution step", self.skill)

    def test_preflight_is_suggested_but_requires_user_selection(self):
        self.assertIn("Pre-submission preflight", self.author)
        self.assertIn("all checks, selected items, or skip", self.author)
        self.assertIn("run the corresponding queries according to that choice", self.author)
        self.assertIn("cluster-verified / user-provided / not-checked", self.author)
        self.assertIn("If the user skipped preflight", self.author)
        self.assertIn("read and confirm the target context", self.author)

    def test_policy_is_user_supplied_and_not_proactively_designed(self):
        self.assertIn("Policy content should come primarily from the user", self.author)
        self.assertIn("does not extend into designing a complete rule set", self.author)
        self.assertIn("Do not query the cluster or expand rules on the user's behalf", self.author)
        self.assertIn("without rewriting the user's original file", self.author)
        self.assertIn(
            'install -m 600 -- "$SOURCE_POLICY" "$RUN_DIR/1.1.3-draft.yaml"',
            self.author,
        )
        self.assertNotIn("Optional rule suggestions", self.author)
        self.assertNotIn("Recommended rules", self.skill)

    def test_optimization_stops_after_attribution(self):
        self.assertIn(
            "entered independently in a new invocation or session",
            self.optimize,
        )
        self.assertIn(
            "collection -> attribution report -> user decision -> candidate -> confirmed update",
            self.optimize,
        )
        self.assertIn("#### Attribution report", self.optimize)
        self.assertIn("After reporting, ask whether the user wants deletion, retention, or continued", self.optimize)
        self.assertIn("Stay in this section until the user provides", self.optimize)
        self.assertIn("the deletion scope; do not generate post-Seccomp, candidate, or guard diff beforehand", self.optimize)
        self.assertIn(
            "obtain the user's deletion-scope decision before generating a candidate policy",
            self.author,
        )

    def test_collection_reads_one_batch_timestamp(self):
        self.assertEqual(
            self.optimize.count('COLLECTION_STARTED_AT="$(date +%s)"'),
            1,
        )
        self.assertIn(
            "record `COLLECTION_STARTED_AT` only once for the entire node batch and reuse it",
            self.contract,
        )
        self.assertIn(
            "Subsequent nodes reuse that value without repeated",
            self.optimize,
        )
        self.assertIn(
            "This branch reuses `WINDOW_END` and `COLLECTION_STARTED_AT` established before node traversal in 2.1.3",
            self.optimize,
        )

    def test_shell_safeguards_are_selected_not_mechanical_prefixes(self):
        self.assertIn("Choose shell safeguards according to command structure", self.contract)
        self.assertIn("Do not mechanically prefix every simple query", self.contract)
        self.assertIn("explicit permission restriction", self.contract)
        examples = self.author + self.optimize
        self.assertLessEqual(examples.count("set -euo pipefail"), 2)
        self.assertLessEqual(examples.count("umask 077"), 2)

    def test_task_record_is_the_entry_point_regardless_of_scheduler(self):
        self.assertIn("Successfully persisting the task record establishes this optimization task", self.author)
        self.assertIn("Scheduled tasks, reminders, or manual continuation", self.skill)
        self.assertIn("Input is the absolute path to one or more task records", self.optimize)
        self.assertIn("every\ntrigger", self.contract)
        self.assertIn("common entry point", self.contract)
        self.assertEqual(self.task["status"], "observing")
        self.assertIn("taskId", self.task)
        self.assertEqual(self.task["window"]["plannedEnd"], self.task["window"]["end"])
        self.assertEqual(self.task["window"]["endReason"], "planned")
        self.assertIn("trigger", self.task)
        self.assertEqual(self.task["lastTrigger"]["mode"], "none")
        self.assertIn("outputs", self.task)

    def test_async_batch_tasks_have_stable_external_names(self):
        self.assertIn("One invocation can process multiple policies or task records", self.skill)
        self.assertIn("independent run directory and task record for each policy", self.author)
        self.assertIn("One invocation may process multiple tasks", self.optimize)
        self.assertIn("Task records belong in a persistent task directory, outside phase artifacts", self.contract)
        self.assertIn("The model may choose another persistent location and equivalent naming", self.contract)
        self.assertIn(
            "vpol-<namespace>-<name>--<start>--<plannedEnd>.json",
            self.contract,
        )
        self.assertIn(
            "vcpol-<name>--<start>--<plannedEnd>.json",
            self.contract,
        )
        self.assertNotIn("1.7-observation-task.json", self.skill + self.author + self.optimize)

    def test_window_can_close_early_before_collection(self):
        self.assertIn("explicitly states application operations are complete and requests early analysis", self.optimize)
        self.assertIn("keep `plannedEnd` unchanged", self.optimize)
        self.assertIn("Do not suggest a separate future short window", self.optimize)
        self.assertIn("Once formal collection starts", self.optimize)
        self.assertIn("Once collection starts, scope is fixed", self.loop)

    def test_candidate_replace_is_verified_against_live_spec(self):
        self.assertIn('kubectl --context "$CTX" replace', self.optimize)
        self.assertIn("--verify-live", self.optimize)
        self.assertIn("2.1.8-post-replace.yaml", self.optimize)
        self.assertIn("live spec differing from candidate", self.contract)


if __name__ == "__main__":
    unittest.main()
