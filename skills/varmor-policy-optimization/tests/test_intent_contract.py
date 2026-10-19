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
        self.assertIn("## 两个异步阶段", self.skill)
        self.assertIn("不要求在一次调用中线性完成", self.skill)
        self.assertIn("进入阶段后再展开该阶段细节", self.skill)
        self.assertIn("命令、产物和失败关闭条件留到相应执行步骤说明", self.skill)

    def test_preflight_is_suggested_but_requires_user_selection(self):
        self.assertIn("下发前预检", self.author)
        self.assertIn("全部、指定项目或跳过", self.author)
        self.assertIn("按用户选择运行相应查询", self.author)
        self.assertIn("cluster-verified / user-provided / not-checked", self.author)
        self.assertIn("用户跳过预检时", self.author)
        self.assertIn("读取并确认目标 context", self.author)

    def test_policy_is_user_supplied_and_not_proactively_designed(self):
        self.assertIn("策略内容优先来自用户", self.author)
        self.assertIn("不延伸为设计一整套规则", self.author)
        self.assertIn("不替用户扩充规则", self.author)
        self.assertIn("不改写用户原文件", self.author)
        self.assertIn(
            'install -m 600 -- "$SOURCE_POLICY" "$RUN_DIR/1.1.3-draft.yaml"',
            self.author,
        )
        self.assertNotIn("可选规则建议", self.author)
        self.assertNotIn("推荐规则", self.skill)

    def test_optimization_stops_after_attribution(self):
        self.assertIn(
            "可以在新的调用或会话中独立进入",
            self.optimize,
        )
        self.assertIn(
            "采集 → 归因汇报 → 用户决定 → 候选 → 确认更新",
            self.optimize,
        )
        self.assertIn("#### 归因汇报", self.optimize)
        self.assertIn("汇报后询问用户希望删除、保留还是继续", self.optimize)
        self.assertIn("在用户给出", self.optimize)
        self.assertIn("删除范围前停留在本节", self.optimize)
        self.assertIn(
            "取得删除范围决定后，再生成候选策略",
            self.author,
        )

    def test_collection_reads_one_batch_timestamp(self):
        self.assertEqual(
            self.optimize.count('COLLECTION_STARTED_AT="$(date +%s)"'),
            1,
        )
        self.assertIn(
            "整批节点采集只记录一次 `COLLECTION_STARTED_AT` 并复用",
            self.contract,
        )
        self.assertIn(
            "后续节点复用该值，不重复",
            self.optimize,
        )
        self.assertIn(
            "本分支复用 2.1.3 在节点遍历前确定的",
            self.optimize,
        )

    def test_shell_safeguards_are_selected_not_mechanical_prefixes(self):
        self.assertIn("根据命令结构选择 shell 保护", self.contract)
        self.assertIn("不为每条简单查询机械添加这些前缀", self.contract)
        self.assertIn("显式权限收敛", self.contract)
        examples = self.author + self.optimize
        self.assertLessEqual(examples.count("set -euo pipefail"), 2)
        self.assertLessEqual(examples.count("umask 077"), 2)

    def test_task_record_is_the_entry_point_regardless_of_scheduler(self):
        self.assertIn("任务记录成功落盘即表示本轮优化任务", self.author)
        self.assertIn("定时任务、提醒或用户手动触发", self.skill)
        self.assertIn("输入是一份或多份任务记录的绝对路径", self.optimize)
        self.assertIn("所有触发方式的", self.contract)
        self.assertIn("统一入口", self.contract)
        self.assertEqual(self.task["status"], "observing")
        self.assertIn("taskId", self.task)
        self.assertEqual(self.task["window"]["plannedEnd"], self.task["window"]["end"])
        self.assertEqual(self.task["window"]["endReason"], "planned")
        self.assertIn("trigger", self.task)
        self.assertEqual(self.task["lastTrigger"]["mode"], "none")
        self.assertIn("outputs", self.task)

    def test_async_batch_tasks_have_stable_external_names(self):
        self.assertIn("一次调用可以处理多份策略或多个任务记录", self.skill)
        self.assertIn("每份策略使用独立运行目录和任务记录", self.author)
        self.assertIn("一次调用可处理多个任务", self.optimize)
        self.assertIn("任务记录位于持久任务目录，不属于阶段产物", self.contract)
        self.assertIn("模型也可选择其他持久位置和等价命名", self.contract)
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
        self.assertIn("明确表示业务操作已完成并要求提前进行", self.optimize)
        self.assertIn("保持 `plannedEnd` 不变", self.optimize)
        self.assertIn("不要另行建议一个未来的短窗口", self.optimize)
        self.assertIn("一旦正式采集开始", self.optimize)
        self.assertIn("采集开始后范围固定", self.loop)

    def test_candidate_replace_is_verified_against_live_spec(self):
        self.assertIn('kubectl --context "$CTX" replace', self.optimize)
        self.assertIn("--verify-live", self.optimize)
        self.assertIn("2.1.8-post-replace.yaml", self.optimize)
        self.assertIn("线上 spec 与 candidate 不一致", self.contract)


if __name__ == "__main__":
    unittest.main()
