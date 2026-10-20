# Automated Policy Optimization

English | [简体中文](README.zh_CN.md)

This skill helps an AI assistant refine [vArmor](https://www.varmor.org/) policies, reducing business disruption and the effort of manual policy tuning. Start with a relatively strict **EnhanceProtect** policy aligned with your security goals, then use real business observations to refine it over successive rounds.

The assistant helps deploy the policy in observation mode and continuously collect violation logs during an agreed window. It maps events to actual rules and explains conflicts with required business behavior. You choose removals, review the validated candidate, and authorize the update. Repeated observation and adjustment gradually bring the policy closer to the application's needs.

## How it works

1. **Choose the initial policy:** provide YAML, or have the assistant prepare a relatively strict draft from your confirmed target, enforcer, and security requirements.
2. **Start observation:** review and authorize deployment, agree on a window, and let the assistant save starting evidence and initialize collection before the window begins.
3. **Exercise the application:** after collection is ready, trigger representative behavior such as startup, normal requests, retries, recovery, and scheduled jobs to capture actual business needs.
4. **Review and refine:** the assistant explains violations and rule attribution. Choose removal, retention, or further observation, then review the candidate and approve any update.
5. **Repeat:** observe the revised policy in a new window until agreed scenarios are covered and no further confirmed business conflicts need adjustment. Convergence depends on coverage, not event counts alone.

**Scope:** EnhanceProtect policies using namespaced `VarmorPolicy` or cluster-scoped `VarmorClusterPolicy`, refined by deleting existing rules. This skill does not optimize DefenseInDepth policies or generate BehaviorModeling models.

BehaviorModeling output can supply allowlist Profiles for DefenseInDepth, which also accepts custom Profiles; see the [official policy modes](https://www.varmor.org/docs/v0.10/guides/policies_and_rules/policy_modes/). Its behavior data can also help select EnhanceProtect rules through the official [Policy Advisor](https://varmor.org/docs/v0.10/guides/policy_tools/policy_advisor/). This skill refines EnhanceProtect policies from observation logs without requiring a prior modeling phase.

## What to prepare

You can ask about the workflow without running commands or connecting to a cluster. Execution requires:

| Task | Requirements |
|---|---|
| Local policy validation or draft preparation | A skill-capable assistant that can run local commands; Python 3 and PyYAML. No cluster connection is needed for local validation. |
| Live observation | A working vArmor installation, a known cluster context, configured `kubectl`, and read access to the policy, agents, and logs. The installed version and enforcer capabilities are checked for the selected rules. |
| Continuous collection | A Unix-like local environment with Python SQLite support, persistent writable storage, and a process that can stay running throughout the window. Authorized read-only agent exec access is needed. |
| Agent log reads | The confirmed log directory and `sh`, compatible `stat -L -c`, `tail`, and `head` in the agent; `gzip` and `wc` when compressed backups are present. |
| Policy creation or update | Permission to create/update the selected policy resource, plus your authorization for the reviewed change. This is separate from read access. |

Install PyYAML in the Python environment used by the assistant if needed: `python3 -m pip install -r requirements.txt` from this skill directory. The skill does not install dependencies automatically.

Provide the policy YAML or intended workload, **context and namespace**, and business scenarios. You manage workloads and Pods; the assistant explains required recreation or rollout and reviews policy settings that may trigger workload updates.

## Install and start

Copy the complete `varmor-policy-optimization/` directory into your assistant's skills directory. Keep `SKILL.md`, `references/`, `playbooks/`, `scripts/` including data files, and `templates/` together. For other skill-compatible assistants, use their corresponding skills directory.

| Assistant | User-level directory | Project directory |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `<project>/.claude/skills/` |
| Codex | `~/.agents/skills/` | `<project>/.agents/skills/` |

For a Codex user-level installation, replace `/ABS/varmor-policy-optimization` with the actual source directory:

```sh
mkdir -p ~/.agents/skills
cp -R /ABS/varmor-policy-optimization ~/.agents/skills/
```

When updating, replace the existing skill copy rather than nesting another directory inside it. See the [Claude Code instructions](https://code.claude.com/docs/en/skills) and [Codex instructions](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills) for installation locations and invocation. Codex paths follow the current documentation; check the discovery paths for your release when using an older version.

Use `/varmor-policy-optimization` in Claude Code or `$varmor-policy-optimization` in Codex CLI/IDE, followed by your request. You can also name the skill in plain language. If it is not discovered, ask the assistant to read the installed `SKILL.md` by absolute path. Script commands are handled by the assistant.

**Check an existing YAML locally:**

> Use varmor-policy-optimization to review ./checkout-policy.yaml for an EnhanceProtect observation. Explain validation findings, changes needed, and rules that could still block business activity. Do not connect to a cluster or deploy it.

**Prepare a policy when you do not have YAML:**

> Use varmor-policy-optimization to prepare an EnhanceProtect observation policy for Deployment checkout in namespace shop, context staging. Explain the enforcer and rule choices first, and draft it from my confirmed requirements. Do not deploy yet.

**Establish an observation task:**

> Use varmor-policy-optimization with ./checkout-policy.yaml in context staging. Help me plan an observation covering startup, normal requests, retries, and scheduled jobs. Show the policy changes and collection plan for confirmation before starting.

**Return to an existing task, including in another conversation:**

> Use varmor-policy-optimization to continue the task at /absolute/path/task.json. Check collection status and analyze the evidence when ready. Report rule attribution first; wait for my removal choices and final update approval.

## Observation and update considerations

The assistant handles validation, collection, attribution, and candidate checks. You confirm security goals, exercise business scenarios, and choose removals. Before updating, it presents the candidate and deletion diff, runs server-side validation, and waits for your final approval of the target cluster and change.

**Observation is not guaranteed to be non-blocking.** Built-in rules and the baseline are observed, but custom RawRules retain their configured actions and may still deny activity. Review these effects before running traffic.

Removal preserves policy scope, mode, enforcer, privilege and observation settings; it does not switch to blocking mode. Seccomp or injection changes may require new containers. Coordinate their lifecycle and test the business afterward.

## Collection, continuation, and results

New tasks normally collect every 30 seconds. Default budgets, shared across all task nodes, are 4 MiB of processing per round and 16 MiB of audit exec stdout per rolling minute. Local storage has a 512 MiB stop threshold. The assistant explains agreed limits; API and protocol overhead are excluded from the stdout budget.

Keep the collector host running and save the **task's absolute path and referenced artifact directories**. At the deadline, it confirms reads and prepares data; it does not call the model or send notifications. Return to request analysis or arrange a host automation separately. You can request an early end after business testing.

If a persistent collector is unavailable, the assistant can explain the snapshot fallback and its rotation limits. It cannot recover logs already overwritten or create missing starting evidence after the fact.

Results include the task, coverage findings, attribution, and review decisions. Approved removals also produce candidate YAML, the deletion diff, an analysis report, and verification and rollback guidance. Uncertain matches are retained.

## Coverage matters

- Exercise representative behavior; a quiet log or fewer events alone does not prove the policy is suitable or secure.
- Node scaling, agent replacement, or agent DaemonSet scheduling-count changes block whole-policy deletions for that window. Existing evidence remains available for read-only analysis; establish a new window after the topology stabilizes.
- An interruption can recover only when the original identities and file checkpoints prove continuity. Unrecoverable gaps or policy drift block deletion.
- NetworkProxy rule removal requires eligible node logs on vArmor v0.10.3+ with runc. Unknown/older versions and micro-VM evidence do not qualify for NetworkProxy deletion in this workflow.

For troubleshooting an existing failure, use [Automated Diagnosis](../varmor-diagnosis/README.md).

## Further reading

- [SKILL.md](SKILL.md): instructions for the assistant.
- [Incremental collection](references/incremental-collection.md): startup, budgets, interruption recovery, and abandoned analysis tasks.
- [Policy semantics](references/enhance-protect-semantics.md): observation, custom rules, and the implicit baseline.

<!-- package:source-only:start -->
## Maintainer notes

### Install from source

Run from this skill directory; Python 3.9+ is required for the delivery tools:

```sh
python3 install.py --tool codex --project /ABS/PROJECT
python3 install.py --tool both
```

The installer creates relative symbolic links to the source, using `.agents/skills/`
for Codex and `.claude/skills/` for Claude Code at the selected project or home
directory. It refuses to overwrite another installation and does not install
dependencies. Keep the source directory in place while using these links.

### Build distribution packages

```sh
python3 package.py
python3 package.py --full
python3 package.py --output /ABS/RELEASE/varmor-policy-optimization-skill.zip
```

The default outputs are `dist/varmor-policy-optimization-skill.zip` (runtime resources,
bilingual guides, and license) and `dist/varmor-policy-optimization-full.zip` (also includes
the installer, packager, and regression tests). Both extract to `varmor-policy-optimization/`.
The slim package omits these maintainer notes. Packaging uses explicit file lists,
excludes unlisted local evidence, sessions, caches, and archives, and replaces an
existing ZIP only after a successful build. Identical inputs produce identical bytes
in the same Python/zlib environment. Update the lists in `package.py` when adding
resources or tests; publish ZIPs as release attachments rather than committing them.

### Run regression tests

From this skill directory, in either repository or an extracted full package:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v
```

Tests live directly in this skill's `tests/` directory in both repositories.

These tests use local fixtures and do not connect to a cluster. They check script
behavior, portable packages, and installation collision handling.
<!-- package:source-only:end -->

## License

Apache-2.0; see [LICENSE](LICENSE).
