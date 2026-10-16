# vArmor Diagnosis

English | [简体中文](README.zh_CN.md)

This skill helps an AI assistant troubleshoot configuration, protection, and runtime issues in [vArmor](https://www.varmor.org/). Describe symptoms such as a Ready policy that seems ineffective, unexpected permission errors, or Pods that fail to start, and the assistant helps investigate the cause.

It combines vArmor's protection model with actual cluster evidence, following target matching, Profile generation, Pod injection, node loading, and runtime enforcement. By connecting policy state, events, and logs, it distinguishes missing protection, rule denials, and application failures. You do not need to know every component or correlate the queries yourself.

## How it works

1. **Describe the problem:** share a known application, Pod, policy, or node, with the symptom and approximate time.
2. **Gather relevant evidence:** the assistant checks status, events, and logs, following clues and adding container or node checks when needed.
3. **Identify the cause:** it compares configuration with runtime results and explains confirmed findings, affected scope, and missing evidence.
4. **Plan the next step:** receive recommended fixes and verification steps, with a formal report when requested.

Coverage includes policies, Profiles, webhooks, vArmor components, BehaviorModeling, and NetworkProxy. **Diagnosis is read-only:** it does not change policies, restart workloads, or modify nodes.

## What to prepare

| What you want to do | Requirements |
|---|---|
| Discuss a problem or analyze existing material | A skill-capable assistant and the relevant configuration, status, events, or log excerpts. Cluster access is optional. |
| Investigate a live cluster | An assistant that can run commands; `kubectl` configured for the target context; permission to read relevant resources, events, and logs. |
| Use the optional helper scripts | Python 3. The scripts use the standard library and require no additional Python packages. |
| Inspect a container or node, or run a connectivity probe | Access and authorization for that specific operation. These checks are used only when needed. |

Provide the **cluster context, namespace, one known target, symptom, and approximate failure time** when available. A target can be a Pod, workload, policy, or node. Include the vArmor version and recent changes if you know them; the assistant can discover missing names and relationships.

## Install and start

Copy the complete `varmor-diagnosis/` directory into your assistant's skills directory. Keep `SKILL.md`, `references/`, `playbooks/`, `scripts/` including data files, and `templates/` together. For other skill-compatible assistants, use their corresponding skills directory.

| Assistant | User-level directory | Project directory |
|---|---|---|
| Claude Code | `~/.claude/skills/` | `<project>/.claude/skills/` |
| Codex | `~/.agents/skills/` | `<project>/.agents/skills/` |

For a Codex user-level installation, replace `/ABS/varmor-diagnosis` with the actual source directory:

```sh
mkdir -p ~/.agents/skills
cp -R /ABS/varmor-diagnosis ~/.agents/skills/
```

When updating, replace the existing skill copy rather than nesting another directory inside it. See the [Claude Code instructions](https://code.claude.com/docs/en/skills) and [Codex instructions](https://learn.chatgpt.com/docs/build-skills#where-codex-loads-local-skills) for installation locations and invocation. Codex paths follow the current documentation; check the discovery paths for your release when using an older version.

Use `/varmor-diagnosis` in Claude Code or `$varmor-diagnosis` in Codex CLI/IDE, followed by your request. You can also name the skill in plain language. If it is not discovered, ask the assistant to read the installed `SKILL.md` by absolute path.

For an application failure:

> Use varmor-diagnosis to investigate why Deployment checkout in namespace shop, context staging, started reporting permission denied about ten minutes ago after a policy change. Keep the investigation read-only and tell me whether the evidence connects the failure to vArmor.

For a policy that reports Ready:

> Use varmor-diagnosis to check policy checkout in namespace shop, context staging. It is Ready, but the application does not seem protected. Check target matching, actual Pod injection, and Profile use.

For analysis without cluster access:

> Use varmor-diagnosis to analyze these policy YAML files, Pod events, and audit excerpts. Do not connect to a cluster. Explain what they establish and what evidence is still missing.

You do not need to choose a playbook or run the helper scripts yourself.

## What you receive

You provide business context and any authorization needed to extend the investigation. Results include:

- A conclusion with supporting evidence, confidence, and affected scope.
- A distinction between confirmed findings, likely causes, and missing evidence.
- Suggested fixes and verification steps, with relevant impact and prerequisites. A formal Markdown report is available when requested.

Policy Ready alone does not prove protection, and permission errors alone do not prove vArmor caused them. When evidence is insufficient, the assistant identifies the next useful check rather than claiming a root cause.

To create or refine an EnhanceProtect policy, use [vArmor Policy Optimization](../varmor-policy-optimization/README.md).

## Further reading

- [SKILL.md](SKILL.md): instructions for the assistant.
- [Diagnostic playbooks](playbooks/README.md): investigation methods, access boundaries, and evidence conventions.

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
python3 package.py --output /ABS/RELEASE/varmor-diagnosis-skill.zip
```

The default outputs are `dist/varmor-diagnosis-skill.zip` (runtime resources,
bilingual guides, and license) and `dist/varmor-diagnosis-full.zip` (also includes
the installer, packager, and regression tests). Both extract to `varmor-diagnosis/`.
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
