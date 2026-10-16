#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministic Seccomp optimization: map the observed syscalls to the
# built-in rules and custom syscallRawRules currently enabled in the policy,
# and produce an atomic removal plan. Custom entries preserve the full RawRule
# shape so args/errnoRet and other constraints remain reviewable. ALLOW and
# LOG rules are never removal candidates because deleting them would not make
# a blocked syscall usable. Ambiguous syscalls (matching multiple restrictive
# rules) require explicit approval before application.
#
# Ported from policy-optimization-agent/internal/seccompopt and the
# syscall map in policy-optimization-agent policyio pipeline.

import argparse
import copy
import json
import sys

import vopt_common as common

HARDENING = "hardeningRules"
ATTACK = "attackProtectionRules"
VUL = "vulMitigationRules"

# syscall -> built-in rule removals (mirrors syscallBuiltInRules in optimizer.go)
BUILTIN_MAP = {
    "unshare": [{"source": HARDENING, "rule": "disallow-create-user-ns"}],
    "bpf": [{"source": HARDENING, "rule": "disallow-load-all-bpf-prog"}],
    "setsockopt": [{"source": HARDENING, "rule": "disallow-load-bpf-via-setsockopt"}],
    "userfaultfd": [{"source": HARDENING, "rule": "disallow-userfaultfd-creation"}],
    "chmod": [
        {"source": ATTACK, "rule": "disable-chmod-x-bit"},
        {"source": ATTACK, "rule": "disable-chmod-s-bit"},
    ],
    "fchmod": [
        {"source": ATTACK, "rule": "disable-chmod-x-bit"},
        {"source": ATTACK, "rule": "disable-chmod-s-bit"},
    ],
    "fchmodat": [
        {"source": ATTACK, "rule": "disable-chmod-x-bit"},
        {"source": ATTACK, "rule": "disable-chmod-s-bit"},
    ],
    "fchmodat2": [
        {"source": ATTACK, "rule": "disable-chmod-x-bit"},
        {"source": ATTACK, "rule": "disable-chmod-s-bit"},
    ],
    "splice": [{"source": VUL, "rule": "dirty-pipe-mitigation"}],
}


def _enhance(document):
    enhance = common.get_path(document, "spec", "policy", "enhanceProtect")
    if not isinstance(enhance, dict):
        raise common.ValidationError(
            "policy.enhanceProtect is required for Seccomp optimization"
        )
    return enhance


def _builtin_active(enhance, removal, catalog):
    source = removal["source"]
    rule = removal["rule"]
    if source in (HARDENING, VUL):
        return common.canonical_rule_id(rule, catalog) in {
            common.canonical_rule_id(item, catalog) for item in enhance.get(source) or []
        }
    if source == ATTACK:
        for group in enhance.get(ATTACK) or []:
            if not isinstance(group, dict) or group.get("targets"):
                continue
            names = {
                common.canonical_rule_id(item, catalog)
                for item in group.get("rules") or []
            }
            if common.canonical_rule_id(rule, catalog) in names:
                return True
    return False


def build_plan(
    document,
    observed_syscalls,
    catalog=None,
    remove_builtin_rules=None,
    keep_builtin_rules=None,
    remove_syscalls=None,
    keep_syscalls=None,
):
    catalog = catalog or common.load_catalog()
    enhance = _enhance(document)
    if not isinstance(observed_syscalls, list) or any(
        not isinstance(item, str) or not item.strip() for item in observed_syscalls
    ):
        raise common.ValidationError("observed syscalls must be a list of non-empty strings")
    observed = {item.strip() for item in observed_syscalls}
    decision_inputs = (
        ("remove rules", remove_builtin_rules),
        ("keep rules", keep_builtin_rules),
        ("remove syscalls", remove_syscalls),
        ("keep syscalls", keep_syscalls),
    )
    for label, values in decision_inputs:
        if values is not None and (
            not isinstance(values, list)
            or any(not isinstance(value, str) or not value.strip() for value in values)
        ):
            raise common.ValidationError("%s must be a list of non-empty strings" % label)
    remove_rules = {
        common.canonical_rule_id(rule, catalog)
        for rule in (remove_builtin_rules or [])
    }
    keep_rules = {common.canonical_rule_id(rule, catalog) for rule in (keep_builtin_rules or [])}
    remove_calls = {call.strip() for call in (remove_syscalls or [])}
    keep_calls = {call.strip() for call in (keep_syscalls or [])}
    if remove_rules & keep_rules:
        raise common.ValidationError("a built-in Seccomp rule cannot be both remove and keep")
    if remove_calls & keep_calls:
        raise common.ValidationError("a Seccomp syscall cannot be both remove and keep")

    builtin_candidates = {}
    builtin_candidate_syscalls = {}
    custom_candidates = []
    custom_candidate_syscalls = set()
    builtin_removals = []
    kept_builtin_rules = []
    pending_builtin_rules = []
    custom_removals = []
    kept_custom_rules = []
    pending_custom_rules = []
    ignored_allow_rules = []
    ignored_log_rules = []
    matched_counts = {syscall: 0 for syscall in observed}

    for syscall in sorted(observed):
        for removal in BUILTIN_MAP.get(syscall, []):
            if _builtin_active(enhance, removal, catalog):
                canonical = common.canonical_rule_id(removal["rule"], catalog)
                matched_counts[syscall] += 1
                builtin_candidates.setdefault(canonical, removal)
                builtin_candidate_syscalls.setdefault(canonical, set()).add(syscall)

    for raw in enhance.get("syscallRawRules") or []:
        if not isinstance(raw, dict):
            continue
        action = str(raw.get("action") or "").strip().upper()
        for syscall in raw.get("names") or []:
            if syscall not in observed:
                continue
            single = copy.deepcopy(raw)
            single["names"] = [syscall]
            coordinate = {"source": "syscallRawRules", "rule": single}
            if action == "SCMP_ACT_ALLOW":
                ignored_allow_rules.append(coordinate)
                continue
            if action == "SCMP_ACT_LOG":
                ignored_log_rules.append(coordinate)
                continue
            matched_counts[syscall] += 1
            custom_candidate_syscalls.add(syscall)
            custom_candidates.append((syscall, coordinate))

    unmatched_rule_decisions = sorted(
        (remove_rules | keep_rules) - set(builtin_candidates)
    )
    if unmatched_rule_decisions:
        raise common.ValidationError(
            "Seccomp rule decisions must name active built-in rules matched "
            "by the observed syscalls: %s"
            % ", ".join(unmatched_rule_decisions)
        )
    unmatched_syscall_decisions = sorted(
        (remove_calls | keep_calls) - custom_candidate_syscalls
    )
    if unmatched_syscall_decisions:
        raise common.ValidationError(
            "Seccomp syscall decisions must name observed syscalls with "
            "restrictive custom rules: %s"
            % ", ".join(unmatched_syscall_decisions)
        )

    for canonical, coordinate in builtin_candidates.items():
        if canonical in remove_rules:
            builtin_removals.append(coordinate)
        elif canonical in keep_rules:
            kept_builtin_rules.append(coordinate)
        else:
            pending_builtin_rules.append(coordinate)
    for syscall, coordinate in custom_candidates:
        if syscall in remove_calls:
            custom_removals.append(coordinate)
        elif syscall in keep_calls:
            kept_custom_rules.append(coordinate)
        else:
            pending_custom_rules.append(coordinate)

    unmatched = sorted(syscall for syscall in observed if matched_counts[syscall] == 0)
    removed_rule_ids = set(remove_rules)
    ambiguous = sorted(
        syscall for syscall in observed if matched_counts[syscall] > 1
    )
    ambiguous_removals = sorted(
        syscall for syscall in observed
        if matched_counts[syscall] > 1
        and (
            syscall in remove_calls
            or any(
                rule in removed_rule_ids
                for rule, syscalls in builtin_candidate_syscalls.items()
                if syscall in syscalls
            )
        )
    )
    changed = bool(builtin_removals) or bool(custom_removals)
    decisions_complete = not pending_builtin_rules and not pending_custom_rules

    return {
        "changed": changed,
        "decisionsComplete": decisions_complete,
        "builtinRemovals": builtin_removals,
        "keptBuiltinRules": kept_builtin_rules,
        "pendingBuiltinRules": pending_builtin_rules,
        "keptCustomRules": kept_custom_rules,
        "keptSyscalls": sorted(keep_calls),
        "customRemovals": custom_removals,
        "pendingCustomRules": pending_custom_rules,
        "ignoredAllowRules": ignored_allow_rules,
        "ignoredLogRules": ignored_log_rules,
        "unmatchedSyscalls": unmatched,
        "ambiguousSyscalls": ambiguous,
        "ambiguousRemovals": ambiguous_removals,
    }


def _remove_strings(values, removed):
    return [item for item in values if item not in removed]


def apply_plan(document, plan, catalog=None):
    """Return a new document with the Seccomp removal plan applied."""
    if not isinstance(plan, dict) or plan.get("decisionsComplete") is not True:
        raise common.ValidationError(
            "explicit remove/keep decisions are required for every Seccomp candidate"
        )
    catalog = catalog or common.load_catalog()
    root = copy.deepcopy(document)
    enhance = common.get_path(root, "spec", "policy", "enhanceProtect")

    removals_by_source = {}
    for removal in plan["builtinRemovals"]:
        removals_by_source.setdefault(removal["source"], set()).add(
            common.canonical_rule_id(removal["rule"], catalog)
        )

    for source in (HARDENING, VUL):
        removed = removals_by_source.get(source)
        if removed:
            enhance[source] = [
                item
                for item in enhance.get(source) or []
                if common.canonical_rule_id(item, catalog) not in removed
            ]
            if not enhance[source]:
                enhance.pop(source, None)

    removed_attack = removals_by_source.get(ATTACK)
    if removed_attack:
        groups = []
        for group in enhance.get(ATTACK) or []:
            if not isinstance(group, dict) or group.get("targets"):
                groups.append(group)
                continue
            remaining = [
                item
                for item in group.get("rules") or []
                if common.canonical_rule_id(item, catalog) not in removed_attack
            ]
            if remaining:
                group["rules"] = remaining
                groups.append(group)
        if groups:
            enhance[ATTACK] = groups
        else:
            enhance.pop(ATTACK, None)

    custom_removed = {
        common.stable_json(entry["rule"]): 0
        for entry in plan["customRemovals"]
        if entry.get("source") == "syscallRawRules"
        and isinstance(entry.get("rule"), dict)
    }
    if not custom_removed:
        return root
    rules = []
    for raw in enhance.get("syscallRawRules") or []:
        if not isinstance(raw, dict):
            rules.append(raw)
            continue
        remaining_names = []
        for name in raw.get("names") or []:
            single = copy.deepcopy(raw)
            single["names"] = [name]
            key = common.stable_json(single)
            if key in custom_removed:
                custom_removed[key] += 1
            else:
                remaining_names.append(name)
        if remaining_names:
            raw["names"] = remaining_names
            rules.append(raw)
    if rules:
        enhance["syscallRawRules"] = rules
    else:
        enhance.pop("syscallRawRules", None)

    bad_counts = {
        key: count for key, count in custom_removed.items() if count != 1
    }
    if bad_counts:
        raise common.ValidationError(
            "custom Seccomp removal must match exactly one rule atom: %s"
            % ", ".join(sorted(bad_counts))
        )

    return root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--policy", required=True, help="current policy YAML file")
    parser.add_argument(
        "--syscalls",
        help="observed syscalls (non-apply, or must match pre.seccompSyscalls)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="apply the plan and print the resulting policy YAML",
    )
    parser.add_argument(
        "--pre",
        help="preprocess_aggregate output; required with --apply",
    )
    parser.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="apply a plan that removes multiple restrictive rules for one syscall",
    )
    parser.add_argument(
        "--remove-seccomp-rule",
        action="append",
        default=[],
        help="remove an observed built-in Seccomp rule (repeat)",
    )
    parser.add_argument(
        "--keep-seccomp-rule",
        action="append",
        default=[],
        help="keep an observed built-in Seccomp rule (repeat for multiple rules)",
    )
    parser.add_argument(
        "--remove-seccomp-syscall",
        action="append",
        default=[],
        help="remove all restrictive custom atoms for an observed syscall",
    )
    parser.add_argument(
        "--keep-seccomp-syscall",
        action="append",
        default=[],
        help="keep all restrictive custom atoms for an observed syscall",
    )
    args = parser.parse_args()

    catalog = common.load_catalog()
    document = common.load_yaml_doc(common.read_input(args.policy))

    pre = None
    if args.pre:
        with open(args.pre, "r", encoding="utf-8") as handle:
            pre = json.load(handle)
        if pre.get("collectionComplete") is not True:
            raise common.ValidationError(
                "collection incomplete; refusing to remove Seccomp rules"
            )
        if pre.get("retentionCovered") is not True:
            raise common.ValidationError(
                "log retention coverage is not proven; refusing Seccomp removals"
            )
        if pre.get("failures"):
            raise common.ValidationError(
                "preprocessing has invalid events; refusing to remove Seccomp rules"
            )
        observed = sorted(pre.get("seccompSyscalls") or [])
        if args.syscalls:
            given = {
                item.strip() for item in args.syscalls.split(",") if item.strip()
            }
            if given != set(observed):
                raise common.ValidationError(
                    "--syscalls must equal pre.seccompSyscalls"
                )
    else:
        if args.apply:
            raise common.ValidationError("--apply requires --pre <pre.json>")
        if not args.syscalls:
            raise common.ValidationError("--pre or --syscalls is required")
        observed = [item.strip() for item in args.syscalls.split(",") if item.strip()]

    plan = build_plan(
        document,
        observed,
        catalog,
        remove_builtin_rules=args.remove_seccomp_rule,
        keep_builtin_rules=args.keep_seccomp_rule,
        remove_syscalls=args.remove_seccomp_syscall,
        keep_syscalls=args.keep_seccomp_syscall,
    )

    if not args.apply:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
        return

    if not plan["decisionsComplete"]:
        raise common.ValidationError(
            "every Seccomp candidate requires an explicit remove or keep decision"
        )
    if plan["ambiguousRemovals"] and not args.allow_ambiguous:
        raise common.ValidationError(
            "ambiguous syscall matches require explicit --allow-ambiguous: %s"
            % ", ".join(plan["ambiguousRemovals"])
        )

    updated = apply_plan(document, plan, catalog)
    print(common.dump_yaml(updated))


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("SECCOMP PLAN FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
