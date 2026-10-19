#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0

# Conflict semantics are adapted from the vArmor policy advisor:
# https://github.com/bytedance/vArmor/tree/main/tools/policy-advisor
# The analyzer is modified to inspect an existing policy and never generates policy content.

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter


CATALOG_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "built-in-rule-conflicts.json")
KNOWN_ENFORCERS = ("apparmor", "bpf", "seccomp", "networkproxy")
BEHAVIOR_DIMENSIONS = ("capabilities", "syscalls", "executions", "files")
CONTEXT_DIMENSIONS = ("features", "capabilities")
POLICY_RESOURCE_BY_KIND = {
    "vp": "varmorpolicies.crd.varmor.org",
    "vcp": "varmorclusterpolicies.crd.varmor.org",
}
APM_RESOURCE = "armorprofilemodels.crd.varmor.org"
DEFAULT_TIMEOUT_SECONDS = 30


def fail(stage, reason, code=2, kind=None):
    kind_field = f" kind={kind}" if kind else ""
    print(f"ERROR stage={stage}{kind_field} reason={json.dumps(str(reason))}")
    sys.exit(code)


def run_json(command, stage, context=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    if context:
        command = [command[0], "--context", context, *command[1:]]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as error:
        fail(stage, error, code=127, kind="DEPENDENCY_MISSING")
    except subprocess.TimeoutExpired:
        fail(stage, f"command exceeded {timeout}s timeout", kind="TIMEOUT")
    except OSError as error:
        fail(stage, error, kind="OS_ERROR")
    if result.returncode != 0:
        fail(stage, result.stderr.strip() or result.stdout.strip() or "unknown kubectl error", kind="KUBECTL_FAILED")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        fail(f"{stage}_parse", error, kind="BAD_RESPONSE")


def load_json(path, stage):
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, json.JSONDecodeError) as error:
        fail(stage, error)


def parse_csv(value):
    if value is None:
        return None
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def policy_enforcers(value):
    compact = re.sub(r"[^a-z]", "", (value or "").lower())
    return {name for name in KNOWN_ENFORCERS if name in compact}


def configured_rules(policy):
    policy_spec = (policy.get("spec") or {}).get("policy") or {}
    enhance = policy_spec.get("enhanceProtect") or {}
    found = []
    for field in ("hardeningRules", "vulMitigationRules"):
        for rule_id in enhance.get(field) or []:
            found.append((str(rule_id), field))
    for group_index, group in enumerate(enhance.get("attackProtectionRules") or []):
        for rule_id in (group or {}).get("rules") or []:
            found.append((str(rule_id), f"attackProtectionRules[{group_index}]"))
    return policy_spec, found


def retrieve_behavior(apm):
    dynamic = ((apm or {}).get("data") or {}).get("dynamicResult") or {}
    apparmor = dynamic.get("appArmor") or {}
    bpf = dynamic.get("bpf") or {}
    seccomp = dynamic.get("seccomp") or {}
    executions = []
    for value in (apparmor.get("executions") or []) + (bpf.get("executions") or []):
        executions.append(os.path.basename(value))
    return {
        "capabilities": {
            str(value).lower()
            for value in (apparmor.get("capabilities") or []) + (bpf.get("capabilities") or [])
        },
        "syscalls": {str(value).lower() for value in seccomp.get("syscalls") or []},
        "executions": {str(value).lower() for value in executions},
        "files": (apparmor.get("files") or []) + (bpf.get("files") or []),
    }


def common(expected, actual):
    expected_set = {str(value).lower() for value in expected or []}
    return bool(expected_set & actual), sorted(expected_set & actual)


def file_conflicts(file_rules, files):
    matches = 0
    invalid_patterns = []
    for file_rule in file_rules or []:
        pattern = file_rule.get("path_regex") or ""
        try:
            compiled = re.compile(pattern)
        except re.error:
            invalid_patterns.append(pattern)
            continue
        expected_permissions = {str(value).lower() for value in file_rule.get("permissions") or []}
        for item in files:
            path = item.get("oldPath") or item.get("path") or ""
            permissions = {str(value).lower() for value in item.get("permissions") or []}
            if compiled.search(path) and ("*" in expected_permissions or expected_permissions & permissions):
                matches += 1
    return matches, invalid_patterns


def context_match(rule_section, features, capabilities):
    matched_dimensions = []
    matched_values = {}
    if features is not None and "features" in rule_section:
        expected = {str(value).lower() for value in rule_section.get("features") or []}
        if "*" in expected:
            matched_dimensions.append("features")
            matched_values["features"] = ["*"]
        else:
            matched, values = common(expected, features)
            if matched:
                matched_dimensions.append("features")
                matched_values["features"] = values
    if capabilities is not None and "capabilities" in rule_section:
        matched, values = common(rule_section.get("capabilities"), capabilities)
        if matched:
            matched_dimensions.append("capabilities")
            matched_values["capabilities"] = values
    return matched_dimensions, matched_values


def behavior_match(conflicts, behavior):
    dimensions = []
    details = {}
    for dimension in ("capabilities", "syscalls", "executions"):
        if dimension in conflicts:
            matched, values = common(conflicts.get(dimension), behavior[dimension])
            if matched:
                dimensions.append(dimension)
                details[dimension] = values
    if "files" in conflicts:
        count, invalid_patterns = file_conflicts(conflicts.get("files"), behavior["files"])
        if invalid_patterns:
            return dimensions, details, invalid_patterns
        if count:
            dimensions.append("files")
            details["files"] = {"matched_records": count, "paths": "REDACTED"}
    return dimensions, details, []


def evaluate_rule(rule_id, location, catalog, enforcers, features, capabilities, apm, behavior):
    metadata = catalog.get(rule_id)
    if metadata is None:
        return "UNASSESSED", "rule_not_in_advisor_catalog", {}

    supported = set(metadata.get("enforcers") or []) & enforcers
    if not supported:
        return "UNSUPPORTED_BY_ENFORCER", "no_common_enforcer", {
            "policy_enforcers": sorted(enforcers),
            "rule_enforcers": metadata.get("enforcers") or [],
        }

    conflicts = metadata.get("conflicts") or {}
    declared_dimensions, declared_values = context_match(conflicts, features, capabilities)
    if declared_dimensions:
        return "CONFLICT_DECLARED", "explicit_context_matches_conflict_metadata", {
            "dimensions": declared_dimensions,
            "matches": declared_values,
        }

    context_needed = any(dimension in conflicts for dimension in CONTEXT_DIMENSIONS)
    if context_needed and features is None and capabilities is None:
        return "UNASSESSED", "features_and_capabilities_not_provided", {}

    applicable = metadata.get("applicable")
    if applicable:
        applicable_dimensions, applicable_values = context_match(applicable, features, capabilities)
        if not applicable_dimensions:
            return "APPLICABILITY_NOT_ESTABLISHED", "explicit_context_does_not_establish_applicability", {}
        applicability = applicable_values
    else:
        applicability = {}

    behavior_dimensions = [dimension for dimension in BEHAVIOR_DIMENSIONS if dimension in conflicts]
    if behavior_dimensions:
        if apm is None:
            return "APM_DATA_UNAVAILABLE", "behavior_conflict_metadata_requires_apm_sample", {
                "dimensions": behavior_dimensions,
                "applicability": applicability,
            }
        observed_dimensions, observed_values, invalid_patterns = behavior_match(conflicts, behavior)
        if invalid_patterns:
            return "UNASSESSED", "invalid_catalog_path_regex", {"invalid_pattern_count": len(invalid_patterns)}
        if observed_dimensions:
            return "CONFLICT_OBSERVED", "apm_sample_matches_conflict_metadata", {
                "dimensions": observed_dimensions,
                "matches": observed_values,
            }
        return "NO_CONFLICT_OBSERVED", "no_match_in_supplied_apm_sample", {
            "assurance": "sample_only_not_proof_of_absence",
            "dimensions_checked": behavior_dimensions,
            "applicability": applicability,
        }

    return "SUPPORTED", "no_conflict_established_from_supplied_evidence", {
        "applicability": applicability,
        "location": location,
    }


def main():
    parser = argparse.ArgumentParser(
        description="Analyze conflict evidence for built-in rules already configured in one VP or VCP."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy-file", help="Existing VP/VCP JSON exported with kubectl -o json.")
    source.add_argument("--kind", choices=("vp", "vcp"), help="Query one existing policy with kubectl.")
    parser.add_argument("--name", help="Policy name; required with --kind.")
    parser.add_argument("--namespace", help="Policy namespace; required for VP.")
    parser.add_argument("--apm-file", help="Optional ArmorProfileModel JSON exported with kubectl -o json.")
    parser.add_argument("--apm-name", help="Optional ArmorProfileModel name to query with kubectl.")
    parser.add_argument("--apm-namespace", help="Namespace for --apm-name.")
    parser.add_argument("--features", help="Comma-separated application features; an empty value means explicitly none.")
    parser.add_argument("--capabilities", help="Comma-separated required capabilities; empty means explicitly none.")
    parser.add_argument("--catalog", default=CATALOG_PATH, help=argparse.SUPPRESS)
    parser.add_argument("--context", help="kubectl context override; defaults to the current context.")
    args = parser.parse_args()

    if args.kind:
        if not args.name:
            parser.error("--name is required with --kind")
        if args.kind == "vp" and not args.namespace:
            parser.error("--namespace is required for VP")
        command = ["kubectl"]
        if args.kind == "vp":
            command.extend(["-n", args.namespace])
        command.extend(["get", POLICY_RESOURCE_BY_KIND[args.kind], args.name, "-o", "json"])
        policy = run_json(command, "policy_query", context=args.context)
    else:
        if args.name or args.namespace:
            parser.error("--name/--namespace are only valid with --kind")
        policy = load_json(args.policy_file, "policy_file")

    if args.apm_file and args.apm_name:
        parser.error("--apm-file and --apm-name are mutually exclusive")
    if args.apm_name:
        if not args.apm_namespace:
            parser.error("--apm-namespace is required with --apm-name")
        apm = run_json(
            ["kubectl", "-n", args.apm_namespace, "get", APM_RESOURCE, args.apm_name, "-o", "json"],
            "apm_query",
            context=args.context,
        )
    elif args.apm_file:
        apm = load_json(args.apm_file, "apm_file")
    else:
        apm = None

    catalog_document = load_json(args.catalog, "catalog")
    catalog = catalog_document.get("rules") or {}
    policy_spec, rules = configured_rules(policy)
    enforcers = policy_enforcers(policy_spec.get("enforcer"))
    features = parse_csv(args.features)
    capabilities = parse_csv(args.capabilities)
    behavior = retrieve_behavior(apm) if apm is not None else None
    metadata = policy.get("metadata") or {}

    print(
        f"POLICY kind={policy.get('kind', 'UNKNOWN')} "
        f"namespace={metadata.get('namespace') or 'CLUSTER'} name={metadata.get('name', 'UNKNOWN')} "
        f"uid={metadata.get('uid', 'UNKNOWN')} mode={json.dumps(policy_spec.get('mode') or 'UNKNOWN')} "
        f"enforcers={json.dumps(sorted(enforcers), separators=(',', ':'))}"
    )
    print(
        f"EVIDENCE features={'NOT_PROVIDED' if features is None else json.dumps(sorted(features), separators=(',', ':'))} "
        f"capabilities={'NOT_PROVIDED' if capabilities is None else json.dumps(sorted(capabilities), separators=(',', ':'))} "
        f"apm={'PROVIDED' if apm is not None else 'NOT_PROVIDED'} "
        f"catalog_revision={json.dumps(catalog_document.get('sourceRevision') or 'UNKNOWN')}"
    )

    if policy_spec.get("mode") != "EnhanceProtect":
        print("CONCLUSION status=NOT_APPLICABLE reason=policy_mode_is_not_EnhanceProtect")
        return
    if not enforcers:
        fail("policy_validation", "policy enforcer is missing or unrecognized", 3)

    unique_rules = []
    seen = set()
    for rule_id, location in rules:
        if rule_id not in seen:
            unique_rules.append((rule_id, location))
            seen.add(rule_id)

    if not unique_rules:
        print("CONCLUSION status=NOT_APPLICABLE reason=no_built_in_rules_configured configured=0")
        return

    counts = Counter()
    for rule_id, location in unique_rules:
        status, reason, evidence = evaluate_rule(
            rule_id, location, catalog, enforcers, features, capabilities, apm, behavior
        )
        counts[status] += 1
        print(
            f"RULE id={json.dumps(rule_id)} location={json.dumps(location)} status={status} "
            f"reason={reason} evidence={json.dumps(evidence, sort_keys=True, separators=(',', ':'))}"
        )

    unresolved_statuses = {
        "CONFLICT_DECLARED",
        "CONFLICT_OBSERVED",
        "APPLICABILITY_NOT_ESTABLISHED",
        "APM_DATA_UNAVAILABLE",
        "UNASSESSED",
        "UNSUPPORTED_BY_ENFORCER",
    }
    unresolved = sum(counts[status] for status in unresolved_statuses)
    status = "REVIEW_REQUIRED" if unresolved else "NO_CONFLICT_ESTABLISHED"
    reason = "one_or_more_rules_unresolved" if unresolved else "all_rules_assessed_with_supplied_evidence"
    print(
        f"CONCLUSION status={status} configured={len(unique_rules)} unresolved={unresolved} "
        f"duplicates_ignored={len(rules) - len(unique_rules)} "
        f"counts={json.dumps(dict(sorted(counts.items())), separators=(',', ':'))} reason={reason}"
    )
    if unresolved:
        print("INTERPRETATION rule_layer=NOT_EXCLUDED reason=unresolved_rules_require_additional_evidence")
    else:
        print("INTERPRETATION rule_layer=NO_CONFLICT_ESTABLISHED scope=supplied_evidence_only")
    print("NOTICE result_is_diagnostic_evidence_not_a_policy_recommendation")


if __name__ == "__main__":
    main()
