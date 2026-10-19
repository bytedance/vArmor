#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
import sys


RESOURCE_BY_KIND = {
    "deployment": "deployments",
    "statefulset": "statefulsets",
    "daemonset": "daemonsets",
    "pod": "pods",
}

POLICY_RESOURCE_BY_KIND = {
    "vp": "varmorpolicies.crd.varmor.org",
    "vcp": "varmorclusterpolicies.crd.varmor.org",
}

DEFAULT_TIMEOUT_SECONDS = 20


def run_json(command, stage, allow_empty=False, context=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    if context:
        command = [command[0], "--context", context, *command[1:]]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as error:
        print(f"ERROR stage={stage} kind=DEPENDENCY_MISSING reason={json.dumps(str(error))}")
        sys.exit(127)
    except subprocess.TimeoutExpired:
        print(f"ERROR stage={stage} kind=TIMEOUT reason={json.dumps(f'command exceeded {timeout}s timeout')}")
        sys.exit(2)
    except OSError as error:
        print(f"ERROR stage={stage} kind=OS_ERROR reason={json.dumps(str(error))}")
        sys.exit(2)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown kubectl error"
        print(f"ERROR stage={stage} kind=KUBECTL_FAILED reason={json.dumps(message)}")
        sys.exit(2)
    if allow_empty and not result.stdout.strip():
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(f"ERROR stage={stage}_parse kind=BAD_RESPONSE reason={json.dumps(str(error))}")
        sys.exit(2)


def normalize_kind(value):
    return (value or "").replace("-", "").lower()


def evaluate_selector(selector, labels):
    labels = labels or {}
    failures = []
    for key, expected in (selector.get("matchLabels") or {}).items():
        if labels.get(key) != expected:
            failures.append(f"matchLabels:{key}")

    for index, expression in enumerate(selector.get("matchExpressions") or []):
        key = expression.get("key")
        operator = expression.get("operator")
        values = expression.get("values") or []
        if not key:
            raise ValueError("matchExpressions entry has no key")
        if operator in ("In", "NotIn") and not values:
            raise ValueError(f"matchExpressions operator {operator} requires non-empty values")
        if operator in ("Exists", "DoesNotExist") and values:
            raise ValueError(f"matchExpressions operator {operator} does not allow values")
        if operator == "In":
            if key not in labels or labels[key] not in values:
                failures.append(f"matchExpressions:{index}:In:{key}")
        elif operator == "NotIn":
            if key in labels and labels[key] in values:
                failures.append(f"matchExpressions:{index}:NotIn:{key}")
        elif operator == "Exists":
            if key not in labels:
                failures.append(f"matchExpressions:{index}:Exists:{key}")
        elif operator == "DoesNotExist":
            if key in labels:
                failures.append(f"matchExpressions:{index}:DoesNotExist:{key}")
        else:
            raise ValueError(f"unsupported matchExpressions operator: {operator!r}")
    return not failures, failures


def selector_matches(selector, labels):
    matched, _ = evaluate_selector(selector, labels)
    return matched


def main():
    parser = argparse.ArgumentParser(description="Resolve the resources matched by one VP or VCP target.")
    parser.add_argument("--kind", required=True, choices=("vp", "vcp"), help="Policy resource kind.")
    parser.add_argument("--name", required=True, help="Policy name.")
    parser.add_argument("--namespace", help="Policy namespace; required for VP and ignored for VCP.")
    parser.add_argument(
        "--target-namespace",
        help="Namespace in which to evaluate target resources; defaults to the VP namespace.",
    )
    parser.add_argument("--context", help="kubectl context override; defaults to the current context.")
    args = parser.parse_args()

    if args.kind == "vp" and not args.namespace:
        parser.error("--namespace is required for VP")
    if args.kind == "vcp" and not args.target_namespace:
        parser.error("--target-namespace is required for VCP")
    if args.kind == "vp" and args.target_namespace and args.target_namespace != args.namespace:
        parser.error("VP target resources are limited to the policy namespace")

    policy_command = ["kubectl"]
    if args.kind == "vp":
        policy_command.extend(["-n", args.namespace])
    policy_command.extend(["get", POLICY_RESOURCE_BY_KIND[args.kind], args.name, "-o", "json"])
    policy = run_json(policy_command, "policy_query", context=args.context)

    policy_metadata = policy.get("metadata") or {}
    target = ((policy.get("spec") or {}).get("target") or {})
    target_kind_raw = target.get("kind") or ""
    target_kind = normalize_kind(target_kind_raw)
    resource = RESOURCE_BY_KIND.get(target_kind)
    target_namespace = args.target_namespace or args.namespace

    print(
        f"POLICY kind={policy.get('kind', 'UNKNOWN')} "
        f"namespace={policy_metadata.get('namespace') or 'CLUSTER'} "
        f"name={policy_metadata.get('name', args.name)} uid={policy_metadata.get('uid', 'UNKNOWN')}"
    )
    print(
        f"TARGET namespace={target_namespace} kind={target_kind_raw or 'UNKNOWN'} "
        f"name={target.get('name') or 'NONE'} "
        f"containers={json.dumps(target.get('containers') or [], separators=(',', ':'))} "
        f"selector={json.dumps(target.get('selector') or {}, separators=(',', ':'))}"
    )

    if resource is None:
        print(
            f"ERROR stage=target_validation reason={json.dumps('unsupported or missing target.kind: ' + (target_kind_raw or 'UNKNOWN'))}"
        )
        sys.exit(3)

    target_name = target.get("name")
    selector = target.get("selector") or {}
    if target_name and selector:
        print("ERROR stage=target_validation reason=\"target.name and target.selector are both set\"")
        sys.exit(3)
    if not target_name and not selector:
        print("ERROR stage=target_validation reason=\"neither target.name nor target.selector is set\"")
        sys.exit(3)

    if target_name:
        obj = run_json(
            [
                "kubectl",
                "-n",
                target_namespace,
                "get",
                resource,
                target_name,
                "--ignore-not-found",
                "-o",
                "json",
            ],
            "target_query",
            allow_empty=True,
            context=args.context,
        )
        if obj is None:
            print(f"TARGET_NOT_FOUND name={target_name} namespace={target_namespace} resource={resource}")
            print("SUMMARY api_candidates=0 matched=0 unmatched=0")
            return
        metadata = obj.get("metadata") or {}
        print(
            f"CANDIDATE name={metadata.get('name', target_name)} "
            f"created={metadata.get('creationTimestamp', 'UNKNOWN')} matched=true reason=exact_name"
        )
        print("SUMMARY api_candidates=1 matched=1 unmatched=0")
        return

    candidate_command = ["kubectl", "-n", target_namespace, "get", resource]
    match_labels = selector.get("matchLabels") or {}
    if match_labels:
        api_selector = ",".join(f"{key}={value}" for key, value in sorted(match_labels.items()))
        candidate_command.extend(["-l", api_selector])
    candidate_command.extend(["-o", "json"])
    resource_list = run_json(candidate_command, "candidate_query", context=args.context)
    items = resource_list.get("items") or []
    matches = []
    try:
        for item in items:
            metadata = item.get("metadata") or {}
            matched, failures = evaluate_selector(selector, metadata.get("labels") or {})
            print(
                f"CANDIDATE name={metadata.get('name', 'UNKNOWN')} matched={str(matched).lower()} "
                f"failed={json.dumps(failures, separators=(',', ':'))}"
            )
            if matched:
                matches.append(metadata)
    except ValueError as error:
        print(f"ERROR stage=selector_evaluation reason={json.dumps(str(error))}")
        sys.exit(3)

    for metadata in sorted(matches, key=lambda value: value.get("name") or ""):
        print(
            f"MATCH name={metadata.get('name', 'UNKNOWN')} "
            f"uid={metadata.get('uid', 'UNKNOWN')} created={metadata.get('creationTimestamp', 'UNKNOWN')}"
        )
    print(f"SUMMARY api_candidates={len(items)} matched={len(matches)} unmatched={len(items) - len(matches)}")


if __name__ == "__main__":
    main()
