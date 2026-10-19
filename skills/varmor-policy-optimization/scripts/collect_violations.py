#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Read a vArmor violations log (the per-line JSON written to
# /var/log/varmor/violations.log) and keep only the events whose
# eventTimestamp falls inside a fixed closed interval AND that belong to
# the target policy.
#
# The window must be a fixed closed interval [start, end]; this tool never
# fills the end time with "now". It performs no semantic judgments.

import argparse
import datetime
import json
import math
import sys

import vopt_common as common


def parse_timestamp(value):
    """Accept unix epoch seconds or an ISO 8601 timestamp; return epoch seconds."""
    text = str(value).strip()
    if text == "":
        raise common.ValidationError("时间戳不能为空")
    if text.lstrip("-").isdigit():
        return int(text)
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.datetime.fromisoformat(normalized)
    except ValueError:
        raise common.ValidationError("无法解析时间戳 %r" % value)
    if parsed.tzinfo is None:
        raise common.ValidationError("时间戳 %r 必须带时区" % value)
    return int(parsed.timestamp())


def _identity_result(record, kind, namespace, name, profile_name):
    """Return (matched, reason, schema) for policy identity filtering."""
    policy_kind = record.get("policyKind")
    policy_name = record.get("policyName")
    policy_namespace = record.get("policyNamespace")
    has_identity = not (
        common.is_blank(policy_kind)
        and common.is_blank(policy_name)
        and common.is_blank(policy_namespace)
    )
    has_profile = isinstance(record.get("profileName"), str) and bool(record["profileName"].strip())
    schema = "policyIdentity" if has_identity else ("profileName" if has_profile else "none")
    if not common.is_blank(profile_name) and not has_profile:
        return False, "missingIdentity", schema
    if not common.is_blank(profile_name) and record.get("profileName") != profile_name:
        return False, "profileMismatch", schema
    if has_identity:
        matched = (
            (common.is_blank(kind) or policy_kind == kind)
            and (common.is_blank(name) or policy_name == name)
            and (
                policy_namespace in (None, "")
                if kind == "VarmorClusterPolicy"
                else (common.is_blank(namespace) or policy_namespace == namespace)
            )
        )
        return (
            matched,
            "matched" if matched else "policyIdentityMismatch",
            "policyIdentity",
        )
    if not common.is_blank(profile_name):
        return True, "matched", "profileName"
    return False, "missingIdentity", "none"


def valid_event_timestamp(value):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and value >= 0
        and (not isinstance(value, float) or math.isfinite(value))
    )


def parse_log_line(line):
    def reject_constant(value):
        raise ValueError("non-finite JSON value: %s" % value)

    record = json.loads(line, parse_constant=reject_constant)
    if not isinstance(record, dict):
        raise ValueError("log record must be an object")
    return record


def collect(
    log_text,
    start,
    end,
    kind=None,
    namespace=None,
    name=None,
    profile_name=None,
):
    """Filter raw violations log lines. Returns a result dict."""
    if end is None:
        raise common.ValidationError("必须提供结束时间，窗口是固定闭区间，不得用 now 补齐")
    if start > end:
        raise common.ValidationError("起始时间不能晚于结束时间")

    matched = []
    parse_errors = 0
    invalid_timestamps = 0
    outside_window = 0
    other_policy = 0
    profile_mismatch = 0
    policy_identity_mismatch = 0
    missing_identity = 0
    records_with_policy_identity = 0
    records_with_profile_only = 0
    blank_lines = 0
    total_lines = 0

    for line in (log_text or "").splitlines():
        total_lines += 1
        line = line.strip()
        if not line:
            blank_lines += 1
            continue
        try:
            record = parse_log_line(line)
        except ValueError:
            parse_errors += 1
            continue
        if not isinstance(record, dict):
            parse_errors += 1
            continue

        event_time = record.get("eventTimestamp")
        if not valid_event_timestamp(event_time):
            parse_errors += 1
            invalid_timestamps += 1
            continue
        if not (start <= event_time <= end):
            outside_window += 1
            continue
        matched_identity, reason, schema = _identity_result(
            record, kind, namespace, name, profile_name
        )
        if schema == "policyIdentity":
            records_with_policy_identity += 1
        elif schema == "profileName":
            records_with_profile_only += 1
        if not matched_identity:
            other_policy += 1
            if reason == "profileMismatch":
                profile_mismatch += 1
            elif reason == "policyIdentityMismatch":
                policy_identity_mismatch += 1
            else:
                missing_identity += 1
            continue
        matched.append(record)

    return {
        "window": {"start": start, "end": end},
        "matched": matched,
        "counts": {
            "totalLines": total_lines,
            "accountedLines": (
                len(matched)
                + outside_window
                + other_policy
                + parse_errors
                + blank_lines
            ),
            "matched": len(matched),
            "outsideWindow": outside_window,
            "otherPolicy": other_policy,
            "identityMismatch": other_policy,
            "profileMismatch": profile_mismatch,
            "policyIdentityMismatch": policy_identity_mismatch,
            "missingIdentity": missing_identity,
            "recordsWithPolicyIdentity": records_with_policy_identity,
            "recordsWithProfileNameOnly": records_with_profile_only,
            "parseErrors": parse_errors,
            "invalidTimestamps": invalid_timestamps,
            "blankLines": blank_lines,
        },
    }


def validate_identity_scope(kind=None, namespace=None, name=None):
    kind = (kind or "").strip()
    has_policy_scope = any(
        value is not None for value in (kind or None, name, namespace)
    )
    if not has_policy_scope:
        return
    if not kind or not (name or "").strip():
        raise common.ValidationError(
            "policy identity requires both --policy-kind and --policy-name"
        )
    if kind == "VarmorPolicy":
        if not (namespace or "").strip():
            raise common.ValidationError(
                "VarmorPolicy requires a non-empty --policy-namespace"
            )
    elif kind == "VarmorClusterPolicy":
        if namespace is not None:
            raise common.ValidationError(
                "VarmorClusterPolicy must not use --policy-namespace"
            )
    else:
        raise common.ValidationError("unknown --policy-kind %r" % kind)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", help="violations log file (default: stdin)")
    parser.add_argument("--start", required=True, help="window start (epoch or ISO 8601)")
    parser.add_argument("--end", required=True, help="window end (epoch or ISO 8601)")
    parser.add_argument("--policy-kind", help="VarmorPolicy or VarmorClusterPolicy")
    parser.add_argument(
        "--policy-namespace",
        help="required for VarmorPolicy; forbidden for VarmorClusterPolicy",
    )
    parser.add_argument("--policy-name", help="policy metadata.name")
    parser.add_argument(
        "--profile-name",
        required=True,
        help="always match profileName; policy identity is an additional check when present",
    )
    parser.add_argument(
        "--explain",
        action="store_true",
        help="print non-sensitive filter diagnostics to stderr",
    )
    args = parser.parse_args()

    if common.is_blank(args.profile_name):
        raise common.ValidationError("--profile-name must be a non-empty string")

    # Identity requires kind + name. Namespace rules are explicit, never
    # expressed by an empty value (#2):
    #   VP: namespace is mandatory; VCP: the flag is forbidden.
    validate_identity_scope(
        args.policy_kind,
        args.policy_namespace,
        args.policy_name,
    )

    start = parse_timestamp(args.start)
    end = parse_timestamp(args.end)
    log_text = common.read_input(args.file)
    result = collect(
        log_text,
        start,
        end,
        kind=args.policy_kind,
        namespace=args.policy_namespace,
        name=args.policy_name,
        profile_name=args.profile_name,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.explain:
        counts = result["counts"]
        print(
            "filter: matched=%d outsideWindow=%d identityMismatch=%d "
            "(profile=%d policy=%d missing=%d) parseErrors=%d"
            % (
                counts["matched"],
                counts["outsideWindow"],
                counts["identityMismatch"],
                counts["profileMismatch"],
                counts["policyIdentityMismatch"],
                counts["missingIdentity"],
                counts["parseErrors"],
            ),
            file=sys.stderr,
        )


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        sys.exit(2)
