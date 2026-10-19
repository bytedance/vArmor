#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministic binding of a policy YAML to its content hash or live identity.
#   hash_policy.py fingerprint [--file normalized.yaml]
#       -> prints sha256 of the canonical policy document
#   hash_policy.py verify [--file normalized.yaml] --hash <expected>
#       -> exit 0 on match; structured failure (exit 2) if the file changed
#   hash_policy.py snapshot --file live-policy.yaml
#       -> records identity, resource version, profile, and spec hash
#   hash_policy.py verify-snapshot --file current.yaml --snapshot snapshot.json
#       -> rejects policy recreation or spec drift during an observation window

import argparse
import json
import os
import sys
import time

import collect_violations
import vopt_common as common


def _canonical_text(content):
    # Normalize YAML formatting while preserving the document's list order.
    document = common.load_yaml_doc(content)
    return common.dump_yaml(document)


def fingerprint(content):
    text = _canonical_text(content)
    return common.sha256_text(text), text


def _required_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise common.ValidationError("%s must be a non-empty string" % field)
    return value.strip()


def create_snapshot(content, captured_at=None):
    document = common.load_yaml_doc(content)
    metadata = document.get("metadata")
    spec = document.get("spec")
    if not isinstance(metadata, dict):
        raise common.ValidationError("metadata must be an object")
    if not isinstance(spec, dict):
        raise common.ValidationError("spec must be an object")

    kind = _required_string(document.get("kind"), "kind")
    if kind not in ("VarmorPolicy", "VarmorClusterPolicy"):
        raise common.ValidationError("unsupported policy kind %r" % kind)
    namespace = metadata.get("namespace")
    if kind == "VarmorPolicy":
        namespace = _required_string(namespace, "metadata.namespace")
    elif namespace not in (None, ""):
        raise common.ValidationError(
            "VarmorClusterPolicy metadata.namespace must be absent"
        )
    else:
        namespace = ""

    generation = metadata.get("generation")
    if (
        not isinstance(generation, int)
        or isinstance(generation, bool)
        or generation < 1
    ):
        raise common.ValidationError("metadata.generation must be a positive integer")

    spec_text = json.dumps(
        spec,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    status = document.get("status")
    profile_name = status.get("profileName") if isinstance(status, dict) else ""
    if profile_name is None:
        profile_name = ""
    if not isinstance(profile_name, str):
        raise common.ValidationError("status.profileName must be a string")

    if captured_at is None:
        captured_at = int(time.time())
    if (
        not isinstance(captured_at, int)
        or isinstance(captured_at, bool)
        or captured_at < 0
    ):
        raise common.ValidationError("capturedAt must be a non-negative epoch integer")

    return {
        "snapshotVersion": 2,
        "capturedAt": captured_at,
        "policy": {
            "kind": kind,
            "namespace": namespace,
            "name": _required_string(metadata.get("name"), "metadata.name"),
            "uid": _required_string(metadata.get("uid"), "metadata.uid"),
            "generation": generation,
            "resourceVersion": _required_string(
                metadata.get("resourceVersion"), "metadata.resourceVersion"
            ),
            "profileName": profile_name,
            "specSha256": common.sha256_text(spec_text),
        },
    }


def verify_snapshot(content, snapshot, window_start):
    if not isinstance(snapshot, dict) or snapshot.get("snapshotVersion") != 2:
        raise common.ValidationError("unsupported or malformed policy snapshot")
    captured_at = snapshot.get("capturedAt")
    if (
        not isinstance(captured_at, int)
        or isinstance(captured_at, bool)
        or captured_at < 0
    ):
        raise common.ValidationError("policy snapshot has invalid capturedAt")
    if (
        not isinstance(window_start, int)
        or isinstance(window_start, bool)
        or window_start < captured_at
    ):
        raise common.ValidationError(
            "observation window start %r is earlier than snapshot capturedAt %d"
            % (window_start, captured_at)
        )
    expected = snapshot.get("policy")
    if not isinstance(expected, dict):
        raise common.ValidationError("policy snapshot is missing policy")

    current = create_snapshot(content)["policy"]
    compared_fields = (
        "kind",
        "namespace",
        "name",
        "uid",
        "generation",
        "profileName",
        "specSha256",
    )
    mismatches = []
    for field in compared_fields:
        if current.get(field) != expected.get(field):
            mismatches.append(
                {
                    "field": field,
                    "expected": expected.get(field),
                    "actual": current.get(field),
                }
            )

    return {
        "valid": not mismatches,
        "mismatches": mismatches,
        "capturedAt": captured_at,
        "windowStart": window_start,
        "observationStartResourceVersion": expected.get("resourceVersion"),
        "currentResourceVersion": current["resourceVersion"],
        "resourceVersionChanged": (
            expected.get("resourceVersion") != current["resourceVersion"]
        ),
        "specSha256": current["specSha256"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    fp = sub.add_parser("fingerprint")
    fp.add_argument("--file")
    ver = sub.add_parser("verify")
    ver.add_argument("--file")
    ver.add_argument("--hash", required=True)
    snap = sub.add_parser("snapshot")
    snap.add_argument("--file")
    verify_snap = sub.add_parser("verify-snapshot")
    verify_snap.add_argument("--file")
    verify_snap.add_argument("--snapshot", required=True)
    verify_snap.add_argument(
        "--window-start",
        required=True,
        help="fixed observation-window start (epoch or ISO 8601)",
    )
    verify_snap.add_argument(
        "--resource-version-file",
        help="write the verified current resourceVersion to this file",
    )
    verify_snap.add_argument(
        "--resource-version-only",
        action="store_true",
        help="after successful verification, print only current resourceVersion",
    )
    args = parser.parse_args()

    content = common.read_input(args.file)

    if args.command == "fingerprint":
        digest, _ = fingerprint(content)
        print(json.dumps({"sha256": digest}, ensure_ascii=False))
        return

    if args.command == "snapshot":
        print(json.dumps(create_snapshot(content), ensure_ascii=False, indent=2))
        return

    if args.command == "verify-snapshot":
        try:
            with open(args.snapshot, "r", encoding="utf-8") as handle:
                snapshot = json.load(handle)
        except (OSError, ValueError) as error:
            raise common.ValidationError(
                "cannot read policy snapshot %r: %s" % (args.snapshot, error)
            )
        window_start = collect_violations.parse_timestamp(args.window_start)
        result = verify_snapshot(content, snapshot, window_start)
        if not result["valid"]:
            print(
                json.dumps(result, ensure_ascii=False, indent=2),
                file=sys.stderr if args.resource_version_only else sys.stdout,
            )
            sys.exit(2)
        if args.resource_version_file:
            try:
                with open(
                    args.resource_version_file, "w", encoding="utf-8"
                ) as handle:
                    handle.write(result["currentResourceVersion"] + "\n")
                os.chmod(args.resource_version_file, 0o600)
            except OSError as error:
                raise common.ValidationError(
                    "cannot write resource version file %r: %s"
                    % (args.resource_version_file, error)
                )
        if args.resource_version_only:
            print(result["currentResourceVersion"])
        else:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        return

    digest, _ = fingerprint(content)
    if digest != args.hash.strip():
        print(
            json.dumps(
                {
                    "valid": False,
                    "expected": args.hash,
                    "actual": digest,
                    "message": "policy content changed since it was checked",
                },
                ensure_ascii=False,
            )
        )
        sys.exit(2)
    print(json.dumps({"valid": True, "sha256": digest}, ensure_ascii=False))


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("ERROR: %s" % error, file=sys.stderr)
        sys.exit(2)
