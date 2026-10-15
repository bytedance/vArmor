#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Build an auditable vArmor agent inventory from DaemonSet and Pod JSON.
# The inventory includes every Pod owned by the target DaemonSet, including
# NotReady and terminating Pods, and compares that set with the controller's
# desired scheduling count. It never queries the cluster directly. The compact
# CLI accepts a mixed Kubernetes List on stdin so callers do not need to retain
# raw DaemonSet and PodList dumps.

import argparse
import json
import sys
import time

import vopt_common as common


def _load_json(path, label):
    try:
        value = json.loads(common.read_input(None if path == "-" else path))
    except (OSError, ValueError) as error:
        raise common.ValidationError("cannot read %s %r: %s" % (label, path, error))
    if not isinstance(value, dict):
        raise common.ValidationError("%s must be a JSON object" % label)
    return value


def split_cluster_snapshot(payload, daemonset_name, daemonset_namespace=None):
    if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
        raise common.ValidationError("cluster snapshot must be a Kubernetes List")
    name = _required_string(daemonset_name, "--daemonset-name")
    namespace = (
        _required_string(daemonset_namespace, "--daemonset-namespace")
        if daemonset_namespace is not None
        else None
    )
    daemonsets = []
    pods = []
    for item in payload["items"]:
        if not isinstance(item, dict):
            continue
        kind = item.get("kind")
        metadata = item.get("metadata")
        if kind == "Pod":
            pods.append(item)
        elif (
            kind == "DaemonSet"
            and isinstance(metadata, dict)
            and metadata.get("name") == name
            and (namespace is None or metadata.get("namespace") == namespace)
        ):
            daemonsets.append(item)
    if len(daemonsets) != 1:
        raise common.ValidationError(
            "cluster snapshot must contain exactly one matching DaemonSet %r; got %d"
            % (name, len(daemonsets))
        )
    return daemonsets[0], {"items": pods}


def _required_string(value, field):
    if not isinstance(value, str) or not value.strip():
        raise common.ValidationError("%s must be a non-empty string" % field)
    return value.strip()


def _non_negative_int(value, field):
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
    ):
        raise common.ValidationError("%s must be a non-negative integer" % field)
    return value


def _owned_by_daemonset(pod, name, uid):
    metadata = pod.get("metadata")
    if not isinstance(metadata, dict):
        return False
    owners = metadata.get("ownerReferences")
    if not isinstance(owners, list):
        return False
    return any(
        isinstance(owner, dict)
        and owner.get("kind") == "DaemonSet"
        and owner.get("name") == name
        and owner.get("uid") == uid
        for owner in owners
    )


def _pod_ready(pod):
    status = pod.get("status")
    conditions = status.get("conditions") if isinstance(status, dict) else None
    if not isinstance(conditions, list):
        return False
    return any(
        isinstance(condition, dict)
        and condition.get("type") == "Ready"
        and condition.get("status") == "True"
        for condition in conditions
    )


def build(daemonset, pod_list, captured_at=None):
    metadata = daemonset.get("metadata")
    status = daemonset.get("status")
    if daemonset.get("kind") != "DaemonSet":
        raise common.ValidationError("daemonset input kind must be DaemonSet")
    if not isinstance(metadata, dict):
        raise common.ValidationError("daemonset metadata must be an object")
    if not isinstance(status, dict):
        raise common.ValidationError("daemonset status must be an object")
    items = pod_list.get("items")
    if not isinstance(items, list):
        raise common.ValidationError("pod list items must be an array")

    name = _required_string(metadata.get("name"), "daemonset metadata.name")
    namespace = _required_string(
        metadata.get("namespace"), "daemonset metadata.namespace"
    )
    uid = _required_string(metadata.get("uid"), "daemonset metadata.uid")
    generation = _non_negative_int(
        metadata.get("generation"), "daemonset metadata.generation"
    )
    desired = _non_negative_int(
        status.get("desiredNumberScheduled"),
        "daemonset status.desiredNumberScheduled",
    )
    current = _non_negative_int(
        status.get("currentNumberScheduled"),
        "daemonset status.currentNumberScheduled",
    )
    ready_count = _non_negative_int(
        status.get("numberReady"), "daemonset status.numberReady"
    )
    observed_generation = _non_negative_int(
        status.get("observedGeneration"),
        "daemonset status.observedGeneration",
    )

    agents = []
    issues = []
    for pod in items:
        if not isinstance(pod, dict) or not _owned_by_daemonset(pod, name, uid):
            continue
        pod_metadata = pod.get("metadata") or {}
        pod_spec = pod.get("spec") or {}
        pod_status = pod.get("status") or {}
        pod_name = _required_string(
            pod_metadata.get("name"), "owned pod metadata.name"
        )
        node = pod_spec.get("nodeName")
        node = node.strip() if isinstance(node, str) else ""
        terminating = pod_metadata.get("deletionTimestamp") is not None
        ready = _pod_ready(pod) and not terminating
        agents.append(
            {
                "node": node,
                "pod": pod_name,
                "uid": _required_string(
                    pod_metadata.get("uid"), "owned pod metadata.uid"
                ),
                "ready": ready,
                "terminating": terminating,
                "phase": str(pod_status.get("phase") or ""),
            }
        )
        if not node:
            issues.append("owned pod %s is not scheduled to a node" % pod_name)
        if terminating:
            issues.append("owned pod %s is terminating" % pod_name)
        elif not ready:
            issues.append("owned pod %s is not Ready" % pod_name)

    agents.sort(key=lambda item: (item["node"], item["pod"]))
    scheduled_nodes = [agent["node"] for agent in agents if agent["node"]]
    if desired <= 0:
        issues.append("DaemonSet desiredNumberScheduled is zero")
    if observed_generation != generation:
        issues.append(
            "DaemonSet status.observedGeneration does not match metadata.generation"
        )
    if current != desired:
        issues.append(
            "DaemonSet currentNumberScheduled %d does not equal desired %d"
            % (current, desired)
        )
    if ready_count != desired:
        issues.append(
            "DaemonSet numberReady %d does not equal desired %d"
            % (ready_count, desired)
        )
    if len(agents) != desired:
        issues.append(
            "owned Pod count %d does not equal desired %d" % (len(agents), desired)
        )
    if len(scheduled_nodes) != len(set(scheduled_nodes)):
        issues.append("multiple owned Pods are assigned to the same node")

    if captured_at is None:
        captured_at = int(time.time())
    if (
        not isinstance(captured_at, int)
        or isinstance(captured_at, bool)
        or captured_at < 0
    ):
        raise common.ValidationError("capturedAt must be a non-negative epoch integer")

    return {
        "inventoryVersion": 2,
        "capturedAt": captured_at,
        "daemonSet": {
            "namespace": namespace,
            "name": name,
            "uid": uid,
            "generation": generation,
            "resourceVersion": _required_string(
                metadata.get("resourceVersion"),
                "daemonset metadata.resourceVersion",
            ),
            "observedGeneration": observed_generation,
            "desiredNumberScheduled": desired,
            "currentNumberScheduled": current,
            "numberReady": ready_count,
        },
        "inventoryComplete": not issues,
        "issues": issues,
        "agents": agents,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--daemonset", help="DaemonSet JSON file")
    parser.add_argument("--pods", help="namespace PodList JSON file")
    parser.add_argument(
        "--cluster-snapshot",
        help="mixed Kubernetes List file; use '-' to read stdin",
    )
    parser.add_argument(
        "--daemonset-name",
        help="exact DaemonSet name when using --cluster-snapshot",
    )
    parser.add_argument(
        "--daemonset-namespace",
        help="optional exact DaemonSet namespace for a cluster-scoped snapshot",
    )
    args = parser.parse_args()

    compact_mode = args.cluster_snapshot is not None or args.daemonset_name is not None
    file_mode = args.daemonset is not None or args.pods is not None
    if compact_mode and file_mode:
        raise common.ValidationError(
            "use either --cluster-snapshot/--daemonset-name or --daemonset/--pods"
        )
    if compact_mode:
        if not args.daemonset_name:
            raise common.ValidationError(
                "--daemonset-name is required with --cluster-snapshot"
            )
        payload = _load_json(args.cluster_snapshot, "cluster snapshot")
        daemonset, pods = split_cluster_snapshot(
            payload,
            args.daemonset_name,
            args.daemonset_namespace,
        )
    else:
        if not args.daemonset or not args.pods:
            raise common.ValidationError(
                "--daemonset and --pods are required in file mode"
            )
        daemonset = _load_json(args.daemonset, "DaemonSet")
        pods = _load_json(args.pods, "PodList")
    print(json.dumps(build(daemonset, pods), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("BUILD AGENT INVENTORY FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
