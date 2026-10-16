#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Build the collection manifest deterministically and merge per-node logs.
#
# The expected agent-node list and readiness state come from an inventory built
# from the DaemonSet and all of its owned Pods. NotReady, terminating, missing,
# duplicate, or uncollected agents keep nodeSetComplete=false. For every
# collected node a log file must be supplied:
# read=true only when the copy command exited successfully and the local file
# exists. An empty file is valid evidence that the node was read and currently
# has no retained violations. A missing/unreadable file is read=false.
#
# Usage:
#   build_manifest.py \
#     --start-agent-inventory agent-start.json \
#     --end-agent-inventory agent-end.json \
#     --window-start 1710000000 --window-end 1710003600 \
#     --node n1 --log n1.log \
#     --node n2 --log n2.log \
#     --out-manifest manifest.json --out-logs merged.log
#
# Per node it counts lines that fail JSON parsing and derives earliest/latest
# eventTimestamp values. Retention is covered only when every readable node has
# a retained event at or before the window start. This is intentionally
# conservative: absent evidence remains unknown rather than caller-asserted.

import argparse
import json
import os
import sys
import time

import collect_violations
import vopt_common as common


def _inspect_lines(lines, expected_node=None):
    errors = 0
    node_mismatches = 0
    timestamps = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = collect_violations.parse_log_line(stripped)
        except ValueError:
            errors += 1
            continue
        timestamp = record.get("eventTimestamp")
        if collect_violations.valid_event_timestamp(timestamp):
            timestamps.append(timestamp)
        else:
            errors += 1
        if expected_node and record.get("nodeName") not in (None, "", expected_node):
            node_mismatches += 1
    return {
        "parseErrors": errors,
        "nodeIdentityMismatches": node_mismatches,
        "earliestEventTimestamp": min(timestamps) if timestamps else None,
        "latestEventTimestamp": max(timestamps) if timestamps else None,
    }


def _unique_nodes(nodes, label, allow_empty=False):
    if not isinstance(nodes, list) or (not nodes and not allow_empty):
        raise common.ValidationError("%s must contain at least one node" % label)
    normalized = []
    seen = set()
    for value in nodes:
        if not isinstance(value, str) or not value.strip():
            raise common.ValidationError("%s contains an empty node" % label)
        node = value.strip()
        if node in seen:
            raise common.ValidationError("%s contains duplicate node %r" % (label, node))
        seen.add(node)
        normalized.append(node)
    return normalized


def load_agent_inventory(path):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, ValueError) as error:
        raise common.ValidationError(
            "cannot read agent inventory %r: %s" % (path, error)
        )
    if (
        not isinstance(payload, dict)
        or payload.get("inventoryVersion") != 2
        or not isinstance(payload.get("capturedAt"), int)
        or isinstance(payload.get("capturedAt"), bool)
        or not isinstance(payload.get("daemonSet"), dict)
        or not isinstance(payload.get("agents"), list)
        or not isinstance(payload.get("issues"), list)
        or not isinstance(payload.get("inventoryComplete"), bool)
    ):
        raise common.ValidationError("agent inventory is malformed")
    return payload


def _inventory_state(inventory):
    daemonset = inventory["daemonSet"]
    agents = inventory["agents"]
    required_counts = (
        "generation",
        "observedGeneration",
        "desiredNumberScheduled",
        "currentNumberScheduled",
        "numberReady",
    )
    for field in required_counts:
        value = daemonset.get(field)
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or value < 0
        ):
            raise common.ValidationError(
                "agent inventory daemonSet.%s must be a non-negative integer"
                % field
            )

    for field in ("namespace", "name", "uid", "resourceVersion"):
        value = daemonset.get(field)
        if not isinstance(value, str) or not value.strip():
            raise common.ValidationError(
                "agent inventory daemonSet.%s must be a non-empty string" % field
            )

    captured_at = inventory["capturedAt"]
    if captured_at < 0:
        raise common.ValidationError(
            "agent inventory capturedAt must be a non-negative integer"
        )

    nodes = []
    normalized_agents = []
    for index, agent in enumerate(agents):
        if not isinstance(agent, dict):
            raise common.ValidationError(
                "agent inventory agents[%d] must be an object" % index
            )
        node = agent.get("node")
        pod = agent.get("pod")
        uid = agent.get("uid")
        if (
            not isinstance(node, str)
            or not isinstance(pod, str)
            or not pod
            or not isinstance(uid, str)
            or not uid
        ):
            raise common.ValidationError(
                "agent inventory agents[%d] has invalid node, pod, or uid" % index
            )
        normalized = {
            "node": node.strip(),
            "pod": pod,
            "uid": uid,
            "ready": agent.get("ready") is True,
            "terminating": agent.get("terminating") is True,
        }
        normalized_agents.append(normalized)
        if normalized["node"]:
            nodes.append(normalized["node"])

    desired = daemonset["desiredNumberScheduled"]
    derived_complete = (
        desired > 0
        and daemonset["observedGeneration"] == daemonset["generation"]
        and daemonset["currentNumberScheduled"] == desired
        and daemonset["numberReady"] == desired
        and len(normalized_agents) == desired
        and len(nodes) == desired
        and len(nodes) == len(set(nodes))
        and all(
            agent["ready"] and not agent["terminating"]
            for agent in normalized_agents
        )
        and not inventory["issues"]
    )
    complete = inventory["inventoryComplete"] is True and derived_complete
    return {
        "capturedAt": captured_at,
        "nodes": sorted(nodes),
        "agents": normalized_agents,
        "complete": complete,
        "daemonSet": daemonset,
        "issues": inventory["issues"],
    }


def build(
    start_agent_inventory,
    end_agent_inventory,
    node_log_exit,
    window_start,
    window_end,
    manifest_built_at=None,
):
    if window_start > window_end:
        raise common.ValidationError("window start cannot be later than window end")
    if manifest_built_at is None:
        manifest_built_at = time.time()
    if (
        not collect_violations.valid_event_timestamp(manifest_built_at)
    ):
        raise common.ValidationError("manifest build time must be a non-negative epoch")

    start_state = _inventory_state(start_agent_inventory)
    end_state = _inventory_state(end_agent_inventory)
    if start_state["capturedAt"] > window_start:
        raise common.ValidationError(
            "window start is earlier than the start agent inventory"
        )

    start_nodes = set(start_state["nodes"])
    end_nodes = set(end_state["nodes"])
    expected_nodes = sorted(start_nodes | end_nodes)
    disappeared = sorted(start_nodes - end_nodes)
    appeared = sorted(end_nodes - start_nodes)
    start_agents = {
        agent["node"]: agent for agent in start_state["agents"] if agent["node"]
    }
    end_agents = {
        agent["node"]: agent for agent in end_state["agents"] if agent["node"]
    }
    replaced = sorted(
        node
        for node in start_nodes & end_nodes
        if start_agents[node]["uid"] != end_agents[node]["uid"]
    )
    start_ds = start_state["daemonSet"]
    end_ds = end_state["daemonSet"]
    daemonset_changed = any(
        start_ds.get(field) != end_ds.get(field)
        for field in ("namespace", "name", "uid", "generation")
    )
    continuity_complete = (
        start_state["complete"]
        and end_state["complete"]
        and not disappeared
        and not appeared
        and not replaced
        and not daemonset_changed
    )

    actual_nodes = _unique_nodes(
        [entry[0] for entry in node_log_exit],
        "collected nodes",
        allow_empty=True,
    )
    expected_set = set(expected_nodes)
    actual_set = set(actual_nodes)
    missing = sorted(expected_set - actual_set)
    unexpected = sorted(actual_set - expected_set)
    node_set_complete = (
        continuity_complete
        and not missing
        and not unexpected
    )

    nodes = []
    merged_lines = []
    total_parse_errors = 0
    by_node = {entry[0]: entry for entry in node_log_exit}
    # A typo must not let one local file stand in for two expected nodes.
    seen_files = set()
    for _, path, _ in node_log_exit:
        try:
            info = os.stat(path)
        except OSError:
            continue  # recorded as unread below
        identity = (info.st_dev, info.st_ino)
        if identity in seen_files:
            raise common.ValidationError("each node must have a distinct local log file")
        seen_files.add(identity)
    agent_by_node = dict(start_agents)
    agent_by_node.update(end_agents)

    for node in expected_nodes:
        agent = agent_by_node[node]
        collected = by_node.get(node)
        entry = {
            "node": node,
            "pod": agent["pod"],
            "agentReady": agent["ready"],
            "agentTerminating": agent["terminating"],
            "read": False,
            "exit": collected[2] if collected else None,
        }
        if collected is None:
            entry["retention"] = {
                "status": "unknown",
                "basis": "node-not-collected",
            }
            nodes.append(entry)
            continue
        _, path, exit_code = collected
        try:
            file_info = os.stat(path)
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()
        except (OSError, UnicodeError):
            entry["retention"] = {
                "status": "unknown",
                "basis": "local-log-unreadable",
            }
            nodes.append(entry)
            continue

        lines = content.splitlines()
        byte_count = len(content.encode("utf-8"))
        node_collected_at = file_info.st_mtime
        # Coverage is defined by exec success (exit==0). A non-zero exit with
        # partial output (e.g. main log missing, only a rotated file read) is a
        # partial read: fail closed and do not merge its lines. exit==0 with an
        # empty file means the node was covered but had no violations.
        if exit_code != 0:
            entry["retention"] = {
                "status": "unknown",
                "basis": "node-read-failed",
            }
            nodes.append(entry)
            continue

        inspection = _inspect_lines(lines, expected_node=node)
        parse_errors = inspection["parseErrors"]
        entry.update(
            {
                "read": True,
                "bytes": byte_count,
                "lines": len(lines),
                "parseErrors": parse_errors,
                "nodeIdentityMismatches": inspection["nodeIdentityMismatches"],
                "collectionStartedAt": node_collected_at,
                "collectedAt": node_collected_at,
                "collectedAfterWindow": node_collected_at >= window_end,
                "earliestEventTimestamp": inspection["earliestEventTimestamp"],
                "latestEventTimestamp": inspection["latestEventTimestamp"],
            }
        )
        if node_collected_at < window_end:
            retention = {"status": "unknown", "basis": "log-collected-before-window-end"}
        elif inspection["nodeIdentityMismatches"]:
            retention = {"status": "unknown", "basis": "node-identity-mismatch"}
        elif parse_errors:
            retention = {
                "status": "unknown",
                "basis": "unparseable-log-lines",
            }
        elif inspection["earliestEventTimestamp"] is None:
            retention = {
                "status": "unknown",
                "basis": "no-timestamped-events",
            }
        elif inspection["earliestEventTimestamp"] <= window_start:
            retention = {
                "status": "covered",
                "basis": "earliest-retained-event-at-or-before-window-start",
            }
        else:
            retention = {
                "status": "unknown",
                "basis": "earliest-retained-event-after-window-start",
            }
        entry["retention"] = retention
        total_parse_errors += parse_errors
        merged_lines.extend(lines)
        nodes.append(entry)

    retention_covered = all(
        node.get("retention", {}).get("status") == "covered" for node in nodes
    ) and node_set_complete
    readable_collection_times = [
        node["collectedAt"] for node in nodes if node.get("read") is True
    ]
    logs_collected_after_window = (
        len(readable_collection_times) == len(expected_nodes)
        and all(value >= window_end for value in readable_collection_times)
    )
    window_complete = (
        end_state["capturedAt"] >= window_end
        and manifest_built_at >= end_state["capturedAt"]
        and manifest_built_at >= window_end
        and logs_collected_after_window
    )
    manifest = {
        "window": {"start": window_start, "end": window_end},
        "collectionStartedAt": (
            min(readable_collection_times) if readable_collection_times else None
        ),
        "collectedAt": (
            min(readable_collection_times) if readable_collection_times else None
        ),
        "manifestBuiltAt": manifest_built_at,
        "windowComplete": window_complete,
        "logsCollectedAfterWindow": logs_collected_after_window,
        "expectedNodes": expected_nodes,
        "collectedNodes": actual_nodes,
        "missingCollectedNodes": missing,
        "unexpectedCollectedNodes": unexpected,
        "agentInventoryComplete": continuity_complete,
        "startAgentInventoryComplete": start_state["complete"],
        "endAgentInventoryComplete": end_state["complete"],
        "startAgentInventoryCapturedAt": start_state["capturedAt"],
        "endAgentInventoryCapturedAt": end_state["capturedAt"],
        "startAgentInventoryIssues": start_state["issues"],
        "endAgentInventoryIssues": end_state["issues"],
        "disappearedNodes": disappeared,
        "appearedNodes": appeared,
        "replacedAgentNodes": replaced,
        "daemonSetChanged": daemonset_changed,
        "startDaemonSet": start_ds,
        "endDaemonSet": end_ds,
        "nodeSetComplete": node_set_complete,
        "retentionCovered": retention_covered,
        "retentionStatus": "true" if retention_covered else "unknown",
        "retentionEvidence": {
            "windowStart": window_start,
            "basis": "per-node-earliest-retained-event",
        },
        "parseErrors": total_parse_errors,
        "nodes": nodes,
    }
    return manifest, "\n".join(merged_lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--start-agent-inventory",
        required=True,
        help="agent inventory captured before the observation window",
    )
    parser.add_argument(
        "--end-agent-inventory",
        required=True,
        help="agent inventory captured after the observation window",
    )
    parser.add_argument(
        "--window-start",
        required=True,
        help="fixed observation-window start (epoch or ISO 8601)",
    )
    parser.add_argument(
        "--window-end",
        required=True,
        help="fixed observation-window end (epoch or ISO 8601)",
    )
    parser.add_argument(
        "--node",
        action="append",
        dest="nodes",
        default=[],
        help="collected node (repeat; pair each with --log)",
    )
    parser.add_argument(
        "--log",
        action="append",
        dest="logs",
        default=[],
        help="per-node log file (repeat, same order as --node)",
    )
    parser.add_argument(
        "--exit",
        action="append",
        dest="exits",
        default=[],
        help="per-node kubectl exec exit code (repeat, same order as --node)",
    )
    parser.add_argument("--out-manifest", required=True)
    parser.add_argument("--out-logs", required=True)
    args = parser.parse_args()

    if not (len(args.nodes) == len(args.logs) == len(args.exits)):
        raise common.ValidationError(
            "each --node must be paired with one --log and one --exit"
        )

    try:
        exit_codes = [int(value) for value in args.exits]
    except ValueError:
        raise common.ValidationError("--exit values must be integers")

    triples = list(zip(args.nodes, args.logs, exit_codes))
    start_agent_inventory = load_agent_inventory(args.start_agent_inventory)
    end_agent_inventory = load_agent_inventory(args.end_agent_inventory)
    window_start = collect_violations.parse_timestamp(args.window_start)
    window_end = collect_violations.parse_timestamp(args.window_end)
    manifest, merged = build(
        start_agent_inventory,
        end_agent_inventory,
        triples,
        window_start,
        window_end,
    )

    with open(args.out_manifest, "w", encoding="utf-8") as handle:
        json.dump(manifest, handle, ensure_ascii=False, indent=2)
    os.chmod(args.out_manifest, 0o600)
    with open(args.out_logs, "w", encoding="utf-8") as handle:
        handle.write(merged)
    os.chmod(args.out_logs, 0o600)

    unread = [n["node"] for n in manifest["nodes"] if not n["read"]]
    print(
        "manifest: %d node(s), %d unread, %d parse error(s)"
        % (len(manifest["nodes"]), len(unread), manifest["parseErrors"]),
        file=sys.stderr,
    )
    if unread:
        print("  unread: %s" % ", ".join(unread), file=sys.stderr)
    if not manifest["windowComplete"]:
        print(
            "  collection completed before the observation window ended; "
            "removal must remain blocked",
            file=sys.stderr,
        )
    if not manifest["retentionCovered"]:
        print(
            "  retention coverage is %s; removal must remain blocked"
            % manifest["retentionStatus"],
            file=sys.stderr,
        )


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("BUILD MANIFEST FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
