#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministic collection, filtering, preprocessing, and cross-record global
# aggregation for vArmor violations. The compact path accepts per-node logs
# plus start/end inventories and emits one self-contained pre.json. It also
# builds the rule_catalog used for attribution.
#
# Ported from policy-optimization-agent/internal/logpreprocess and
# internal/logaggregate. No business semantics are judged here.

import argparse
import ipaddress
import json
import sys
from urllib.parse import urlsplit

import build_manifest
import collect_violations
import vopt_common as common
import pathnorm

APPARMOR_IGNORED = {
    "version", "event", "task", "magicToken", "epoch", "auditSubID", "bitMask",
    "auditID", "pid", "peerPID", "parent", "namespace", "attribute", "info",
    "peerInfo", "errorCode",
}
NETWORKPROXY_IGNORED = {"durationMs", "responseCode", "reason", "filterChain"}

APPARMOR_FILE_OPERATIONS = {
    "open", "file_perm", "file_mmap", "file_lock", "file_inherit", "create",
    "mkdir", "mknod", "rename_src", "rename_dest", "unlink", "rmdir",
    "symlink", "link", "truncate", "chmod", "chown", "getattr", "setattr",
    "getxattr", "setxattr", "removexattr",
}

MAX_EXAMPLES = 3
MAX_FOREIGN_ENDPOINTS = 16
NETWORK_PROXY_EVIDENCE_STATUSES = (
    "not-applicable",
    "eligible",
    "ineligible",
)


# ---------------------------------------------------------------------------
# Cleaning
# ---------------------------------------------------------------------------

def clean_value(value):
    if value is None:
        return None, False
    if isinstance(value, str):
        return value, value != ""
    if isinstance(value, dict):
        cleaned = clean_object(value)
        return cleaned, bool(cleaned)
    if isinstance(value, list):
        items = []
        for item in value:
            cleaned, keep = clean_value(item)
            if keep:
                items.append(cleaned)
        return items, bool(items)
    return value, True


def clean_object(obj):
    for key in list(obj.keys()):
        cleaned, keep = clean_value(obj[key])
        if not keep:
            del obj[key]
        else:
            obj[key] = cleaned
    return obj


def sorted_string_set(values):
    strings = [v for v in values if isinstance(v, str) and v != ""]
    return sorted(set(strings))


def normalize_bpf_arrays(event):
    for field in ("permissions", "flags"):
        value = event.get(field)
        if isinstance(value, list):
            normalized = sorted_string_set(value)
            if normalized:
                event[field] = normalized
            else:
                event.pop(field, None)


# ---------------------------------------------------------------------------
# Preprocess a batch of matched records
# ---------------------------------------------------------------------------

def preprocess(
    records,
    catalog,
    manifest=None,
    collection_counts=None,
    collection_window=None,
    network_proxy_evidence_status="not-applicable",
):
    if network_proxy_evidence_status not in NETWORK_PROXY_EVIDENCE_STATUSES:
        raise common.ValidationError(
            "invalid network proxy evidence status %r"
            % network_proxy_evidence_status
        )
    events = []
    seccomp_syscalls = set()
    failures = []
    raw_count = 0
    enforcer_counts = {}

    for record in records:
        raw_count += 1
        enforcer = record.get("enforcer")
        if not isinstance(enforcer, str) or enforcer not in {
            "AppArmor", "BPF", "Seccomp", "NetworkProxy"
        }:
            failures.append({"reason": "missing or invalid enforcer"})
            continue
        enforcer_counts[enforcer] = enforcer_counts.get(enforcer, 0) + 1
        event = record.get("event")
        if not isinstance(event, dict):
            failures.append({"enforcer": enforcer, "reason": "event must be an object"})
            continue

        if enforcer == "Seccomp":
            syscall = event.get("syscall")
            if not isinstance(syscall, str) or not syscall.strip():
                failures.append({"enforcer": enforcer, "reason": "syscall is required"})
                continue
            seccomp_syscalls.add(syscall.strip())
            continue

        if enforcer == "AppArmor":
            for field in APPARMOR_IGNORED:
                event.pop(field, None)
            clean_object(event)
        elif enforcer == "NetworkProxy":
            for field in NETWORKPROXY_IGNORED:
                event.pop(field, None)
            clean_object(event)
        else:  # BPF and any unknown enforcer
            clean_object(event)
            normalize_bpf_arrays(event)

        events.append({"enforcer": enforcer, "event": event})

    # Collection integrity combines:
    #   - no unparsable lines (collect counts.parseErrors == 0)
    #   - every expected node was actually read successfully (manifest)
    manifest_parse_errors = 0
    collection_parse_errors = 0
    nodes_complete = True
    node_set_complete = False
    agent_inventory_complete = False
    window_complete = False
    retention_covered = False
    if isinstance(manifest, dict):
        manifest_parse_errors = int(manifest.get("parseErrors") or 0)
        nodes = manifest.get("nodes") or []
        expected_nodes = manifest.get("expectedNodes") or []
        node_names = [
            node.get("node") for node in nodes if isinstance(node, dict)
        ]
        expected_unique = (
            bool(expected_nodes)
            and all(isinstance(node, str) and node for node in expected_nodes)
            and len(expected_nodes) == len(set(expected_nodes))
        )
        actual_unique = (
            bool(node_names)
            and all(isinstance(node, str) and node for node in node_names)
            and len(node_names) == len(set(node_names))
        )
        node_set_complete = (
            manifest.get("agentInventoryComplete") is True
            and manifest.get("nodeSetComplete") is True
            and expected_unique
            and actual_unique
            and set(expected_nodes) == set(node_names)
        )
        agent_inventory_complete = (
            manifest.get("agentInventoryComplete") is True
        )
        manifest_window = manifest.get("window")
        collected_at = manifest.get("collectedAt")
        manifest_built_at = manifest.get("manifestBuiltAt")
        if (
            isinstance(manifest_window, dict)
            and isinstance(manifest_window.get("start"), int)
            and not isinstance(manifest_window.get("start"), bool)
            and isinstance(manifest_window.get("end"), int)
            and not isinstance(manifest_window.get("end"), bool)
            and collect_violations.valid_event_timestamp(collected_at)
            and collect_violations.valid_event_timestamp(manifest_built_at)
        ):
            window_complete = (
                manifest.get("windowComplete") is True
                and (
                    (manifest.get("collectionMode", "snapshot") == "snapshot"
                     and manifest.get("logsCollectedAfterWindow") is True)
                    or (manifest.get("collectionMode") == "incremental"
                        and manifest.get("finalReadComplete") is True
                        and isinstance(manifest.get("collectionIssues", []), list)
                        and not any(
                            not isinstance(item, dict)
                            or item.get("severity") != "suspected"
                            or not collect_violations.valid_event_timestamp(item.get("resolvedAt"))
                            for item in manifest.get("collectionIssues", []))
                        and isinstance(manifest.get("settleIntervalSeconds"), (int, float))
                        and not isinstance(manifest["settleIntervalSeconds"], bool)
                        and manifest["settleIntervalSeconds"] > 0
                        and actual_unique
                        and all(
                            isinstance(node.get("incremental"), dict)
                            and collect_violations.valid_event_timestamp(
                                node["incremental"].get("coveredFrom"))
                            and node["incremental"]["coveredFrom"] < manifest_window["start"]
                            and collect_violations.valid_event_timestamp(
                                node["incremental"].get("lastReadStartedAt"))
                            and node["incremental"]["lastReadStartedAt"] >= manifest_window["end"]
                            and collect_violations.valid_event_timestamp(
                                node["incremental"].get("lastDrainedAt"))
                            and node["incremental"]["lastDrainedAt"] >= manifest_window["end"]
                            and node["incremental"].get("backlogBytes") == 0
                            and type(node["incremental"].get("cleanReads")) is int
                            and node["incremental"].get("cleanReads", 0) >= 2
                            and collect_violations.valid_event_timestamp(
                                node["incremental"].get("firstCleanCompletedAt"))
                            and collect_violations.valid_event_timestamp(
                                node["incremental"].get("confirmationReadStartedAt"))
                            and node["incremental"]["confirmationReadStartedAt"] >=
                                node["incremental"]["firstCleanCompletedAt"] + manifest["settleIntervalSeconds"]
                            for node in nodes))
                )
                and manifest_window["start"] <= manifest_window["end"]
                and collected_at >= manifest_window["end"]
                and manifest_built_at >= manifest_window["end"]
                and (
                    collection_window is None
                    or collection_window == manifest_window
                )
            )
        nodes_complete = (
            node_set_complete
            and all(node.get("read") is True for node in nodes)
        )
        per_node_retention = all(
            isinstance(node, dict)
            and node.get("retention", {}).get("status") == "covered"
            for node in nodes
        )
        retention_covered = (
            manifest.get("retentionCovered") is True
            and per_node_retention
            and nodes_complete
        )
    if isinstance(collection_counts, dict):
        collection_parse_errors = int(collection_counts.get("parseErrors") or 0)
    collection_complete = (
        manifest_parse_errors == 0
        and collection_parse_errors == 0
        and window_complete
        and nodes_complete
        and retention_covered
        and not failures
    )

    return {
        "events": events,
        "collectionComplete": collection_complete,
        "networkProxyEvidenceEligible": (
            network_proxy_evidence_status == "eligible"
        ),
        "networkProxyEvidenceStatus": network_proxy_evidence_status,
        "seccompSyscalls": sorted(seccomp_syscalls),
        "failures": failures,
        "statistics": {
            "rawCount": raw_count,
            "enforcerCounts": enforcer_counts,
            "failureCount": len(failures),
            "manifestParseErrors": manifest_parse_errors,
            "collectionParseErrors": collection_parse_errors,
            "windowComplete": window_complete,
            "agentInventoryComplete": agent_inventory_complete,
            "nodeSetComplete": node_set_complete,
            "retentionCovered": retention_covered,
            "seccompCount": len(seccomp_syscalls),
            "nonSeccompEventCount": len(events),
        },
    }


def validate_network_proxy_evidence(policy, status, catalog):
    if status not in NETWORK_PROXY_EVIDENCE_STATUSES:
        raise common.ValidationError(
            "network proxy evidence status must be one of %s"
            % ", ".join(NETWORK_PROXY_EVIDENCE_STATUSES)
        )
    enforcer = common.get_path(policy, "spec", "policy", "enforcer")
    parsed, valid = common.parse_enforcers(enforcer, catalog)
    if not valid:
        raise common.ValidationError("policy has an invalid enforcer")
    applicable = common.ENFORCER_NETWORKPROXY in parsed
    if applicable and status == "not-applicable":
        raise common.ValidationError(
            "NetworkProxy policy requires eligible or ineligible evidence status"
        )
    if not applicable and status != "not-applicable":
        raise common.ValidationError(
            "network proxy evidence must be not-applicable when the policy "
            "does not use NetworkProxy"
        )


# ---------------------------------------------------------------------------
# Aggregation helpers
# ---------------------------------------------------------------------------

def _selected(source, fields):
    return {field: _clone(source[field]) for field in fields if field in source}


def _clone(value):
    if isinstance(value, dict):
        return {k: _clone(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_clone(v) for v in value]
    return value


def _set_merge(target, source, field):
    values = sorted_string_set(list(target.get(field, [])) + list(source.get(field, [])))
    if values:
        target[field] = values
    else:
        target.pop(field, None)


def _examples(target, source, field_output, field_orig=None):
    key = field_output + "Examples"
    merged = sorted_string_set(list(target.get(key, [])) + list(source.get(key, [])))
    if merged:
        target[key] = merged[:MAX_EXAMPLES]
    else:
        target.pop(key, None)


def _norm_path_into(output, field, original):
    if original == "":
        return
    normalized, changed = pathnorm.normalize_path(original)
    output[field] = normalized
    if changed:
        output[field + "Examples"] = [original]


def _key_for(output, fields):
    return common.stable_json({f: output.get(f) for f in fields})


# ---------------------------------------------------------------------------
# AppArmor classification
# ---------------------------------------------------------------------------

def classify_apparmor(event):
    operation = str(event.get("operation") or "").strip()

    if operation == "capable":
        out = _selected(event, ["operation", "profile", "name"])
        out["_aggregation"] = "apparmor.capability"
        if event.get("comm"):
            out["comms"] = sorted_string_set([event["comm"]])
        return "apparmor.capability", _key_for(out, ["profile", "name"]), out

    if operation in ("mount", "umount"):
        out = _selected(event, ["operation", "profile", "name", "srcName", "fsType", "flags"])
        _norm_path_into(out, "name", out.get("name", ""))
        _norm_path_into(out, "srcName", out.get("srcName", ""))
        out["_aggregation"] = "apparmor.mount"
        if event.get("comm"):
            out["comms"] = sorted_string_set([event["comm"]])
        return (
            "apparmor.mount",
            _key_for(out, ["profile", "operation", "name", "srcName", "fsType", "flags"]),
            out,
        )

    if operation == "ptrace":
        out = _selected(event, ["operation", "profile", "peer", "peerProfile"])
        out["_aggregation"] = "apparmor.ptrace"
        if event.get("requestedMask"):
            out["requestedMasks"] = sorted_string_set([event["requestedMask"]])
        if event.get("deniedMask"):
            out["deniedMasks"] = sorted_string_set([event["deniedMask"]])
        return "apparmor.ptrace", _key_for(out, ["profile", "peer", "peerProfile"]), out

    if operation == "signal":
        out = _selected(event, ["operation", "profile", "peer", "peerProfile"])
        effect = {}
        if event.get("signal"):
            effect["signal"] = event["signal"]
        if event.get("deniedMask"):
            effect["deniedMask"] = event["deniedMask"]
        if effect:
            out["effects"] = [effect]
        out["_aggregation"] = "apparmor.signal"
        return "apparmor.signal", _key_for(out, ["profile", "peer", "peerProfile"]), out

    if operation.startswith("dbus_"):
        out = _selected(
            event,
            ["operation", "profile", "dbusBus", "dbusPath", "dbusInterface",
             "dbusMember", "peer", "peerProfile", "deniedMask"],
        )
        out["_aggregation"] = "apparmor.dbus"
        return (
            "apparmor.dbus",
            _key_for(
                out,
                ["profile", "operation", "dbusBus", "dbusPath", "dbusInterface",
                 "dbusMember", "peer", "peerProfile", "deniedMask"],
            ),
            out,
        )

    if operation == "exec":
        out = _selected(event, ["operation", "profile", "name"])
        _norm_path_into(out, "name", out.get("name", ""))
        access = {}
        if event.get("deniedMask"):
            access["deniedMask"] = event["deniedMask"]
        if event.get("requestedMask"):
            access["requestedMask"] = event["requestedMask"]
        if access:
            out["accesses"] = [access]
        if event.get("comm"):
            out["comms"] = sorted_string_set([event["comm"]])
        out["_aggregation"] = "apparmor.exec"
        return "apparmor.exec", _key_for(out, ["profile", "name"]), out

    if any(event.get(field) for field in ("netFamily", "netSockType", "netProtocol")):
        out = _selected(event, ["profile", "netFamily", "netSockType", "netProtocol"])
        endpoint = {}
        foreign = event.get("netForeignAddr")
        if isinstance(foreign, str) and foreign:
            parsed = _parse_ip(foreign)
            if parsed:
                endpoint["addr"] = parsed
        port = event.get("netForeignPort")
        if isinstance(port, int) and not isinstance(port, bool) and 0 < port <= 65535:
            endpoint["port"] = port
        if endpoint:
            out["foreignEndpoints"] = [endpoint]
        out["_aggregation"] = "apparmor.network"
        return (
            "apparmor.network",
            _key_for(out, ["profile", "netFamily", "netSockType", "netProtocol"]),
            out,
        )

    if operation in APPARMOR_FILE_OPERATIONS and event.get("name"):
        out = _selected(event, ["profile", "name", "name2"])
        _norm_path_into(out, "name", out.get("name", ""))
        _norm_path_into(out, "name2", out.get("name2", ""))
        access = _selected(event, ["operation", "deniedMask", "requestedMask", "fsuid", "ouid"])
        if access:
            out["accesses"] = [access]
        if event.get("comm"):
            out["comms"] = sorted_string_set([event["comm"]])
        out["_aggregation"] = "apparmor.file"
        return "apparmor.file", _key_for(out, ["profile", "name", "name2"]), out

    out = _clone(event)
    out["_aggregation"] = "apparmor.unknown"
    return "apparmor.unknown", common.stable_json(event), out


# ---------------------------------------------------------------------------
# BPF classification
# ---------------------------------------------------------------------------

def classify_bpf(event):
    operation = str(event.get("operation") or "").strip()

    if operation == "Capability":
        capability = str(event.get("capability") or "").strip()
        if not capability or capability.lower() == "unknown":
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = {
            "_aggregation": "bpf.capability",
            "operation": operation,
            "capabilities": [capability],
        }
        return "bpf.capability", _key_for(out, []), out

    if operation == "File":
        path = str(event.get("path") or "").strip()
        if not path:
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = _selected(event, ["operation", "path"])
        normalized, changed = pathnorm.normalize_path(path)
        out["path"] = normalized
        if changed:
            out["pathExamples"] = [path]
        if isinstance(event.get("permissions"), list):
            out["permissions"] = sorted_string_set(event["permissions"])
        out["_aggregation"] = "bpf.file"
        return "bpf.file", _key_for(out, ["path"]), out

    if operation == "Bprm":
        path = str(event.get("path") or "").strip()
        if not path:
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = _selected(event, ["operation", "path"])
        normalized, changed = pathnorm.normalize_path(path)
        out["path"] = normalized
        if changed:
            out["pathExamples"] = [path]
        out["_aggregation"] = "bpf.bprm"
        return "bpf.bprm", _key_for(out, ["path"]), out

    if operation == "Network":
        return classify_bpf_network(event)

    if operation == "Ptrace":
        external = event.get("external")
        if not isinstance(external, bool):
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = {"_aggregation": "bpf.ptrace", "operation": operation, "external": external}
        if event.get("permission"):
            out["permissions"] = sorted_string_set([event["permission"]])
        return "bpf.ptrace", _key_for(out, ["external"]), out

    if operation == "Mount":
        path = str(event.get("path") or "").strip()
        fstype = str(event.get("type") or "").strip()
        if not path or not fstype:
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = _selected(event, ["operation", "path", "type"])
        normalized, changed = pathnorm.normalize_path(path)
        out["path"] = normalized
        if changed:
            out["pathExamples"] = [path]
        if isinstance(event.get("flags"), list):
            out["flags"] = sorted_string_set(event["flags"])
        out["_aggregation"] = "bpf.mount"
        return "bpf.mount", _key_for(out, ["path", "type"]), out

    out = _clone(event)
    out["_aggregation"] = "bpf.unknown"
    return "bpf.unknown", common.stable_json(event), out


def classify_bpf_network(event):
    etype = str(event.get("type") or "").strip()
    if etype == "socket":
        socket = event.get("socket")
        socket = socket if isinstance(socket, dict) else {}
        out = {
            "_aggregation": "bpf.network.socket",
            "operation": "Network",
            "type": "socket",
            "socket": _selected(socket, ["domain", "type", "protocol"]),
        }
        return "bpf.network.socket", _key_for(out, ["socket"]), out
    if etype == "connect":
        address = event.get("address")
        address = address if isinstance(address, dict) else {}
        ip = _parse_ip(str(address.get("ip") or ""))
        port = address.get("port")
        if not ip or not isinstance(port, int) or isinstance(port, bool) or not 0 < port <= 65535:
            out = _clone(event)
            out["_aggregation"] = "bpf.unknown"
            return "bpf.unknown", common.stable_json(event), out
        out = {
            "_aggregation": "bpf.network.connect",
            "operation": "Network",
            "type": "connect",
            "address": {"ip": ip, "ports": [port]},
        }
        key = common.stable_json({"type": "connect", "address": {"ip": ip}})
        return "bpf.network.connect", key, out
    out = _clone(event)
    out["_aggregation"] = "bpf.unknown"
    return "bpf.unknown", common.stable_json(event), out


# ---------------------------------------------------------------------------
# NetworkProxy classification
# ---------------------------------------------------------------------------

def _split_host_port(value):
    value = str(value).strip()
    if not value:
        return None, None, False
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return None, None, False
        host = value[1:end]
        rest = value[end + 1:]
        port = rest[1:] if rest.startswith(":") else None
    else:
        if value.count(":") > 1:
            return None, None, False
        if ":" in value:
            host, port = value.rsplit(":", 1)
        else:
            host, port = value, None
    ip = _parse_ip(host)
    if ip is None:
        return None, None, False
    if port is not None:
        try:
            port = int(port)
        except ValueError:
            return None, None, False
        if not 0 < port <= 65535:
            return None, None, False
    else:
        port = 0
    return ip, port, True


def _parse_ip(value):
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _split_authority(value):
    value = str(value).strip()
    if not value:
        return "", 0, False
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            return "", 0, False
        host = value[1:end]
        rest = value[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") else 0
    elif value.count(":") == 1:
        host, raw_port = value.rsplit(":", 1)
        if not raw_port.isdigit():
            return "", 0, False
        port = int(raw_port)
    else:
        host, port = value, 0
    host = host.lower().rstrip(".")
    return host, port, bool(host)


def classify_networkproxy(event):
    layer = str(event.get("layer") or "").strip().upper()
    if layer not in ("L4", "L7"):
        out = _clone(event)
        out["_aggregation"] = "networkproxy.unknown"
        return "networkproxy.unknown", common.stable_json(event), out

    ip, port, ok = _split_host_port(event.get("dstAddress"))
    if not ok:
        out = _clone(event)
        out["_aggregation"] = "networkproxy.unknown"
        return "networkproxy.unknown", common.stable_json(event), out

    if layer == "L4":
        sni = str(event.get("sni") or "").strip().lower().rstrip(".")
        if not sni:
            out = {"_aggregation": "networkproxy.l4.ip", "layer": "L4", "dstIP": ip, "dstPort": port}
            return "networkproxy.l4.ip", _key_for(out, ["dstIP", "dstPort"]), out
        out = {
            "_aggregation": "networkproxy.l4.sni",
            "layer": "L4",
            "sni": sni,
            "dstPort": port,
            "dstIPs": [ip],
        }
        return "networkproxy.l4.sni", _key_for(out, ["sni", "dstPort"]), out

    authority, authority_port, authority_ok = _split_authority(event.get("authority"))
    method = str(event.get("method") or "").strip().upper()
    path = _http_path(event.get("path"))
    if not authority_ok or not method or not path:
        out = _clone(event)
        out["_aggregation"] = "networkproxy.unknown"
        return "networkproxy.unknown", common.stable_json(event), out
    out = {
        "_aggregation": "networkproxy.l7",
        "layer": "L7",
        "sni": str(event.get("sni") or "").strip().lower().rstrip("."),
        "authority": authority,
        "dstPort": port,
        "authorityPort": authority_port,
        "method": method,
        "path": path,
        "dstIPs": [ip],
    }
    return (
        "networkproxy.l7",
        _key_for(
            out,
            ["sni", "authority", "dstPort", "authorityPort", "method", "path"],
        ),
        out,
    )


def _http_path(value):
    value = str(value or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    return parsed.path or ""


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------

def _merge(kind, target, source):
    if kind in ("apparmor.capability", "apparmor.mount"):
        _set_merge(target, source, "comms")
    elif kind == "apparmor.ptrace":
        _set_merge(target, source, "requestedMasks")
        _set_merge(target, source, "deniedMasks")
    elif kind == "apparmor.signal":
        _merge_object_set(target, source, "effects")
    elif kind == "apparmor.exec":
        _merge_object_set(target, source, "accesses")
        _set_merge(target, source, "comms")
    elif kind == "apparmor.network":
        _merge_capped_objects(target, source, "foreignEndpoints", MAX_FOREIGN_ENDPOINTS)
    elif kind == "apparmor.file":
        _merge_object_set(target, source, "accesses")
        _set_merge(target, source, "comms")
    elif kind == "bpf.capability":
        _set_merge(target, source, "capabilities")
    elif kind in ("bpf.file", "bpf.ptrace"):
        _set_merge(target, source, "permissions")
    elif kind == "bpf.network.connect":
        socket_t = target.get("address", {})
        socket_s = source.get("address", {})
        if isinstance(socket_t, dict) and isinstance(socket_s, dict):
            ports = sorted(set(socket_t.get("ports", [])) | set(socket_s.get("ports", [])))
            socket_t["ports"] = ports
    elif kind == "bpf.mount":
        _set_merge(target, source, "flags")
    elif kind in ("networkproxy.l4.sni", "networkproxy.l7"):
        _set_merge(target, source, "dstIPs")

    # Merge Examples payloads regardless of kind.
    for key in list(source.keys()):
        if key.endswith("Examples"):
            base_field = key[: -len("Examples")]
            merged = sorted_string_set(list(target.get(key, [])) + list(source.get(key, [])))
            if merged:
                target[key] = merged[:MAX_EXAMPLES]


def _object_key(obj):
    return common.stable_json(obj)


def _merge_object_set(target, source, field):
    merged = {}
    for obj in list(target.get(field, [])) + list(source.get(field, [])):
        merged[_object_key(obj)] = obj
    if merged:
        target[field] = list(merged.values())
    else:
        target.pop(field, None)


def _merge_capped_objects(target, source, field, cap):
    merged = {}
    for obj in list(target.get(field, [])) + list(source.get(field, [])):
        merged[_object_key(obj)] = obj
    values = list(merged.values())[:cap]
    if values:
        target[field] = values
        if len(merged) > cap:
            target[field + "Truncated"] = True
    else:
        target.pop(field, None)


def aggregate(events):
    buckets = {}
    order = []
    for item in events:
        enforcer = item["enforcer"]
        if enforcer == "AppArmor":
            kind, key, out = classify_apparmor(item["event"])
        elif enforcer == "BPF":
            kind, key, out = classify_bpf(item["event"])
        elif enforcer == "NetworkProxy":
            kind, key, out = classify_networkproxy(item["event"])
        else:
            out = _clone(item["event"])
            out["_aggregation"] = "unknown"
            kind, key = "unknown", common.stable_json(item["event"])
        identity = enforcer + "\x00" + kind + "\x00" + key
        if identity not in buckets:
            buckets[identity] = {"enforcer": enforcer, "kind": kind, "event": out}
            order.append(identity)
        else:
            _merge(kind, buckets[identity]["event"], out)

    result = []
    for index, identity in enumerate(order):
        result.append(
            {
                "eventId": "evt-%06d" % (index + 1),
                "enforcer": buckets[identity]["enforcer"],
                "event": buckets[identity]["event"],
            }
        )
    return result


def build_preprocess_output(
    payload,
    policy,
    catalog,
    network_proxy_evidence_status,
    manifest,
):
    validate_network_proxy_evidence(
        policy,
        network_proxy_evidence_status,
        catalog,
    )
    preprocessed = preprocess(
        payload.get("matched") or [],
        catalog,
        manifest=manifest,
        collection_counts=payload.get("counts"),
        collection_window=payload.get("window"),
        network_proxy_evidence_status=network_proxy_evidence_status,
    )
    return {
        "window": payload.get("window"),
        "collectionComplete": preprocessed["collectionComplete"],
        "agentInventoryComplete": preprocessed["statistics"][
            "agentInventoryComplete"
        ],
        "nodeSetComplete": preprocessed["statistics"]["nodeSetComplete"],
        "windowComplete": preprocessed["statistics"]["windowComplete"],
        "retentionCovered": preprocessed["statistics"]["retentionCovered"],
        "networkProxyEvidenceEligible": preprocessed[
            "networkProxyEvidenceEligible"
        ],
        "networkProxyEvidenceStatus": preprocessed[
            "networkProxyEvidenceStatus"
        ],
        "seccompSyscalls": preprocessed["seccompSyscalls"],
        "failures": preprocessed["failures"],
        "collectionCounts": payload.get("counts") or {},
        "collectionManifest": manifest,
        "statistics": preprocessed["statistics"],
        "aggregatedEvents": aggregate(preprocessed["events"]),
    }


def preprocess_node_logs(
    start_agent_inventory,
    end_agent_inventory,
    node_logs,
    window_start,
    window_end,
    policy,
    catalog,
    network_proxy_evidence_status,
    profile_name=None,
    policy_kind=None,
    policy_namespace=None,
    policy_name=None,
    manifest_built_at=None,
):
    # The baseline is already required; derive the identity from it rather
    # than asking the caller to copy the same scope into multiple flags.
    expected = {
        "profile_name": common.get_path(policy, "status", "profileName"),
        "policy_kind": policy.get("kind"),
        "policy_namespace": common.get_path(policy, "metadata", "namespace"),
        "policy_name": common.get_path(policy, "metadata", "name"),
    }
    if not isinstance(expected["profile_name"], str) or not expected["profile_name"].strip():
        raise common.ValidationError("current policy status.profileName is required")
    collect_violations.validate_identity_scope(
        expected["policy_kind"], expected["policy_namespace"], expected["policy_name"]
    )
    for key, supplied in (
        ("profile_name", profile_name), ("policy_kind", policy_kind),
        ("policy_namespace", policy_namespace), ("policy_name", policy_name),
    ):
        if supplied is not None and supplied != expected[key]:
            raise common.ValidationError("%s does not match the current policy" % key)
    triples = [(node, path, 0) for node, path in node_logs]
    manifest, merged = build_manifest.build(
        start_agent_inventory,
        end_agent_inventory,
        triples,
        window_start,
        window_end,
        manifest_built_at=manifest_built_at,
    )
    payload = collect_violations.collect(
        merged,
        window_start,
        window_end,
        kind=expected["policy_kind"],
        namespace=expected["policy_namespace"],
        name=expected["policy_name"],
        profile_name=expected["profile_name"],
    )
    return build_preprocess_output(
        payload,
        policy,
        catalog,
        network_proxy_evidence_status,
        manifest,
    )


# ---------------------------------------------------------------------------
# rule_catalog from the current policy
# ---------------------------------------------------------------------------

def build_rule_catalog(document, catalog):
    """Atomize the current enhanceProtect rules into catalog entries.

    Each entry: {source, rule, context, enforcers}. Seccomp rules are excluded
    because they are handled deterministically by seccomp_plan.py.
    """
    entries = []
    enhance = common.get_path(document, "spec", "policy", "enhanceProtect")
    if not isinstance(enhance, dict):
        return entries
    active_enforcers, valid = common.parse_enforcers(
        common.get_path(document, "spec", "policy", "enforcer"), catalog
    )
    if not valid:
        raise common.ValidationError("policy has an invalid enforcer")

    def add(source, rule, context=None, enforcers=None):
        entries.append(
            {
                "source": source,
                "rule": rule,
                "context": context or {},
                "enforcers": sorted(set(enforcers or []) & active_enforcers),
            }
        )

    def add_builtin(source, rule, context=None):
        enforcers = common.rule_enforcers(rule, catalog)
        if enforcers == [common.ENFORCER_SECCOMP]:
            return
        add(source, rule, context=context, enforcers=enforcers)

    for rule in enhance.get("hardeningRules") or []:
        add_builtin("hardeningRules", rule)
    for rule in enhance.get("vulMitigationRules") or []:
        add_builtin("vulMitigationRules", rule)

    for group in enhance.get("attackProtectionRules") or []:
        if not isinstance(group, dict):
            continue
        targets = group.get("targets") or []
        context = {"targets": targets} if targets else {}
        for rule in group.get("rules") or []:
            add_builtin(
                "attackProtectionRules",
                rule,
                context=context,
            )

    for group in enhance.get("appArmorRawRules") or []:
        if not isinstance(group, dict):
            continue
        targets = group.get("targets") or []
        context = {"targets": targets} if targets else {}
        for line in str(group.get("rules") or "").splitlines():
            line = line.strip().rstrip(",;")
            if line:
                add("appArmorRawRules", line, context=context, enforcers=["AppArmor"])

    bpf = enhance.get("bpfRawRules")
    if isinstance(bpf, dict):
        for field, source in (
            ("files", "bpfRawRules.files"),
            ("processes", "bpfRawRules.processes"),
            ("mounts", "bpfRawRules.mounts"),
        ):
            for obj in bpf.get(field) or []:
                add(source, _clone(obj), enforcers=["BPF"])
        if isinstance(bpf.get("ptrace"), dict):
            add("bpfRawRules.ptrace", _clone(bpf["ptrace"]), enforcers=["BPF"])
        network = bpf.get("network")
        if isinstance(network, dict):
            for obj in network.get("sockets") or []:
                add("bpfRawRules.network.sockets", _clone(obj), enforcers=["BPF"])
            egress = network.get("egress")
            if isinstance(egress, dict):
                for field, source in (
                    ("toDestinations", "bpfRawRules.network.egress.toDestinations"),
                    ("toServices", "bpfRawRules.network.egress.toServices"),
                    ("toPods", "bpfRawRules.network.egress.toPods"),
                ):
                    for obj in egress.get(field) or []:
                        add(source, _clone(obj), enforcers=["BPF"])

    network_proxy = enhance.get("networkProxyRawRules")
    if isinstance(network_proxy, dict):
        egress = network_proxy.get("egress")
        if isinstance(egress, dict):
            for field, source in (
                ("rules", "networkProxyRawRules.egress.rules"),
                ("httpRules", "networkProxyRawRules.egress.httpRules"),
            ):
                for obj in egress.get(field) or []:
                    add(source, _clone(obj), enforcers=["NetworkProxy"])

    return entries


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pre = sub.add_parser(
        "preprocess",
        help="build collection evidence, filter, preprocess, and aggregate",
    )
    pre.add_argument(
        "--file",
        help="legacy collect_violations result JSON (default: stdin in legacy mode)",
    )
    pre.add_argument(
        "--manifest",
        help="legacy collection manifest generated by build_manifest.py",
    )
    pre.add_argument("--start-agent-inventory")
    pre.add_argument("--end-agent-inventory")
    pre.add_argument("--window-start")
    pre.add_argument("--window-end")
    pre.add_argument("--node", action="append", default=[])
    pre.add_argument("--log", action="append", default=[])
    pre.add_argument("--profile-name")
    pre.add_argument("--policy-kind")
    pre.add_argument("--policy-namespace")
    pre.add_argument("--policy-name")
    pre.add_argument(
        "--policy",
        required=True,
        help="current policy YAML used to validate NetworkProxy applicability",
    )
    pre.add_argument(
        "--network-proxy-evidence",
        required=True,
        choices=NETWORK_PROXY_EVIDENCE_STATUSES,
        help="whether NetworkProxy log evidence is eligible for rule removal",
    )

    cat = sub.add_parser("catalog", help="build rule_catalog from the current policy")
    cat.add_argument("--file", help="policy YAML (default: stdin)")

    args = parser.parse_args()
    catalog = common.load_catalog()

    if args.command == "preprocess":
        policy = common.load_yaml_doc(common.read_input(args.policy))
        compact_values = (
            args.start_agent_inventory,
            args.end_agent_inventory,
            args.window_start,
            args.window_end,
        )
        compact_mode = any(value is not None for value in compact_values) or bool(
            args.node or args.log
        )
        if compact_mode:
            if args.file or args.manifest:
                raise common.ValidationError(
                    "compact node-log mode cannot use --file or --manifest"
                )
            if not all(value is not None for value in compact_values):
                raise common.ValidationError(
                    "compact mode requires start/end inventory and window start/end"
                )
            if len(args.node) != len(args.log) or not args.node:
                raise common.ValidationError(
                    "compact mode requires matching, non-empty --node/--log pairs"
                )
            collect_violations.validate_identity_scope(
                args.policy_kind,
                args.policy_namespace,
                args.policy_name,
            )
            start_inventory = build_manifest.load_agent_inventory(
                args.start_agent_inventory
            )
            end_inventory = build_manifest.load_agent_inventory(
                args.end_agent_inventory
            )
            output = preprocess_node_logs(
                start_inventory,
                end_inventory,
                list(zip(args.node, args.log)),
                collect_violations.parse_timestamp(args.window_start),
                collect_violations.parse_timestamp(args.window_end),
                policy,
                catalog,
                args.network_proxy_evidence,
                args.profile_name,
                policy_kind=args.policy_kind,
                policy_namespace=args.policy_namespace,
                policy_name=args.policy_name,
            )
        else:
            payload = json.loads(common.read_input(args.file))
            manifest = None
            if args.manifest:
                with open(args.manifest, "r", encoding="utf-8") as handle:
                    manifest = json.load(handle)
            else:
                # Legacy default: only prove parse completeness.
                manifest = {
                    "parseErrors": int(
                        (payload.get("counts") or {}).get("parseErrors") or 0
                    ),
                    "nodes": [],
                }
            output = build_preprocess_output(
                payload,
                policy,
                catalog,
                args.network_proxy_evidence,
                manifest,
            )
    else:
        document = common.load_yaml_doc(common.read_input(args.file))
        output = {"ruleCatalog": build_rule_catalog(document, catalog)}

    print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, common.ValidationError) as error:
        print("PREPROCESS FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
