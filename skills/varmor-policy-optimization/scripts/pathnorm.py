#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministic path normalization for log aggregation only.
# Ported from policy-optimization-agent/internal/logaggregate/pathnorm.go.
#
# The placeholders produced here (:pid, :pod-uid, :sa-rev, :snapshot, ...)
# are internal aggregation notation. They are NOT AppArmor/BPF wildcards and
# must never be written back into policy rules.

import re

POD_UID = r"[0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12}"

PROC_TASK = re.compile(r"^/proc/[0-9]+/task/[0-9]+(/|$)")
PROC_MAP = re.compile(r"^/proc/[0-9]+/map_files/[0-9a-fA-F]+-[0-9a-fA-F]+(/|$)")
PROC_PID = re.compile(r"^/proc/[0-9]+(/|$)")
KUBELET_POD = re.compile(r"^(/var/lib/kubelet/pods/)" + POD_UID + "(/|$)")
CGROUP_POD = re.compile(r"pod" + POD_UID)
SA_REVISION = re.compile(
    r"^((?:/var)?/run/secrets/kubernetes\.io/serviceaccount/)"
    r"\.\.[0-9]{4}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}_[0-9]{2}\.[0-9]+(/|$)"
)


def _is_decimal(value):
    return bool(value) and value.isdigit()


def normalize_path(path):
    """Return (normalized, changed). Only rewrites segments with fixed meaning."""
    if not path or not path.startswith("/"):
        return path, False
    normalized = path

    if PROC_MAP.match(normalized):
        normalized = PROC_MAP.sub(r"/proc/:pid/map_files/:range\1", normalized)
    elif PROC_TASK.match(normalized):
        normalized = PROC_TASK.sub(r"/proc/:pid/task/:tid\1", normalized)
    elif PROC_PID.match(normalized):
        normalized = PROC_PID.sub(r"/proc/:pid\1", normalized)

    if KUBELET_POD.match(normalized):
        normalized = KUBELET_POD.sub(r"\1:pod-uid\2", normalized)

    if normalized.startswith("/sys/fs/cgroup/") and CGROUP_POD.search(normalized):
        normalized = CGROUP_POD.sub("pod:pod-uid", normalized)

    if SA_REVISION.match(normalized):
        normalized = SA_REVISION.sub(r"\1:sa-rev\2", normalized)

    segments = normalized.split("/")
    i = 1
    while i + 2 < len(segments):
        if segments[i] == "snapshots" and _is_decimal(segments[i + 1]) and segments[i + 2] == "fs":
            segments[i + 1] = ":snapshot"
        i += 1
    normalized = "/".join(segments)
    return normalized, normalized != path
