#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Bounded, read-only incremental collection for one observation task.

run reads existing agents; status only reads local state. SQLite commits complete
lines and their byte cursors together. At the deadline, bounded drain/confirmation reads
exports per-node logs and calls the existing filter/preprocessor. No model API,
policy mutation, workload mutation or notification scheduling is involved.
"""

import argparse
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid

import build_agent_inventory
import build_manifest
import collect_violations
import hash_policy
import preprocess_aggregate
import validate_policy
import vopt_common as common


class EvidenceError(common.ValidationError):
    """A source identity/continuity error, rather than a retryable transport error."""


class TransferPressure(Exception):
    def __init__(self, retry_after):
        self.retry_after = retry_after
        super().__init__("rolling audit byte limit reached")


def secure_tree(root):
    root = Path(root)
    os.chmod(root, 0o700)
    for path in root.rglob("*"):
        if not path.is_symlink():
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


def save(path, value, exclusive=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    os.fchmod(fd, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        if exclusive:
            os.link(temporary, path)
        else:
            os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def local_status(root):
    import fcntl
    root = Path(root)
    if not (root / "collector.json").exists():
        return {"phase": "not-started", "active": False, "readyForWindow": False,
                "processAlive": False, "leaseHeld": False}
    progress = load(root / "collector.json")
    try:
        os.kill(progress["processId"], 0)
        alive = True
    except (OSError, KeyError):
        alive = False
    progress["processAlive"] = alive
    age = time.time() - progress.get("lastHeartbeatAt", progress["startedAt"])
    progress["heartbeatAgeSeconds"] = age
    try:
        fd = os.open(root / ".collector.lock", os.O_RDONLY)
    except FileNotFoundError:
        progress.update(leaseHeld=False, active=False, readyForWindow=False)
        return progress
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            held = False
        except BlockingIOError:
            held = True
    finally:
        os.close(fd)
    progress["leaseHeld"] = held
    progress["active"] = (progress["phase"] in ("running", "ready") and alive and held and
        0 <= age <= max(60, progress["plan"]["interval"] + 2 * progress["plan"]["requestTimeout"]) and
        time.time() < progress["window"]["end"])
    progress["readyForWindow"] = progress["active"] and progress["phase"] == "ready"
    return progress


@contextlib.contextmanager
def locked(root, filename=".collector.lock"):
    import fcntl
    fd = os.open(Path(root) / filename, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise common.ValidationError("a collector already owns this directory") from error
        yield
    finally:
        os.close(fd)


def database(root):
    path = Path(root) / "collector.sqlite"
    con = sqlite3.connect(path)
    os.chmod(path, 0o600)
    con.executescript("""
        CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS cursors (
            node TEXT, identity TEXT, value TEXT NOT NULL, PRIMARY KEY(node, identity));
        CREATE TABLE IF NOT EXISTS records (
            node TEXT, identity TEXT, generation TEXT, position INTEGER, line BLOB,
            PRIMARY KEY(node, identity, generation, position));
        CREATE TABLE IF NOT EXISTS issues (key TEXT PRIMARY KEY, value TEXT NOT NULL);
    """)
    return con


def state_get(con, key, default=None):
    row = con.execute("SELECT value FROM state WHERE key=?", (key,)).fetchone()
    return json.loads(row[0]) if row else default


def state_set(con, key, value):
    con.execute("INSERT OR REPLACE INTO state VALUES (?,?)", (key, json.dumps(value)))


def issue(con, node, reason, **details):
    value = {"node": node, "reason": reason, **details}
    key = common.sha256_text(json.dumps(value, sort_keys=True))
    con.execute("INSERT OR IGNORE INTO issues VALUES (?,?)", (key, json.dumps(value)))
    return key


def issues(con):
    return [json.loads(row[0]) for row in con.execute("SELECT value FROM issues ORDER BY key")]


def blocking_issues(con):
    return [item for item in issues(con) if item.get("severity") != "suspected" or
            not collect_violations.valid_event_timestamp(item.get("resolvedAt"))]


def suspect_read(con, node, reason, at):
    checkpoints = []
    for identity, raw in con.execute("SELECT identity,value FROM cursors WHERE node=?", (node,)):
        cur = json.loads(raw)
        if cur["path"].endswith("/violations.log") and not cur.get("missing"):
            checkpoints.append({"identity": identity, "generation": cur["generation"], "offset": cur["offset"]})
    issue(con, node, reason, severity="suspected", at=at, checkpoints=checkpoints)


def recover_reads(con, node, receipt):
    if receipt.get("backlogBytes") != 0 or not receipt.get("continuityVerifiedAt"):
        return
    cursors = {identity: json.loads(raw) for identity, raw in con.execute(
        "SELECT identity,value FROM cursors WHERE node=?", (node,))}
    for key, raw in con.execute("SELECT key,value FROM issues").fetchall():
        value = json.loads(raw)
        if (value.get("node") == node and value.get("severity") == "suspected" and
                value.get("resolvedAt") is None and
                receipt["continuityVerifiedAt"] >= value.get("at", math.inf)):
            checkpoints = value.get("checkpoints")
            if not isinstance(checkpoints, list) or not checkpoints or not all(
                    checkpoint.get("identity") in cursors and
                    not cursors[checkpoint["identity"]].get("missing") and
                    cursors[checkpoint["identity"]]["generation"] == checkpoint.get("generation") and
                    cursors[checkpoint["identity"]]["offset"] >= checkpoint.get("offset", math.inf)
                    for checkpoint in checkpoints):
                continue  # Later-created cursors cannot replace the original evidence.
            value.update(resolvedAt=receipt["continuityVerifiedAt"],
                         recoveryBasis="retained-file-checkpoints-and-drained-cursors")
            con.execute("UPDATE issues SET value=? WHERE key=?", (json.dumps(value), key))


def cursor_set(con, node, identity, value):
    con.execute("INSERT OR REPLACE INTO cursors VALUES (?,?,?)",
                (node, identity, json.dumps(value)))


class TransferBudget:
    """Persist conservative reservations across crashes; count audit stdout."""
    def __init__(self, root, limit, clock=time.time):
        self.path, self.limit, self.clock = Path(root) / "transfer-ledger.json", limit, clock

    def reserve(self, requested):
        now = self.clock()
        saved = load(self.path) if self.path.exists() else {"entries": [], "totalBytes": 0}
        saved["entries"] = [entry for entry in saved["entries"] if entry["at"] > now - 60]
        available = self.limit - sum(entry["bytes"] for entry in saved["entries"])
        minimum = min(requested, 1048577 + 65536 + 128)
        if available < minimum:
            retry = max(0.1, min((entry["at"] + 60 - now for entry in saved["entries"]), default=60))
            save(self.path, saved)
            raise TransferPressure(retry)
        cap = min(requested, available)
        key = uuid.uuid4().hex
        saved["entries"].append({"id": key, "at": now, "bytes": cap})
        saved["totalBytes"] += cap
        save(self.path, saved)  # Commit before dispatch; a crash keeps the charge.
        return key, cap

    def finish(self, key, actual):
        saved = load(self.path)
        entry = next(entry for entry in saved["entries"] if entry["id"] == key)
        if not 0 <= actual <= entry["bytes"]:
            raise EvidenceError("audit response exceeded its byte reservation")
        saved["totalBytes"] -= entry["bytes"] - actual
        entry["bytes"] = actual
        save(self.path, saved)

    def summary(self):
        saved = load(self.path) if self.path.exists() else {"entries": [], "totalBytes": 0}
        return {"windowBytes": sum(entry["bytes"] for entry in saved["entries"]
                                    if entry["at"] > self.clock() - 60),
                "totalBytes": saved["totalBytes"], "limitBytesPerMinute": self.limit,
                "scope": "audit-exec-stdout-including-framing-and-fingerprints"}


def scan(con, node, reader, budget, checked_at, max_line=1024 * 1024, initialize=False):
    """One node scan. Caller commits records, cursors and scan receipts together."""
    read_started = checked_at() if callable(checked_at) else checked_at
    cursors = {row[0]: json.loads(row[1]) for row in con.execute(
        "SELECT identity,value FROM cursors WHERE node=?", (node,))}
    if hasattr(reader, "known"):
        reader.known = cursors
    files = reader.manifest()
    # Compression changes inode. Preserve the old cursor only after checking
    # the old byte boundary against the decoded archive with the same name.
    for identity, entry in list(files.items()):
        if not entry["path"].endswith(".gz") or identity in cursors:
            continue
        aliases = [(key, cur) for key, cur in cursors.items()
                   if key not in files and cur["path"] in (entry["path"], entry["path"][:-3])]
        if len(aliases) == 1:
            key, cur = aliases[0]
            if hasattr(reader, "prime"):
                reader.prime(entry, cur, budget, initialize)
            offset = cur["offset"]
            anchor = reader.read(entry, max(0, offset - 64), min(offset, 64))
            prefix = reader.read(entry, 0, min(offset, 64))
            if (entry["size"] >= offset and hashlib.sha256(anchor).hexdigest() == cur["anchor"]
                    and hashlib.sha256(prefix).hexdigest() == cur["prefix"]):
                files[key] = files.pop(identity)
    for identity, cur in cursors.items():
        if identity not in files and not cur.get("missing"):
            if cur["offset"] < cur["size"]:
                issue(con, node, "unread-file-disappeared", identity=identity,
                      unreadBytes=cur["size"] - cur["offset"])
            elif cur["path"].endswith("/violations.log"):
                issue(con, node, "active-file-disappeared", identity=identity)
            cur["missing"] = True
            cursor_set(con, node, identity, cur)
    backlog = 0
    for identity, entry in sorted(files.items(), key=lambda item: (
            item[1]["path"].endswith("/violations.log"), item[1]["path"])):
        cur = cursors.get(identity, {"offset": 0, "generation": uuid.uuid4().hex})
        if hasattr(reader, "prime"):
            reader.prime(entry, cur, budget, initialize)
        if (identity in cursors and not cur.get("missing") and cur["offset"] == entry["size"]
                and cur.get("signature") and cur["signature"] == entry.get("signature")
                and not entry["path"].endswith("/violations.log")):
            cur["path"] = entry["path"]
            cursor_set(con, node, identity, cur)
            continue  # Logger-owned, drained immutable backup; metadata only.
        if initialize and identity not in cursors:
            # Before the window, establish a cheap EOF baseline rather than
            # downloading all older retained history. Keep an incomplete tail
            # at its original start so it can be reread as a complete line.
            tail_size = min(entry["size"], 64)
            tail = reader.read(entry, entry["size"] - tail_size, tail_size)
            if len(tail) != tail_size:
                raise common.ValidationError("source changed during cursor initialization")
            if not tail or tail.endswith(b"\n"):
                cur["offset"] = entry["size"]
            else:
                tail_size = min(entry["size"], max_line + 1)
                tail = reader.read(entry, entry["size"] - tail_size, tail_size)
                if len(tail) != tail_size:
                    raise common.ValidationError("source changed during tail initialization")
                end = tail.rfind(b"\n") + 1
                if not end and tail_size > max_line:
                    raise common.ValidationError("unfinished log record exceeds the line limit")
                cur["offset"] = entry["size"] - tail_size + end
        offset = cur["offset"]
        if type(offset) is not int or not 0 <= offset < 2 ** 63:
            raise common.ValidationError("invalid persisted byte cursor")
        reset = entry["size"] < offset or cur.get("missing", False)
        if offset and not reset and identity in cursors:
            anchor = reader.read(entry, max(0, offset - 64), min(offset, 64))
            prefix = reader.read(entry, 0, min(offset, 64))
            reset = (hashlib.sha256(anchor).hexdigest() != cur.get("anchor") or
                     hashlib.sha256(prefix).hexdigest() != cur.get("prefix"))
        if reset:
            issue(con, node, "file-reset", identity=identity)
            cur = {"offset": 0, "generation": uuid.uuid4().hex}
        while cur["offset"] < entry["size"] and budget > 0:
            length = min(entry["size"] - cur["offset"], budget, max_line + 1)
            if "availableEnd" in entry:
                length = min(length, entry["availableEnd"] - cur["offset"])
                if length <= 0:
                    break
            raw = reader.read(entry, cur["offset"], length)
            budget -= len(raw)
            if len(raw) != length:
                raise common.ValidationError("short log read; source changed during transfer")
            end = raw.rfind(b"\n") + 1
            if not end:
                if len(raw) > max_line:
                    raise common.ValidationError("log record exceeds the 1 MiB line limit")
                break  # Persist no partial tail; reread it on the next scan.
            position = cur["offset"]
            for payload in raw[:end].split(b"\n")[:-1]:
                line = payload + b"\n"
                if len(line) > max_line:
                    raise common.ValidationError("log record exceeds the 1 MiB line limit")
                con.execute("INSERT OR IGNORE INTO records VALUES (?,?,?,?,?)",
                            (node, identity, cur["generation"], position, line))
                position += len(line)
            cur["offset"] += end
        cur.update(path=entry["path"], size=entry["size"], missing=False,
                   signature=entry.get("signature"), remoteIdentity=entry["identity"])
        if cur["offset"] != offset or identity not in cursors or reset:
            anchor = reader.read(entry, max(0, cur["offset"] - 64), min(cur["offset"], 64))
            cur["anchor"] = hashlib.sha256(anchor).hexdigest()
        if identity not in cursors or reset or min(cur["offset"], 64) != min(offset, 64):
            prefix = reader.read(entry, 0, min(cur["offset"], 64))
            cur["prefix"] = hashlib.sha256(prefix).hexdigest()
        cursor_set(con, node, identity, cur)
        backlog += entry["size"] - cur["offset"]
    if hasattr(reader, "verify_identity"):
        reader.verify_identity()
    checked_at = checked_at() if callable(checked_at) else checked_at
    receipt = state_get(con, "node:" + node, {})
    receipt.update(lastScanAt=checked_at, lastReadStartedAt=read_started, backlogBytes=backlog)
    receipt.pop("continuityVerifiedAt", None)
    if backlog == 0:
        receipt.setdefault("coveredFrom", checked_at)
        receipt["lastDrainedAt"] = checked_at
        active_before = [key for key, cur in cursors.items()
                         if cur["path"].endswith("/violations.log") and not cur.get("missing")]
        if (active_before and all(key in files for key in active_before) and
                not any(item.get("node") == node and item.get("severity") != "suspected"
                        for item in blocking_issues(con))):
            receipt["continuityVerifiedAt"] = checked_at
    state_set(con, "node:" + node, receipt)
    return budget, receipt


def confirm_final(con, node, end, interval):
    receipt = state_get(con, "node:" + node, {})
    if receipt.get("backlogBytes") != 0 or receipt.get("lastReadStartedAt", -1) < end:
        for key in ("firstCleanCompletedAt", "cleanReads", "confirmationReadStartedAt"):
            receipt.pop(key, None)
    elif "firstCleanCompletedAt" not in receipt:
        receipt.update(firstCleanCompletedAt=receipt["lastDrainedAt"], cleanReads=1)
    elif receipt["lastReadStartedAt"] >= receipt["firstCleanCompletedAt"] + interval:
        receipt.update(cleanReads=2, confirmationReadStartedAt=receipt["lastReadStartedAt"])
    state_set(con, "node:" + node, receipt)
    return receipt


LIST_SCRIPT = r'''
set -eu
dir="$1"
test -d "$dir" && test -r "$dir" && test -x "$dir"
for f in "$dir"/violations.log "$dir"/violations-*.log "$dir"/violations-*.log.gz "$dir"/violations.log.*; do
  test ! -L "$f"
  test -f "$f" || continue
  test -r "$f"
  printf '%s\t%s\t%s\t%s\n' "$f" "$(stat -Lc '%d:%i' "$f")" "$(stat -Lc '%s' "$f")" "$(stat -Lc '%s:%y:%z' "$f")"
done
printf '__VOPT_MANIFEST_END__\n'
'''

FILE_BATCH_SCRIPT = r'''
set -eu
f="$1"; expected="$2"; signature="$3"; known="$4"; offset="$5"; budget="$6"; warm="$7"
test ! -L "$f"
test "$(stat -Lc '%d:%i' "$f")" = "$expected"
wire=$(stat -Lc '%s' "$f")
current_signature=$(stat -Lc '%s:%y:%z' "$f")
case "$f" in *.gz)
  test "$current_signature" = "$signature"
  if [ "$known" -ge 0 ]; then size="$known"; else gzip -t "$f"; size=$(gzip -cd "$f" | wc -c); fi;;
*) size="$wire";; esac
slice() {
  case "$f" in *.gz) gzip -cd "$f" | tail -c "+$(($1 + 1))" | head -c "$2";;
    *) tail -c "+$(($1 + 1))" "$f" | head -c "$2";; esac
}
available=$((cap - 65536))
test "$available" -ge 0
test "$budget" -le "$available" || budget="$available"
prefix=64; test "$size" -ge 64 || prefix="$size"
if [ "$offset" -gt "$size" ]; then offset=0; fi
if [ "$warm" = 1 ]; then
  if [ "$size" -eq 0 ] || [ -z "$(slice $((size - 1)) 1)" ]; then offset="$size";
  else offset=$((size - 1048577)); test "$offset" -ge 0 || offset=0; fi
fi
start=$((offset - 64)); test "$start" -ge 0 || start=0
length=$((size - start)); maximum=$((budget + offset - start))
test "$length" -le "$maximum" || length="$maximum"
printf '%s\t%s\t%s\t%s\n' "$size" "$prefix" "$start" "$length"
if [ "$prefix" -gt 0 ]; then slice 0 "$prefix"; fi
if [ "$length" -gt 0 ]; then slice "$start" "$length"; fi
test ! -L "$f"
test "$(stat -Lc '%d:%i' "$f")" = "$expected"
test "$(stat -Lc '%s' "$f")" -ge "$wire"
case "$f" in *.gz) test "$(stat -Lc '%s:%y:%z' "$f")" = "$signature";; esac
printf '__VOPT_BATCH_END__\n'
'''


class Kubernetes:
    def __init__(self, context, timeout):
        self.context, self.timeout, self.deadline = context, timeout, None
        self.transfer_budget = None

    def audit_call(self, prefix, script, argv, max_bytes):
        reservation, cap = self.transfer_budget.reserve(max_bytes)
        # The script is fixed code from this module, never log-derived text.
        # Pass all file paths/checkpoints as positional arguments; cap stdout
        # remotely so a malformed source cannot exceed the reservation.
        wrapper = 'script="$1"; cap="$2"; shift 2; sh -c "cap=\\$1; shift; $script" vopt-cap "$cap" "$@" | head -c "$cap"'
        raw = self.call(*prefix, wrapper, "vopt-budget", script, str(cap), *argv)
        self.transfer_budget.finish(reservation, len(raw))
        return raw

    def call(self, *args):
        timeout = self.timeout
        if self.deadline is not None:
            timeout = min(timeout, self.deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError("collection read deadline reached")
        try:
            result = subprocess.run(["kubectl", "--context", self.context,
                                     "--request-timeout=%ss" % max(1, int(timeout)), *args],
                                    capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise TimeoutError("kubectl %s timed out" % args[0]) from error
        if result.returncode:
            # Remote output can contain business metadata. Keep raw stderr out
            # of status/report and model context.
            raise common.ValidationError("kubectl %s failed (exit %d)" % (args[0], result.returncode))
        return result.stdout

    def inventory(self, namespace, daemonset):
        payload = json.loads(self.call("get", "daemonset,pods", "-n", namespace, "-o", "json"))
        ds, pods = build_agent_inventory.split_cluster_snapshot(payload, daemonset, namespace)
        return build_agent_inventory.build(ds, pods)

    def policy(self, identity):
        args = ["get", "vpol" if identity["kind"] == "VarmorPolicy" else "vcpol", identity["name"]]
        if identity["kind"] == "VarmorPolicy":
            args += ["-n", identity["namespace"]]
        return common.load_yaml_doc(self.call(*args, "-o", "json").decode())


class AgentReader:
    def __init__(self, kube, namespace, agent, container, directory):
        self.kube, self.directory = kube, directory
        self.namespace, self.agent = namespace, agent
        self.known = {}
        self.cache = {}
        self.prefix = ["exec", "-n", namespace, agent["pod"], "-c", container,
                       "--", "sh", "-c"]

    def manifest(self):
        self.cache.clear()
        # LIST establishes the round's inventory. This GET narrows the
        # LIST-to-exec race; the post-read GET protects the transaction too.
        self.verify_identity()
        raw = self.audit(LIST_SCRIPT, [self.directory], 65536)
        out = {}
        for line in raw.decode("utf-8").splitlines():
            if line == "__VOPT_MANIFEST_END__":
                continue
            path, identity, size, signature = line.split("\t")
            name = Path(path).name
            if (str(Path(path).parent) != self.directory or
                    not re.fullmatch(r"violations(?:\.log(?:\.[A-Za-z0-9_.-]+)?|-[A-Za-z0-9_.-]+\.log(?:\.gz)?)", name) or
                    not re.fullmatch(r"\d+:\d+", identity) or not size.strip().isdigit()):
                raise common.ValidationError("invalid remote log manifest")
            prior_key, prior = next(((key, cur) for key, cur in self.known.items()
                          if cur.get("remoteIdentity") == identity and cur.get("signature") == signature), (identity, {}))
            logical_size = prior.get("size", -1) if path.endswith(".gz") else int(size.strip())
            entry = {"path": path, "identity": identity, "size": logical_size,
                     "wireSize": int(size.strip()), "signature": signature}
            if prior_key not in out or name == "violations.log":
                out[prior_key] = entry
        if not raw.endswith(b"__VOPT_MANIFEST_END__\n"):
            raise EvidenceError("incomplete log manifest")
        return out

    def audit(self, script, argv, cap):
        if getattr(self.kube, "transfer_budget", None) is not None:
            return self.kube.audit_call(self.prefix, script, argv, cap)
        return self.kube.call(*self.prefix, 'cap="$1"; shift; ' + script, "vopt-read", str(cap), *argv)

    def prime(self, entry, cur, budget, initialize=False):
        if entry["identity"] in self.cache:
            return
        if (cur.get("signature") == entry["signature"] and cur.get("offset") == entry["size"]
                and cur.get("signature") and not cur.get("missing")
                and not entry["path"].endswith("/violations.log")):
            return
        requested = max(budget, 1048577) if initialize else budget
        raw = self.audit(FILE_BATCH_SCRIPT,
            [entry["path"], entry["identity"], entry["signature"], str(entry["size"]),
             str(cur.get("offset", 0)), str(requested), "1" if initialize else "0"],
            requested + 65536 + 256)
        header, body = raw.split(b"\n", 1)
        size, prefix_len, start, length = map(int, header.split(b"\t"))
        if (min(size, prefix_len, start, length) < 0 or prefix_len > 64 or
                start + length > size or body[prefix_len + length:] != b"__VOPT_BATCH_END__\n"):
            raise EvidenceError("incomplete audit file batch")
        entry["size"] = size
        entry["availableEnd"] = start + length
        self.cache[entry["identity"]] = (body[:prefix_len], start, body[prefix_len:prefix_len + length])

    def verify_identity(self):
        pod = json.loads(self.kube.call("get", "pod", self.agent["pod"],
                                       "-n", self.namespace, "-o", "json"))
        if pod.get("metadata", {}).get("uid") != self.agent["uid"]:
            raise EvidenceError("agent Pod identity changed")

    def read(self, entry, offset, length):
        if length == 0:
            return b""
        if entry["identity"] not in self.cache:
            self.prime(entry, {"offset": 0}, offset + length)
        prefix, start, raw = self.cache[entry["identity"]]
        if offset + length <= len(prefix):
            return prefix[offset:offset + length]
        if start <= offset and offset + length <= start + len(raw):
            return raw[offset - start:offset - start + length]
        raise EvidenceError("file batch does not contain requested checkpoint bytes")


def checked_task(path):
    task = load(path)
    if task.get("taskType") != "varmor-policy-optimization" or task.get("taskVersion") != 1:
        raise common.ValidationError("unsupported observation task")
    if task.get("status") not in ("observing", "collecting"):
        raise common.ValidationError("task has already advanced past observation")
    window = task.get("window", {})
    start, end = (collect_violations.parse_timestamp(window.get(key)) for key in ("start", "end"))
    if start < 0 or start > end:
        raise common.ValidationError("invalid task window")
    for key in ("policySnapshotFile", "agentInventoryStartFile"):
        if not Path(task[key]).is_absolute():
            raise common.ValidationError("task evidence paths must be absolute")
    identity = task["policy"]
    collect_violations.validate_identity_scope(identity["kind"], identity.get("namespace"), identity["name"])
    if not isinstance(task.get("clusterContext"), str) or not task["clusterContext"].strip():
        raise common.ValidationError("task clusterContext is required")
    return task, start, end


def claim_task(path, owner=None, release=False):
    """Atomically claim stage-two work; a concurrent invocation must stop."""
    path = Path(path)
    if owner is None and not release:
        owner = uuid.uuid4().hex
    if not path.is_absolute() or not isinstance(owner, str) or not owner.strip():
        raise common.ValidationError("claim requires an absolute task path and stable invocation owner")
    with locked(path.parent, path.name + ".analysis.lock"):
        task = load(path)
        if task.get("taskType") != "varmor-policy-optimization":
            raise common.ValidationError("unsupported observation task")
        prior = task.get("analysisClaim", {})
        if release:
            if prior.get("owner") != owner or task["status"] not in ("analyzing", "collecting"):
                raise common.ValidationError("only the current analysis owner can release unfinished work")
            task["status"] = prior["previousStatus"]
            task.pop("analysisClaim")
            save(path, task)
            return {"released": True}
        if prior and task["status"] in ("analyzing", "collecting"):
            return {"claimed": prior.get("owner") == owner, "resumed": prior.get("owner") == owner,
                    "reason": "same-owner" if prior.get("owner") == owner else "already-claimed",
                    "owner": owner, "existingOwner": prior.get("owner"), "claimedAt": prior.get("claimedAt")}
        collector = task.get("outputs", {}).get("collectorDirectory")
        allowed = (task["status"] in ("collected", "collection-failed") if collector else
                   task["status"] == "observing" and
                   collect_violations.parse_timestamp(task["window"]["end"]) <= time.time())
        if not allowed:
            return {"claimed": False, "reason": "task-not-ready-for-analysis"}
        if collector:
            progress = local_status(collector)
            if progress["phase"] not in ("finished", "failed"):
                return {"claimed": False, "reason": "collector-not-finished"}
        previous = task["status"]
        task.update(status="analyzing" if collector else "collecting", updatedAt=int(time.time()),
                    analysisClaim={"owner": owner, "previousStatus": previous, "claimedAt": time.time()},
                    lastTrigger={"mode": "analysis", "at": int(time.time())})
        save(path, task)
        return {"claimed": True, "resumed": False, "owner": owner}


def force_release_task(path, expected_owner, reason, authorized=False):
    """Recover abandoned analysis after explicit authorization, with an audit trail."""
    path = Path(path)
    if (not path.is_absolute() or not isinstance(expected_owner, str) or not expected_owner.strip()
            or not isinstance(reason, str) or not reason.strip() or not authorized):
        raise common.ValidationError("force-release requires an absolute task path, expected owner, reason and authorization")
    with locked(path.parent, path.name + ".analysis.lock"):
        task = load(path)
        prior = task.get("analysisClaim", {})
        if (task.get("taskType") != "varmor-policy-optimization" or not isinstance(prior, dict)
                or prior.get("owner") != expected_owner or task.get("status") not in ("analyzing", "collecting")):
            raise common.ValidationError("analysis claim changed or task no longer has unfinished analysis")
        collector = task.get("outputs", {}).get("collectorDirectory")
        allowed_previous = ("collected", "collection-failed") if collector else ("observing",)
        if prior.get("previousStatus") not in allowed_previous:
            raise common.ValidationError("analysis claim has no valid previous status")
        history = task.setdefault("analysisClaimHistory", [])
        if not isinstance(history, list):
            raise common.ValidationError("invalid analysis claim audit history")
        now = time.time()
        history.append({"event": "force-released", "owner": expected_owner,
                        "claimedAt": prior.get("claimedAt"), "releasedAt": now,
                        "previousStatus": task["status"], "restoredStatus": prior["previousStatus"],
                        "reason": reason.strip()})
        task.update(status=prior["previousStatus"], updatedAt=int(now),
                    lastTrigger={"mode": "analysis-reset", "at": int(now)})
        task.pop("analysisClaim")
        save(path, task)
        return {"released": True, "previousOwner": expected_owner, "status": task["status"]}


def export_pre(con, root, start_inventory, end_inventory, policy, start, end, network_status):
    logs = []
    logdir = root / "2.1.3-logs"
    logdir.mkdir(mode=0o700, exist_ok=True)
    os.chmod(logdir, 0o700)
    states = build_manifest._inventory_state(start_inventory), build_manifest._inventory_state(end_inventory)
    for node in sorted(set(states[0]["nodes"]) | set(states[1]["nodes"])):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", node):
            raise common.ValidationError("invalid node filename")
        path = logdir / (node + ".log")
        fd, tmp = tempfile.mkstemp(dir=logdir)
        os.fchmod(fd, 0o600)
        try:
            with os.fdopen(fd, "wb") as handle:
                for row in con.execute("SELECT line FROM records WHERE node=? ORDER BY rowid", (node,)):
                    handle.write(row[0])
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        logs.append((node, str(path), 0))
    manifest, merged = build_manifest.build(start_inventory, end_inventory, logs, start, end)
    problems = issues(con)
    unresolved = blocking_issues(con)
    global_gap = any(not item.get("node") for item in unresolved)
    for entry in manifest["nodes"]:
        receipt = state_get(con, "node:" + entry["node"], {})
        node_gap = global_gap or any(item.get("node") == entry["node"] for item in unresolved)
        covered = (receipt.get("coveredFrom", math.inf) < start and
                   receipt.get("lastReadStartedAt", -1) >= end and
                   receipt.get("lastDrainedAt", -1) >= end and
                   receipt.get("backlogBytes") == 0 and not node_gap and
                   receipt.get("cleanReads", 0) >= 2 and
                   receipt.get("confirmationReadStartedAt", -1) >=
                   receipt.get("firstCleanCompletedAt", math.inf) + state_get(con, "settleInterval", 30) and
                   entry["parseErrors"] == 0 and entry["nodeIdentityMismatches"] == 0)
        entry.update(collectionStartedAt=receipt.get("coveredFrom"),
                     collectedAt=receipt.get("lastDrainedAt"), incremental=receipt)
        entry["retention"] = {"status": "covered" if covered else "unknown",
                              "basis": "incremental-file-cursors" if covered else "incremental-coverage-incomplete"}
    manifest.update(collectionMode="incremental", collectionStartedAt=state_get(con, "startedAt"),
                    collectedAt=min((entry.get("collectedAt") or 0 for entry in manifest["nodes"]), default=0),
                    collectionIssues=problems, logsCollectedAfterWindow=False,
                    finalReadComplete=all((entry.get("collectedAt") or 0) >= end and
                                          entry["incremental"].get("lastReadStartedAt", -1) >= end and
                                          entry["incremental"].get("backlogBytes") == 0
                                          and entry["incremental"].get("cleanReads", 0) >= 2
                                          and entry["incremental"].get("confirmationReadStartedAt", -1) >=
                                          entry["incremental"].get("firstCleanCompletedAt", math.inf) +
                                          state_get(con, "settleInterval", 30)
                                          for entry in manifest["nodes"]))
    manifest["settleIntervalSeconds"] = state_get(con, "settleInterval", 30)
    manifest["windowComplete"] = (manifest["finalReadComplete"] and
                                  end_inventory["capturedAt"] >= end)
    manifest["retentionCovered"] = (manifest["nodeSetComplete"] and
                                    all(entry["retention"]["status"] == "covered" for entry in manifest["nodes"]))
    manifest["retentionStatus"] = "true" if manifest["retentionCovered"] else "unknown"
    manifest["retentionEvidence"] = {"windowStart": start, "basis": "incremental-file-cursors"}
    payload = collect_violations.collect(merged, start, end, kind=policy["kind"],
                                        namespace=policy["metadata"].get("namespace"),
                                        name=policy["metadata"]["name"],
                                        profile_name=policy["status"]["profileName"])
    pre = preprocess_aggregate.build_preprocess_output(payload, policy, common.load_catalog(), network_status, manifest)
    save(root / "2.1.4-pre.json", pre)
    return pre


def run(args, kube=None, reader_factory=AgentReader, clock=time.time, sleep=time.sleep, monotonic=time.monotonic):
    task, start, end = checked_task(args.task)
    root = Path(args.output).resolve()
    if root.exists() and not (root / "collector.sqlite").exists():
        unrelated = [path.name for path in root.iterdir()
                     if path.name not in ("collector-startup.log", ".collector.lock")]
        if unrelated:
            raise common.ValidationError("new collector requires an empty dedicated output directory")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(root, 0o700)
    kube = kube or Kubernetes(task["clusterContext"], args.request_timeout)
    start_inventory = build_manifest.load_agent_inventory(task["agentInventoryStartFile"])
    baseline = build_manifest._inventory_state(start_inventory)
    if not baseline["complete"] or start_inventory["capturedAt"] > start:
        raise common.ValidationError("incomplete or late start agent inventory")
    snapshot = load(task["policySnapshotFile"])
    if any((snapshot.get("policy", {}).get(key) or "") != (task["policy"].get(key) or "")
           for key in ("kind", "namespace", "name")):
        raise common.ValidationError("snapshot does not belong to the task policy")
    config = {"task": str(Path(args.task).resolve()), "context": task["clusterContext"],
              "policy": task["policy"], "start": start, "end": end,
              "snapshot": snapshot, "inventory": start_inventory,
              "agentNamespace": args.agent_namespace, "daemonset": args.daemonset,
              "container": args.container, "logDirectory": args.log_directory,
              "interval": args.interval, "maxReadMB": args.max_read_mb,
              "maxLocalMB": args.max_local_mb, "networkProxyEvidence": args.network_proxy_evidence,
              "finalReadSeconds": args.final_read_seconds, "requestTimeout": args.request_timeout,
              "maxTransferMBPerMinute": getattr(args, "max_transfer_mb_per_minute", 16),
              "allowEmptySelector": getattr(args, "allow_empty_selector", False)}
    task_path = Path(args.task)
    with locked(root), locked(task_path.parent, task_path.name + ".collector.lock"), contextlib.closing(database(root)) as con:
        existing = state_get(con, "config")
        if existing is not None and existing != config:
            raise common.ValidationError("resume must retain the original task window, scope and limits")
        if state_get(con, "phase") in ("finished", "failed"):
            raise common.ValidationError("completed collection cannot be restarted")
        if existing is not None and clock() >= end:
            raise common.ValidationError("expired collection cannot resume cluster reads")
        if existing is None and clock() >= start:
            raise common.ValidationError("initialization is late; agree a new window or use the snapshot fallback")
        if args.final_read_seconds <= args.interval:
            raise common.ValidationError("final read budget must exceed one scan interval for confirmation")
        if (baseline["daemonSet"]["namespace"] != args.agent_namespace or
                baseline["daemonSet"]["name"] != args.daemonset):
            raise common.ValidationError("agent scope does not match start inventory")
        started = state_get(con, "startedAt", clock())
        with con:
            if existing is not None:
                for node in baseline["nodes"]:
                    suspect_read(con, node, "collector-interrupted", clock())
            state_set(con, "config", config)
            state_set(con, "startedAt", started)
            state_set(con, "phase", "running")
            state_set(con, "settleInterval", args.interval)
        transfer = TransferBudget(root, int(config["maxTransferMBPerMinute"] * 1024 * 1024), clock)
        if hasattr(kube, "transfer_budget"):
            kube.transfer_budget = transfer
        monotonic_stop = monotonic() + max(0, end - clock()) + args.final_read_seconds
        progress = {"collectorVersion": 1, "phase": "running", "processId": os.getpid(),
                    "taskFile": config["task"], "startedAt": started,
                    "window": {"start": start, "end": end}, "plan": config,
                    "preFile": str(root / "2.1.4-pre.json")}
        save(root / "collector.json", progress)
        # Register the persistent collector without advancing the task to the
        # post-observation collecting state. Finalization does not invent user decisions.
        task.setdefault("outputs", {}).update(latestRunDirectory=str(root),
            collectorDirectory=str(root), preFile=str(root / "2.1.4-pre.json"))
        task["updatedAt"] = int(clock())
        save(args.task, task)
        policy_ready = False
        try:
            initial_policy = kube.policy(task["policy"])
            policy_status = initial_policy.get("status")
            profile_name = policy_status.get("profileName") if isinstance(policy_status, dict) else None
            if not isinstance(profile_name, str) or not profile_name.strip():
                raise EvidenceError("policy status.profileName is not ready for evidence filtering")
            normalized = validate_policy.normalize(common.dump_yaml(initial_policy),
                require_atomic_capabilities=True, require_observation=True,
                allow_empty_selector=getattr(args, "allow_empty_selector", False))
            if not normalized["valid"]:
                raise common.ValidationError("policy is not a valid atomic observation policy")
            if not hash_policy.verify_snapshot(common.dump_yaml(initial_policy), snapshot, start)["valid"]:
                raise common.ValidationError("policy snapshot drift")
            preprocess_aggregate.validate_network_proxy_evidence(
                initial_policy, args.network_proxy_evidence, common.load_catalog())
            policy_ready = True
            round_number = 0
            final_started = False
            consecutive_failures = {}
            while True:
                close_path = root / "close-request.json"
                if close_path.exists() and state_get(con, "closeRequest") is None:
                    request = load(close_path)
                    requested_end = request["end"]
                    if (type(requested_end) is not int or not start <= requested_end <= min(end, clock())
                            or not isinstance(request.get("reason"), str) or not request["reason"].strip()):
                        raise common.ValidationError("invalid early-close request")
                    end = requested_end
                    config["end"] = end
                    with con:
                        state_set(con, "closeRequest", request)
                        state_set(con, "config", config)
                    task = load(args.task)
                    task["window"].update(end=end, endReason="user-closed-early")
                    task["updatedAt"] = int(clock())
                    save(args.task, task)
                    progress.update(window={"start": start, "end": end}, plan=config,
                                    closeAppliedAt=clock())
                    save(root / "collector.json", progress)
                    monotonic_stop = min(monotonic_stop, monotonic() + args.final_read_seconds)
                final = clock() >= end
                if final and not final_started:
                    final_started = True
                    monotonic_stop = min(monotonic_stop, monotonic() + args.final_read_seconds)
                if monotonic() >= monotonic_stop:
                    raise TimeoutError("final read budget exhausted")
                initialized = all(state_get(con, "node:" + node, {}).get("coveredFrom", math.inf) < start
                                  for node in baseline["nodes"])
                if not initialized and clock() >= start:
                    with con:
                        issue(con, "", "initialization-missed-start")
                    raise EvidenceError("all nodes must finish initialization before window.start")
                kube.deadline = min(monotonic_stop, monotonic() + args.request_timeout)
                inventory = kube.inventory(args.agent_namespace, args.daemonset)
                current = build_manifest._inventory_state(inventory)
                if (current["nodes"] != baseline["nodes"] or
                    any(current["daemonSet"][key] != baseline["daemonSet"][key]
                        for key in ("namespace", "name", "uid", "generation", "desiredNumberScheduled")) or
                    current["daemonSet"]["currentNumberScheduled"] != baseline["daemonSet"]["currentNumberScheduled"] or
                    current["daemonSet"]["observedGeneration"] != current["daemonSet"]["generation"] or
                    any(agent["terminating"] for agent in current["agents"]) or
                    {(agent["node"], agent["uid"]) for agent in current["agents"]} !=
                    {(agent["node"], agent["uid"]) for agent in baseline["agents"]}):
                    with con:
                        issue(con, "", "agent-inventory-changed-or-incomplete")
                    raise EvidenceError("agent topology changed; evidence retained")
                budget = int(args.max_read_mb * 1024 * 1024)
                agents = current["agents"]
                pivot = round_number % len(agents)
                for agent in agents[pivot:] + agents[:pivot]:
                    if budget <= 0:
                        break
                    kube.deadline = min(monotonic_stop, monotonic() + args.request_timeout)
                    try:
                        with con:
                            warm_start = state_get(con, "node:" + agent["node"]) is None
                            if warm_start and clock() >= start:
                                issue(con, "", "initialization-missed-start")
                                raise EvidenceError("initialization crossed window.start")
                            budget, receipt = scan(con, agent["node"], reader_factory(kube,
                                args.agent_namespace, agent, args.container, args.log_directory),
                                budget, clock, initialize=warm_start)
                            if receipt.get("coveredFrom", math.inf) >= start and clock() >= start:
                                raise EvidenceError("initialization did not complete before window.start")
                            if not agent["ready"]:
                                suspect_read(con, agent["node"], "agent-temporarily-not-ready", clock())
                            else:
                                recover_reads(con, agent["node"], receipt)
                            if final:
                                confirm_final(con, agent["node"], end, args.interval)
                            secure_tree(root)  # Includes an open SQLite rollback journal.
                        consecutive_failures[agent["node"]] = 0
                    except TransferPressure as pressure:
                        progress["resourcePressure"] = "rolling-audit-stdout-limit"
                        break  # No read happened; retained cursors still apply.
                    except EvidenceError:
                        raise
                    except (OSError, ValueError, common.ValidationError, TimeoutError):
                        with con:
                            suspect_read(con, agent["node"], "source-read-failed", clock())
                            receipt = state_get(con, "node:" + agent["node"], {})
                            for key in ("firstCleanCompletedAt", "cleanReads", "confirmationReadStartedAt"):
                                receipt.pop(key, None)
                            state_set(con, "node:" + agent["node"], receipt)
                        consecutive_failures[agent["node"]] = consecutive_failures.get(agent["node"], 0) + 1
                        if not initialized or consecutive_failures[agent["node"]] >= 3:
                            raise
                round_number += 1
                receipts = {node: state_get(con, "node:" + node, {}) for node in baseline["nodes"]}
                drained = all(receipt.get("backlogBytes") == 0 for receipt in receipts.values())
                progress.update(lastHeartbeatAt=clock(), rounds=round_number, nodes=receipts,
                                issues=issues(con), phase="ready" if drained and not blocking_issues(con) else "running",
                                transfer=transfer.summary())
                save(root / "collector.json", progress)
                secure_tree(root)
                used = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
                if used >= args.max_local_mb * 1024 * 1024:
                    with con:
                        issue(con, "", "local-storage-threshold")
                    raise common.ValidationError("local storage threshold reached; evidence retained")
                if final:
                    # Draining may need multiple capped rounds. Never count a
                    # pre-deadline read as the final read for a starved node.
                    if all(receipt.get("lastDrainedAt", 0) >= end and
                           receipt.get("lastReadStartedAt", -1) >= end and
                           receipt.get("backlogBytes") == 0 and receipt.get("cleanReads", 0) >= 2
                           for receipt in receipts.values()) and current["complete"] and not any(
                               item.get("severity") == "suspected" for item in blocking_issues(con)):
                        break
                    due = [receipt["firstCleanCompletedAt"] + args.interval - clock()
                           for receipt in receipts.values() if receipt.get("cleanReads") == 1 and
                           receipt["firstCleanCompletedAt"] + args.interval > clock()]
                    sleep(min(min(due) if due else 5, max(0, monotonic_stop - monotonic())))
                    continue
                sleep(min(args.interval if drained else min(args.interval, 5), max(0, end - clock())))
            kube.deadline = monotonic_stop
            policy = kube.policy(task["policy"])
            if not hash_policy.verify_snapshot(common.dump_yaml(policy), snapshot, start)["valid"]:
                with con:
                    issue(con, "", "policy-snapshot-drift")
                raise common.ValidationError("policy changed during observation")
            end_inventory = kube.inventory(args.agent_namespace, args.daemonset)
            save(root / "2.1.2-agent-inventory.json", end_inventory)
            path = root / "2.1.1-current.yaml"
            path.write_text(common.dump_yaml(policy) + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
            pre = export_pre(con, root, start_inventory, end_inventory, policy, start, end,
                             args.network_proxy_evidence)
            with con:
                state_set(con, "phase", "finished")
            progress.update(phase="finished", finishedAt=clock(), collectionComplete=pre["collectionComplete"],
                            issues=issues(con))
            save(root / "collector.json", progress)
            finished_task = load(args.task)
            finished_task.update(status="collected", updatedAt=int(clock()),
                                 lastTrigger={"mode": "collector", "at": int(clock())})
            save(args.task, finished_task)
            secure_tree(root)
            return 0 if pre["collectionComplete"] else 2
        except (OSError, ValueError, common.ValidationError, TimeoutError, sqlite3.Error, KeyboardInterrupt) as error:
            database_failed = isinstance(error, sqlite3.Error)
            try:
                with con:
                    issue(con, "", "collector-stopped-before-finalization", errorType=type(error).__name__)
                    state_set(con, "phase", "failed")
                failed_issues = issues(con)
            except sqlite3.Error:
                database_failed = True
                failed_issues = [{"node": "", "reason": "database-error"}]
            # Exception text can embed paths or remote data; store a safe category.
            progress.update(phase="failed", stoppedAt=clock(), errorType=type(error).__name__, issues=failed_issues)
            if isinstance(error, EvidenceError):
                progress["errorReason"] = str(error)
            save(root / "collector.json", progress)
            if database_failed and (root / "2.1.4-pre.json").exists():
                previous_pre = load(root / "2.1.4-pre.json")
                previous_pre.update(collectionComplete=False)
                previous_pre.setdefault("failures", []).append({"reason": "database-error"})
                save(root / "2.1.4-pre.json", previous_pre)
            # Retained partial evidence can still be analyzed. It remains
            # ineligible because a global issue is embedded in its manifest.
            if policy_ready and not database_failed:
                try:
                    partial_inventory = inventory if "inventory" in locals() else start_inventory
                    save(root / "2.1.2-agent-inventory.json", partial_inventory)
                    current_file = root / "2.1.1-current.yaml"
                    current_file.write_text(common.dump_yaml(initial_policy) + "\n", encoding="utf-8")
                    os.chmod(current_file, 0o600)
                    export_pre(con, root, start_inventory, partial_inventory, initial_policy,
                               start, end, args.network_proxy_evidence)
                    progress["collectionComplete"] = False
                except (OSError, ValueError, common.ValidationError, sqlite3.Error):
                    progress["partialPreAvailable"] = False
            progress["partialPreAvailable"] = (root / "2.1.4-pre.json").exists()
            save(root / "collector.json", progress)
            failed_task = load(args.task)
            failed_task.update(status="collection-failed", updatedAt=int(clock()),
                               lastTrigger={"mode": "collector", "at": int(clock())})
            save(args.task, failed_task)
            secure_tree(root)
            return 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    monitor = sub.add_parser("run")
    monitor.add_argument("--task", required=True)
    monitor.add_argument("--output", required=True)
    monitor.add_argument("--agent-namespace", required=True)
    monitor.add_argument("--daemonset", required=True)
    monitor.add_argument("--container", required=True)
    monitor.add_argument("--log-directory", default="/var/log/varmor")
    monitor.add_argument("--interval", type=float, default=30)
    monitor.add_argument("--max-read-mb", type=float, default=4)
    monitor.add_argument("--max-local-mb", type=float, default=512)
    monitor.add_argument("--max-transfer-mb-per-minute", type=float, default=16)
    monitor.add_argument("--request-timeout", type=float, default=30)
    monitor.add_argument("--final-read-seconds", type=float, default=60)
    monitor.add_argument("--network-proxy-evidence", required=True,
                         choices=preprocess_aggregate.NETWORK_PROXY_EVIDENCE_STATUSES)
    monitor.add_argument("--authorized-agent-read", action="store_true", required=True)
    monitor.add_argument("--allow-empty-selector", action="store_true")
    status = sub.add_parser("status")
    status.add_argument("--output", required=True)
    close = sub.add_parser("close", help="submit a user-requested early end; verify collector acknowledgement")
    close.add_argument("--output", required=True)
    close.add_argument("--end")
    close.add_argument("--reason", required=True)
    for name in ("claim", "release"):
        command = sub.add_parser(name, help="local atomic stage-two ownership; no cluster reads")
        command.add_argument("--task", required=True)
        command.add_argument("--owner", required=name == "release")
    reset = sub.add_parser("force-release", help="release abandoned analysis after user authorization")
    reset.add_argument("--task", required=True)
    reset.add_argument("--expected-owner", required=True)
    reset.add_argument("--reason", required=True)
    reset.add_argument("--authorized-analysis-reset", action="store_true", required=True)
    args = parser.parse_args()
    if args.command in ("claim", "release"):
        print(json.dumps(claim_task(args.task, args.owner, args.command == "release")))
        return
    if args.command == "force-release":
        print(json.dumps(force_release_task(args.task, args.expected_owner, args.reason,
                                            args.authorized_analysis_reset)))
        return
    if args.command == "close":
        root = Path(args.output)
        progress = local_status(root)
        end = collect_violations.parse_timestamp(args.end) if args.end else int(time.time())
        if (not progress["active"] or
                not progress["window"]["start"] <= end <= min(progress["window"]["end"], time.time())):
            raise common.ValidationError("collector/window is not eligible for early close")
        if (root / "close-request.json").exists():
            raise common.ValidationError("an early-close request already exists")
        if not args.reason.strip():
            raise common.ValidationError("early close requires the user's reason")
        save(root / "close-request.json", {"end": end, "reason": args.reason, "requestedAt": time.time()}, exclusive=True)
        print(json.dumps({"status": "close-requested", "end": end}))
        return
    if args.command == "status":
        progress = local_status(args.output)
        print(json.dumps(progress, ensure_ascii=False, indent=2))
        return
    for key in ("interval", "max_read_mb", "max_local_mb", "request_timeout", "final_read_seconds", "max_transfer_mb_per_minute"):
        if not math.isfinite(getattr(args, key)) or getattr(args, key) <= 0:
            raise common.ValidationError("%s must be finite and positive" % key)
    if args.max_read_mb < 2:
        raise common.ValidationError("max-read-mb must be at least 2 for a complete bounded log record")
    if args.max_transfer_mb_per_minute < 2:
        raise common.ValidationError("rolling audit stdout limit must be at least 2 MiB per minute")
    if not Path(args.task).is_absolute() or not Path(args.output).is_absolute():
        raise common.ValidationError("task and output paths must be absolute")
    args.log_directory = str(Path(args.log_directory))
    if not args.log_directory.startswith("/") or any(char in args.log_directory for char in "\n\t"):
        raise common.ValidationError("log directory must be an absolute container path")
    sys.exit(run(args))


if __name__ == "__main__":
    try:
        main()
    except sqlite3.Error as error:
        # Startup/database-open errors happen before run's failure handler.
        # Preserve a structured failed state as well as a structured stderr.
        try:
            output = Path(sys.argv[sys.argv.index("--output") + 1])
            save(output / "collector.json", {"phase": "failed", "processId": os.getpid(),
                "startedAt": time.time(), "errorType": type(error).__name__, "reason": "database-error"})
        except (OSError, ValueError, IndexError):
            pass
        print(json.dumps({"phase": "failed", "errorType": type(error).__name__, "reason": "database-error"}), file=sys.stderr)
        sys.exit(2)
    except (OSError, ValueError, common.ValidationError) as error:
        print("MONITOR FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
