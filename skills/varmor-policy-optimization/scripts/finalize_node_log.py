#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Validate copied log files and publish one node log without partial output.

Call only after every enumerated remote file was copied successfully. This
offline helper cannot prove remote transfer completeness.
"""

import argparse
import gzip
import os
from pathlib import Path
import sys
import tempfile
import time

import collect_violations
import vopt_common as common


def finalize(files, output, window_end, started_at):
    if not files:
        raise common.ValidationError("at least one copied log file is required")
    if not collect_violations.valid_event_timestamp(window_end):
        raise common.ValidationError("window end must be a non-negative epoch value")
    if (
        not collect_violations.valid_event_timestamp(started_at)
        or started_at < window_end
    ):
        raise common.ValidationError(
            "collection must start at or after the observation window end"
        )
    paths = [Path(path) for path in files]
    stats = [path.stat() for path in paths]
    identities = [(info.st_dev, info.st_ino) for info in stats]
    if len(set(identities)) != len(paths):
        raise common.ValidationError("copied log inputs must be distinct")
    copied_at = min(info.st_mtime for info in stats)
    if copied_at < started_at:
        raise common.ValidationError(
            "a copied log predates the declared collection start"
        )
    target = Path(output)
    if target.exists() or target.is_symlink():
        raise common.ValidationError("refusing to overwrite an existing node log")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(target.parent, 0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=".node-log-", dir=target.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as dest:
            for path in sorted(paths):
                opener = gzip.open if path.suffix == ".gz" else open
                with opener(path, "rt", encoding="utf-8") as source:
                    for number, line in enumerate(source, 1):
                        if line.strip():
                            try:
                                record = collect_violations.parse_log_line(line)
                                if not collect_violations.valid_event_timestamp(
                                    record.get("eventTimestamp")
                                ):
                                    raise ValueError("invalid timestamp")
                            except ValueError:
                                raise common.ValidationError(
                                    "invalid record in %s at line %d" % (path.name, number)
                                )
                        # Preserve content, adding only a missing line separator.
                        dest.write(line if line.endswith("\n") else line + "\n")
            dest.flush()
            os.fsync(dest.fileno())
        os.chmod(temporary, 0o600)
        # Carry the collection start before publication. The manifest cannot
        # later substitute its own build time for this evidence.
        os.utime(temporary, (started_at, started_at))
        # Atomic publication without replacing a previously published log.
        os.link(temporary, target)
    finally:
        os.unlink(temporary)
    return {
        "publishedAt": time.time(),
        "collectionStartedAt": started_at,
        "earliestCopiedAt": copied_at,
        "fileCount": len(paths),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", action="append", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--window-end", required=True)
    parser.add_argument("--started-at", required=True)
    args = parser.parse_args()
    result = finalize(
        args.file,
        args.output,
        collect_violations.parse_timestamp(args.window_end),
        collect_violations.parse_timestamp(args.started_at),
    )
    print(
        "node log publishedAt=%s collectionStartedAt=%s "
        "earliestCopiedAt=%s files=%d"
        % (
            result["publishedAt"],
            result["collectionStartedAt"],
            result["earliestCopiedAt"],
            result["fileCount"],
        ),
        file=sys.stderr,
    )


if __name__ == "__main__":
    try:
        main()
    except (OSError, EOFError, UnicodeError, common.ValidationError) as error:
        print("FINALIZE NODE LOG FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
