#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
"""Read-only kubectl fixture. Never forwards a command to an actual cluster."""
import json
import os
from pathlib import Path
import subprocess
import sys

args = sys.argv[1:]
config = json.loads(Path(os.environ["VOPT_TEST_CONFIG"]).read_text())
with open(os.environ["VOPT_TEST_CALLS"], "a") as handle:
    handle.write(json.dumps(args) + "\n")
if args[:2] != ["--context", config["context"]] or not args[2].startswith("--request-timeout="):
    sys.exit(8)
args = args[3:]
if config.get("fail"):
    print("synthetic-private-error-do-not-disclose", file=sys.stderr)
    sys.exit(7)
if args[:2] == ["get", "vpol"]:
    print(json.dumps(config["policy"]))
elif args[:2] == ["get", "vcpol"]:
    print(json.dumps(config["clusterPolicy"]))
elif args[:2] == ["get", "daemonset,pods"]:
    print(json.dumps(config["inventory"]))
elif args[:2] == ["get", "pod"]:
    print(json.dumps(config["pod"]))
elif args[0] == "exec" and "--" in args:
    result = subprocess.run(args[args.index("--") + 1:], capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.stderr.buffer.write(result.stderr)
    sys.exit(result.returncode)
else:
    sys.exit(9)
