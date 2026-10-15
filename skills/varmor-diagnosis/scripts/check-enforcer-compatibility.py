#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0

import argparse
import json
import re
import subprocess
import sys


ENFORCERS = ("apparmor", "bpf", "seccomp")

DEFAULT_TIMEOUT_SECONDS = 20


def run_json(command, stage, context=None, timeout=DEFAULT_TIMEOUT_SECONDS):
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
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(f"ERROR stage={stage}_parse kind=BAD_RESPONSE reason={json.dumps(str(error))}")
        sys.exit(2)


def version_tuple(value):
    match = re.search(r"(\d+)\.(\d+)", value or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def add_requirement(requirements, name, state, actual, required, evidence, limitation=None):
    requirements.append(
        {
            "name": name,
            "state": state,
            "actual": actual,
            "required": required,
            "evidence": evidence,
            "limitation": limitation,
        }
    )


def compare_version(requirements, name, actual, required, evidence, limitation=None):
    parsed = version_tuple(actual)
    if parsed is None:
        add_requirement(
            requirements,
            name,
            "TO_PROVE",
            actual or "UNKNOWN",
            f">={required[0]}.{required[1]}",
            evidence,
            limitation,
        )
    elif parsed >= required:
        add_requirement(
            requirements,
            name,
            "PROVEN",
            actual,
            f">={required[0]}.{required[1]}",
            evidence,
            limitation,
        )
    else:
        add_requirement(
            requirements,
            name,
            "UNSATISFIED",
            actual,
            f">={required[0]}.{required[1]}",
            evidence,
            limitation,
        )


def print_record(record_type, record):
    fields = [
        f"condition={record['name']}",
        f"state={record['state']}",
        f"actual={json.dumps(record['actual'])}",
    ]
    for key in ("required", "evidence", "limitation", "scope"):
        if record.get(key) is not None:
            fields.append(f"{key}={json.dumps(record[key])}")
    print(f"{record_type} {' '.join(fields)}")


def main():
    parser = argparse.ArgumentParser(description="Check one node against vArmor enforcer prerequisites.")
    parser.add_argument("--node", required=True, help="Target Kubernetes node name.")
    parser.add_argument("--enforcer", required=True, choices=ENFORCERS)
    parser.add_argument("--context", help="kubectl context override; defaults to the current context.")
    args = parser.parse_args()

    node = run_json(["kubectl", "get", "node", args.node, "-o", "json"], "node_query", context=args.context)
    node_info = (node.get("status") or {}).get("nodeInfo") or {}
    os_name = node_info.get("operatingSystem") or "UNKNOWN"
    os_image = node_info.get("osImage") or "UNKNOWN"
    architecture = node_info.get("architecture") or "UNKNOWN"
    kernel = node_info.get("kernelVersion") or "UNKNOWN"
    runtime = node_info.get("containerRuntimeVersion") or "UNKNOWN"
    kubelet = node_info.get("kubeletVersion") or "UNKNOWN"

    print(
        f"FACT subject=node name={args.node} os={json.dumps(os_name)} "
        f"os_image={json.dumps(os_image)} arch={json.dumps(architecture)} "
        f"kernel={json.dumps(kernel)} runtime={json.dumps(runtime)} kubelet={json.dumps(kubelet)} "
        'source="Kubernetes Node status.nodeInfo"'
    )

    requirements = []
    capabilities = []
    indicators = []
    next_probes = []
    if os_name == "linux":
        add_requirement(
            requirements, "operating_system", "PROVEN", os_name, "linux", "Kubernetes Node status.nodeInfo"
        )
    elif os_name == "UNKNOWN":
        add_requirement(
            requirements, "operating_system", "TO_PROVE", os_name, "linux", "Kubernetes Node status.nodeInfo"
        )
    else:
        add_requirement(
            requirements, "operating_system", "UNSATISFIED", os_name, "linux", "Kubernetes Node status.nodeInfo"
        )

    if args.enforcer == "apparmor":
        compare_version(
            requirements,
            "kernel_version",
            kernel,
            (4, 15),
            "Kubernetes Node status.nodeInfo",
            "version threshold does not prove that AppArmor LSM is enabled",
        )
        capabilities.append(
            {
                "name": "apparmor_lsm",
                "state": "TO_PROVE",
                "actual": "UNKNOWN",
                "required": "enabled",
                "evidence": "Node API does not expose the active LSM list",
                "scope": "required",
            }
        )
        next_probes.append(
            {
                "capability": "apparmor_lsm",
                "risk": "L2",
                "probe": "read the active LSM list and AppArmor enabled state via the confirmed existing agent mount; assess access scope",
            }
        )
    elif args.enforcer == "bpf":
        if architecture in ("amd64", "x86_64"):
            add_requirement(
                requirements, "architecture", "PROVEN", architecture, "x86_64", "Kubernetes Node status.nodeInfo"
            )
        elif architecture == "UNKNOWN":
            add_requirement(
                requirements, "architecture", "TO_PROVE", architecture, "x86_64", "Kubernetes Node status.nodeInfo"
            )
        else:
            add_requirement(
                requirements,
                "architecture",
                "UNSATISFIED",
                architecture,
                "x86_64",
                "Kubernetes Node status.nodeInfo",
            )
        compare_version(
            requirements,
            "kernel_version",
            kernel,
            (5, 10),
            "Kubernetes Node status.nodeInfo",
            "version threshold does not prove BPF LSM or BTF availability",
        )
        runtime_name, separator, runtime_version = runtime.partition("://")
        if not separator:
            add_requirement(
                requirements, "container_runtime", "TO_PROVE", runtime, "containerd>=1.6", "unrecognized runtime format"
            )
        elif runtime_name != "containerd":
            add_requirement(
                requirements,
                "container_runtime",
                "UNSATISFIED",
                runtime,
                "containerd>=1.6",
                "Kubernetes Node status.nodeInfo",
            )
        else:
            compare_version(
                requirements,
                "containerd_version",
                runtime_version,
                (1, 6),
                "Kubernetes Node status.nodeInfo",
            )
        capabilities.extend(
            [
                {
                    "name": "bpf_lsm",
                    "state": "TO_PROVE",
                    "actual": "UNKNOWN",
                    "required": "enabled",
                    "evidence": "Node API and kernel version do not expose the active LSM list",
                    "scope": "required",
                },
                {
                    "name": "btf",
                    "state": "TO_PROVE",
                    "actual": "UNKNOWN",
                    "required": "available when the selected feature or failed load depends on BTF",
                    "evidence": "Node API and distribution/kernel names do not prove BTF availability",
                    "scope": "scenario_dependent",
                },
            ]
        )
        next_probes.extend(
            [
                {
                    "capability": "bpf_lsm",
                    "risk": "L2",
                    "probe": "read the active LSM list via the confirmed existing agent mount and check for bpf; assess access scope",
                },
                {
                    "capability": "btf",
                    "risk": "L2",
                    "probe": "when required, check readability of the known BTF file via the existing agent mount and correlate load errors",
                },
            ]
        )
    elif args.enforcer == "seccomp":
        version = run_json(["kubectl", "version", "-o", "json"], "kubernetes_version_query", context=args.context)
        server_version = ((version.get("serverVersion") or {}).get("gitVersion") or "UNKNOWN")
        print(
            f"FACT subject=kubernetes_api server_version={json.dumps(server_version)} "
            'source="kubectl version -o json"'
        )
        compare_version(
            requirements,
            "kubernetes_version",
            server_version,
            (1, 19),
            "Kubernetes API server version",
            "version threshold does not prove seccomp is enabled in the container runtime",
        )

    indicators.append(
        {
            "name": "distribution",
            "state": "OBSERVED" if os_image != "UNKNOWN" else "UNKNOWN",
            "actual": os_image,
            "evidence": "Kubernetes Node status.nodeInfo.osImage",
            "limitation": "distribution is a support clue only and proves no kernel capability",
        }
    )

    for requirement in requirements:
        print_record("REQUIREMENT", requirement)
    for indicator in indicators:
        print_record("INDICATOR", indicator)
    for capability in capabilities:
        print_record("CAPABILITY", capability)

    requirement_states = {item["state"] for item in requirements}
    required_capabilities_to_prove = sum(
        item["state"] == "TO_PROVE" and item["scope"] == "required" for item in capabilities
    )
    if "UNSATISFIED" in requirement_states:
        conclusion = "INCOMPATIBLE"
        reason = "one_or_more_required_conditions_unsatisfied"
    elif "TO_PROVE" in requirement_states or required_capabilities_to_prove:
        conclusion = "PARTIALLY_VERIFIED"
        reason = "one_or_more_required_conditions_or_capabilities_remain_to_prove"
    else:
        conclusion = "COMPATIBLE"
        reason = "all_required_conditions_proven"
    proven = sum(item["state"] == "PROVEN" for item in requirements)
    unsatisfied = sum(item["state"] == "UNSATISFIED" for item in requirements)
    to_prove = sum(item["state"] == "TO_PROVE" for item in requirements) + required_capabilities_to_prove
    print(
        f"CONCLUSION enforcer={args.enforcer} status={conclusion} "
        f"proven={proven} unsatisfied={unsatisfied} to_prove={to_prove} reason={reason}"
    )
    for probe in next_probes:
        print(
            f"NEXT_PROBE capability={probe['capability']} risk={probe['risk']} "
            f"probe={json.dumps(probe['probe'])}"
        )


if __name__ == "__main__":
    main()
