#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0

import argparse
import json
import subprocess
import sys


RESOURCE_ALIASES = {
    "pod": "pod",
    "deployment": "deployment",
    "deploy": "deployment",
    "statefulset": "statefulset",
    "sts": "statefulset",
    "daemonset": "daemonset",
    "ds": "daemonset",
}

DEFAULT_TIMEOUT_SECONDS = 20


def run_json(command, context=None, timeout=DEFAULT_TIMEOUT_SECONDS):
    if context:
        command = [command[0], "--context", context, *command[1:]]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as error:
        print(f"ERROR stage=object_query kind=DEPENDENCY_MISSING reason={json.dumps(str(error))}")
        sys.exit(127)
    except subprocess.TimeoutExpired:
        print(f"ERROR stage=object_query kind=TIMEOUT reason={json.dumps(f'command exceeded {timeout}s timeout')}")
        sys.exit(2)
    except OSError as error:
        print(f"ERROR stage=object_query kind=OS_ERROR reason={json.dumps(str(error))}")
        sys.exit(2)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown kubectl error"
        print(f"ERROR stage=object_query kind=KUBECTL_FAILED reason={json.dumps(message)}")
        sys.exit(2)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        print(f"ERROR stage=object_parse kind=BAD_RESPONSE reason={json.dumps(str(error))}")
        sys.exit(2)


def profile_value(profile):
    if not isinstance(profile, dict) or not profile:
        return "UNSET"
    profile_type = profile.get("type") or "UNKNOWN"
    localhost = profile.get("localhostProfile")
    return f"{profile_type}/{localhost}" if localhost else profile_type


def print_security_context(prefix, spec):
    security_context = spec.get("securityContext") or {}
    print(f"{prefix}_APPARMOR value={json.dumps(profile_value(security_context.get('appArmorProfile')))}")
    print(f"{prefix}_SECCOMP value={json.dumps(profile_value(security_context.get('seccompProfile')))}")
    for container in spec.get("containers") or []:
        container_name = container.get("name") or "UNKNOWN"
        context = container.get("securityContext") or {}
        print(
            f"CONTAINER_SECURITY name={container_name} "
            f"apparmor={json.dumps(profile_value(context.get('appArmorProfile')))} "
            f"seccomp={json.dumps(profile_value(context.get('seccompProfile')))}"
        )


def print_container(kind, container):
    print(
        f"{kind} name={container.get('name', 'UNKNOWN')} "
        f"image={json.dumps(container.get('image') or 'UNKNOWN')}"
    )


def print_init_container_security(container):
    context = container.get("securityContext") or {}
    capabilities = context.get("capabilities") or {}
    privileged = context.get("privileged")
    print(
        f"INIT_CONTAINER_SECURITY name={container.get('name', 'UNKNOWN')} "
        f"apparmor={json.dumps(profile_value(context.get('appArmorProfile')))} "
        f"seccomp={json.dumps(profile_value(context.get('seccompProfile')))} "
        f"privileged={json.dumps('UNSET' if privileged is None else privileged)} "
        f"capabilities_add={json.dumps(capabilities.get('add') or [], separators=(',', ':'))} "
        f"capabilities_drop={json.dumps(capabilities.get('drop') or [], separators=(',', ':'))}"
    )


def print_volume(volume):
    source_type = "other"
    source_name = "UNKNOWN"
    if volume.get("secret") is not None:
        source_type = "secret"
        source_name = (volume.get("secret") or {}).get("secretName") or "UNKNOWN"
    elif volume.get("configMap") is not None:
        source_type = "configMap"
        source_name = (volume.get("configMap") or {}).get("name") or "UNKNOWN"
    elif volume.get("hostPath") is not None:
        source_type = "hostPath"
        source_name = "REDACTED"
    elif volume.get("projected") is not None:
        source_type = "projected"
        source_name = "MULTIPLE"
    elif volume.get("emptyDir") is not None:
        source_type = "emptyDir"
        source_name = "NONE"
    print(
        f"VOLUME name={volume.get('name', 'UNKNOWN')} "
        f"source_type={source_type} source_name={json.dumps(source_name)}"
    )


def main():
    parser = argparse.ArgumentParser(description="Extract injection-relevant facts from one Pod or Workload.")
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--kind", required=True, choices=tuple(RESOURCE_ALIASES))
    parser.add_argument("--name", required=True)
    parser.add_argument("--context", help="kubectl context override; defaults to the current context.")
    args = parser.parse_args()

    resource = RESOURCE_ALIASES[args.kind]
    obj = run_json(
        ["kubectl", "-n", args.namespace, "get", resource, args.name, "-o", "json"],
        context=args.context,
    )
    metadata = obj.get("metadata") or {}
    if resource == "pod":
        template_metadata = metadata
        spec = obj.get("spec") or {}
    else:
        template = ((obj.get("spec") or {}).get("template") or {})
        template_metadata = template.get("metadata") or {}
        spec = template.get("spec") or {}

    print(
        f"OBJECT kind={obj.get('kind', 'UNKNOWN')} namespace={metadata.get('namespace', args.namespace)} "
        f"name={metadata.get('name', args.name)} uid={metadata.get('uid', 'UNKNOWN')} "
        f"created={metadata.get('creationTimestamp', 'UNKNOWN')}"
    )
    if resource == "pod":
        print(
            f"POD_RUNTIME node={spec.get('nodeName') or 'UNSCHEDULED'} "
            f"phase={((obj.get('status') or {}).get('phase') or 'UNKNOWN')}"
        )
        owners = [
            owner
            for owner in metadata.get("ownerReferences") or []
            if owner.get("controller") is True
        ]
        if len(owners) == 1:
            owner = owners[0]
            print(f"CONTROLLER_OWNER kind={owner.get('kind', 'UNKNOWN')} name={owner.get('name', 'UNKNOWN')}")
        elif not owners:
            print("CONTROLLER_OWNER kind=NONE name=NONE")
        else:
            print(f"CONTROLLER_OWNER kind=AMBIGUOUS name=AMBIGUOUS count={len(owners)}")

    annotation_keys = sorted((template_metadata.get("annotations") or {}).keys())
    if annotation_keys:
        for key in annotation_keys:
            print(f"ANNOTATION_KEY key={json.dumps(key)}")
    else:
        print("ANNOTATION_KEY key=NONE")

    print_security_context("POD", spec)
    for container in spec.get("initContainers") or []:
        print_container("INIT_CONTAINER", container)
        print_init_container_security(container)
    for container in spec.get("containers") or []:
        print_container("CONTAINER", container)
    for volume in spec.get("volumes") or []:
        print_volume(volume)

    print(
        f"SUMMARY annotation_keys={len(annotation_keys)} "
        f"init_containers={len(spec.get('initContainers') or [])} "
        f"containers={len(spec.get('containers') or [])} volumes={len(spec.get('volumes') or [])}"
    )
    print("INTERPRETATION status=NOT_EVALUATED reason=script_reports_facts_only")


if __name__ == "__main__":
    main()
