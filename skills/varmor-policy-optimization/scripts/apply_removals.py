#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministically apply non-Seccomp rule removals.
# The model records exact rule coordinates and the user's remove/keep/observe
# decision in attribution.json. This tool derives removal coordinates and
# performs the structural deletion so the model never edits policy YAML freely.
# Each coordinate must match exactly one current atom.
#
# Seccomp removals are already applied beforehand by seccomp_plan.py, so this
# tool only handles the remaining sources. The result is independently
# re-verified by guard_removal.py.

import argparse
import copy
import json
import sys

import vopt_common as common
import validate_attribution
import preprocess_aggregate


class RemoveError(common.ValidationError):
    pass


def _norm_apparmor(line):
    return " ".join(str(line).strip().rstrip(",;").split())


def _remove_from_string_array(enhance, field, target):
    values = enhance.get(field) or []
    target = target.strip()
    remaining = [item for item in values if not (isinstance(item, str) and item.strip() == target)]
    removed = len(values) - len(remaining)
    _require_one(removed, field, target)
    if remaining:
        enhance[field] = remaining
    else:
        enhance.pop(field, None)


def _remove_attack(enhance, rule, targets):
    targets = sorted(targets)
    groups = enhance.get("attackProtectionRules") or []
    removed = 0
    out = []
    for group in groups:
        if not isinstance(group, dict) or sorted(group.get("targets") or []) != targets:
            out.append(group)
            continue
        rules = group.get("rules") or []
        kept = []
        for item in rules:
            if isinstance(item, str) and item.strip() == rule.strip():
                removed += 1
                continue
            kept.append(item)
        if kept:
            group["rules"] = kept
            out.append(group)
    _require_one(removed, "attackProtectionRules", rule)
    if out:
        enhance["attackProtectionRules"] = out
    else:
        enhance.pop("attackProtectionRules", None)


def _remove_apparmor(enhance, rule, targets):
    targets = sorted(targets)
    wanted = _norm_apparmor(rule)
    groups = enhance.get("appArmorRawRules") or []
    removed = 0
    out = []
    for group in groups:
        if not isinstance(group, dict) or sorted(group.get("targets") or []) != targets:
            out.append(group)
            continue
        kept_lines = []
        for line in str(group.get("rules") or "").splitlines():
            if _norm_apparmor(line) == wanted and line.strip():
                removed += 1
                continue
            kept_lines.append(line)
        text = "\n".join(line for line in kept_lines if line.strip())
        if text:
            group["rules"] = text + "\n"
            out.append(group)
    _require_one(removed, "appArmorRawRules", wanted)
    if out:
        enhance["appArmorRawRules"] = out
    else:
        enhance.pop("appArmorRawRules", None)


def _descend_bpf(enhance):
    bpf = enhance.get("bpfRawRules")
    if not isinstance(bpf, dict):
        raise RemoveError("bpfRawRules is absent")
    return bpf


def _remove_bpf_array(container, field, target):
    values = container.get(field) or []
    wanted = common.stable_json(target)
    kept = [item for item in values if common.stable_json(item) != wanted]
    removed = len(values) - len(kept)
    _require_one(removed, field, wanted)
    if kept:
        container[field] = kept
    else:
        container.pop(field, None)


def _remove_bpf_ptrace(bpf, target):
    current = bpf.get("ptrace")
    if not isinstance(current, dict) or common.stable_json(current) != common.stable_json(target):
        raise RemoveError("bpfRawRules.ptrace does not match the selected rule")
    bpf.pop("ptrace", None)


def _remove_bpf(enhance, source, target):
    bpf = _descend_bpf(enhance)
    if source in ("bpfRawRules.files", "bpfRawRules.processes", "bpfRawRules.mounts"):
        field = source.split(".")[-1]
        _remove_bpf_array(bpf, field, target)
        return
    if source == "bpfRawRules.ptrace":
        _remove_bpf_ptrace(bpf, target)
        return
    network = bpf.get("network")
    if not isinstance(network, dict):
        raise RemoveError("bpfRawRules.network is absent")
    if source == "bpfRawRules.network.sockets":
        _remove_bpf_array(network, "sockets", target)
        return
    egress = network.get("egress")
    if not isinstance(egress, dict):
        raise RemoveError("bpfRawRules.network.egress is absent")
    field = source.split(".")[-1]  # toDestinations / toServices / toPods
    _remove_bpf_array(egress, field, target)


def _remove_networkproxy(enhance, field, target):
    egress = common.get_path(enhance, "networkProxyRawRules", "egress")
    if not isinstance(egress, dict):
        raise RemoveError("networkProxyRawRules.egress is absent")
    values = egress.get(field) or []
    wanted = common.stable_json(target)
    kept = [item for item in values if common.stable_json(item) != wanted]
    removed = len(values) - len(kept)
    _require_one(removed, field, wanted)
    if kept:
        egress[field] = kept
    else:
        egress.pop(field, None)


def _require_one(removed, source, target):
    if removed == 0:
        raise RemoveError("no current rule in %s matches %s" % (source, target))
    if removed > 1:
        raise RemoveError(
            "%s has %d duplicate matches for %s; refusing ambiguous removal"
            % (source, removed, target)
        )


DISPATCH = {
    "hardeningRules": lambda enhance, coord: _remove_from_string_array(
        enhance, "hardeningRules", coord["rule"]
    ),
    "vulMitigationRules": lambda enhance, coord: _remove_from_string_array(
        enhance, "vulMitigationRules", coord["rule"]
    ),
    "attackProtectionRules": lambda enhance, coord: _remove_attack(
        enhance,
        coord["rule"],
        (coord.get("context") or {}).get("targets") or [],
    ),
    "appArmorRawRules": lambda enhance, coord: _remove_apparmor(
        enhance,
        coord["rule"],
        (coord.get("context") or {}).get("targets") or [],
    ),
    "networkProxyRawRules.egress.rules": lambda enhance, coord: _remove_networkproxy(
        enhance, "rules", coord["rule"]
    ),
    "networkProxyRawRules.egress.httpRules": lambda enhance, coord: _remove_networkproxy(
        enhance, "httpRules", coord["rule"]
    ),
}


def _coord_key(coord):
    """Identity of a removal coordinate / authorized match."""
    return common.stable_json(
        {
            "source": coord.get("source"),
            "rule": coord.get("rule"),
            "targets": sorted(
                (coord.get("context") or {}).get("targets") or []
            ),
        }
    )


def apply_removals(
    document,
    coordinates,
    authorized,
    network_proxy_evidence_eligible=False,
):
    root = copy.deepcopy(document)
    enhance = common.get_path(root, "spec", "policy", "enhanceProtect")
    if not isinstance(enhance, dict):
        raise RemoveError("spec.policy.enhanceProtect is required")

    # Boundary check: the checked list is recomputed by
    # validate_attribution.py. This prevents removal coordinates outside the
    # referenced event/catalog/enforcer set, but does not prove semantic
    # attribution correctness.
    if not isinstance(authorized, dict) or authorized.get(
        "marker"
    ) != "vopt-authorized-removals":
        raise RemoveError(
            "an authorized-removals document from validate_attribution.py "
            "is required"
        )
    allowed = {_coord_key(item) for item in authorized.get("authorized") or []}
    for coord in coordinates:
        if _coord_key(coord) not in allowed:
            raise RemoveError(
                "removal %s is not present in the authorized set"
                % _coord_key(coord)
            )

    applied = 0
    for index, coord in enumerate(coordinates):
        source = coord.get("source")
        if not isinstance(source, str) or not source or "rule" not in coord:
            raise RemoveError("coordinate #%d must contain source and rule" % index)
        if (
            source.startswith("networkProxyRawRules")
            and not network_proxy_evidence_eligible
        ):
            raise RemoveError(
                "NetworkProxy evidence is ineligible; refusing removal from %s"
                % source
            )
        if source in DISPATCH:
            DISPATCH[source](enhance, coord)
        elif source.startswith("bpfRawRules"):
            _remove_bpf(enhance, source, coord["rule"])
        else:
            raise RemoveError("unsupported source %r" % source)
        applied += 1
    return root, applied


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="baseline policy YAML (post-Seccomp)")
    parser.add_argument("--pre", required=True, help="preprocess_aggregate output (pre.json)")
    parser.add_argument(
        "--attribution",
        required=True,
        help="model attribution draft; semantic conclusions require user review",
    )
    args = parser.parse_args()

    document = common.load_yaml_doc(common.read_input(args.baseline))

    # Authorization is recomputed in-process. The rule catalog is also derived
    # deterministically from the same baseline (not from an external file), so a
    # hand-written catalog cannot mislabel enforcers to authorize a deletion.
    with open(args.pre, "r", encoding="utf-8") as handle:
        pre = json.load(handle)
    catalog = {
        "ruleCatalog": preprocess_aggregate.build_rule_catalog(
            document, common.load_catalog()
        )
    }
    with open(args.attribution, "r", encoding="utf-8") as handle:
        attribution = json.load(handle)
    authorized = validate_attribution.validate(
        pre,
        catalog,
        attribution,
        require_decisions=True,
    )
    coordinates = validate_attribution.selected_removals(authorized)

    root, applied = apply_removals(
        document,
        coordinates,
        authorized,
        network_proxy_evidence_eligible=(
            pre.get("networkProxyEvidenceEligible") is True
        ),
    )
    print(common.dump_yaml(root))
    print("removed %d rule(s)" % applied, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except common.ValidationError as error:
        print("APPLY REMOVALS FAILED: %s" % error, file=sys.stderr)
        sys.exit(1)
