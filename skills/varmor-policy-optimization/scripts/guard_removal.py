#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Safety gate: verify that the final candidate is exactly the result of the
# deterministic Seccomp plan plus the intended non-Seccomp removals.
#
# Ported from policy-optimization-agent/internal/policyguard/removal.go.
# It rejects any added or rewritten rule and any change to the control
# switches (privileged, auditViolations, allowViolations, NetworkProxy
# defaultAction). It does not judge business behavior.
#
# The baseline is the original current policy. The Seccomp plan is recomputed
# from pre.json inside this process, so the final structured diff covers both
# Seccomp and model-attributed removals.

import argparse
import json
import sys

import apply_removals as removal_applier
import preprocess_aggregate
import seccomp_plan as seccomp_optimizer
import validate_attribution
import vopt_common as common

CONTROL_BOOL_FIELDS = ("privileged", "auditViolations", "allowViolations")


def _atom(value):
    return common.stable_json(value)


def _normalize_apparmor_line(line):
    return " ".join(line.strip().rstrip(",;").split())


def _atomize(enhance):
    """Return {source: {atom: display}} for every rule-bearing source."""
    sources = {}

    def put(source, display):
        sources.setdefault(source, {})[_atom(display)] = display

    for rule in enhance.get("hardeningRules") or []:
        put("hardeningRules", str(rule).strip())
    for rule in enhance.get("vulMitigationRules") or []:
        put("vulMitigationRules", str(rule).strip())

    for group in enhance.get("attackProtectionRules") or []:
        if not isinstance(group, dict):
            continue
        targets = group.get("targets") or []
        for rule in group.get("rules") or []:
            put(
                "attackProtectionRules",
                {"rule": str(rule).strip(), "targets": sorted(targets)},
            )

    for group in enhance.get("appArmorRawRules") or []:
        if not isinstance(group, dict):
            continue
        targets = group.get("targets") or []
        for line in str(group.get("rules") or "").splitlines():
            normalized = _normalize_apparmor_line(line)
            if normalized:
                put(
                    "appArmorRawRules",
                    {"rule": normalized, "targets": sorted(targets)},
                )

    bpf = enhance.get("bpfRawRules")
    if isinstance(bpf, dict):
        for field, source in (
            ("files", "bpfRawRules.files"),
            ("processes", "bpfRawRules.processes"),
            ("mounts", "bpfRawRules.mounts"),
        ):
            for obj in bpf.get(field) or []:
                put(source, obj)
        if isinstance(bpf.get("ptrace"), dict):
            put("bpfRawRules.ptrace", bpf["ptrace"])
        network = bpf.get("network")
        if isinstance(network, dict):
            for obj in network.get("sockets") or []:
                put("bpfRawRules.network.sockets", obj)
            egress = network.get("egress")
            if isinstance(egress, dict):
                for field, source in (
                    ("toDestinations", "bpfRawRules.network.egress.toDestinations"),
                    ("toServices", "bpfRawRules.network.egress.toServices"),
                    ("toPods", "bpfRawRules.network.egress.toPods"),
                ):
                    for obj in egress.get(field) or []:
                        put(source, obj)

    for raw in enhance.get("syscallRawRules") or []:
        if not isinstance(raw, dict):
            continue
        for name in raw.get("names") or []:
            single = dict(raw)
            single["names"] = [name]
            put("syscallRawRules", single)

    network_proxy = enhance.get("networkProxyRawRules")
    if isinstance(network_proxy, dict):
        egress = network_proxy.get("egress")
        if isinstance(egress, dict):
            for field, source in (
                ("rules", "networkProxyRawRules.egress.rules"),
                ("httpRules", "networkProxyRawRules.egress.httpRules"),
            ):
                for obj in egress.get(field) or []:
                    put(source, obj)

    return sources


def _check_controls(baseline, candidate):
    for field in CONTROL_BOOL_FIELDS:
        if (field in baseline) != (field in candidate):
            return "%s must remain present or absent exactly as in the baseline" % field
        if baseline.get(field) != candidate.get(field):
            return "%s must remain unchanged" % field

    base_np = baseline.get("networkProxyRawRules")
    cand_np = candidate.get("networkProxyRawRules")
    if cand_np is not None and base_np is None:
        return "networkProxyRawRules cannot be added"
    if isinstance(cand_np, dict):
        base_egress = (base_np or {}).get("egress")
        cand_egress = cand_np.get("egress")
        if cand_egress is not None and not isinstance(base_egress, dict):
            return "networkProxyRawRules.egress cannot be added"
        if isinstance(cand_egress, dict) and isinstance(base_egress, dict):
            if cand_egress.get("defaultAction") != base_egress.get("defaultAction"):
                return "networkProxyRawRules.egress.defaultAction must remain unchanged"
    return None


def _strip_enhance(document):
    """Return a deep copy of the CRD with enhanceProtect removed so that every
    field OUTSIDE spec.policy.enhanceProtect can be compared verbatim."""
    import copy

    root = copy.deepcopy(document)
    policy = common.get_path(root, "spec", "policy")
    if isinstance(policy, dict):
        policy.pop("enhanceProtect", None)
    return root


def _strict_json(value):
    """Canonical object-key order while preserving array order and scalar types."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_live_spec(candidate_doc, live_doc):
    """Verify that a successful replace produced exactly the candidate spec."""
    for field in ("apiVersion", "kind"):
        if candidate_doc.get(field) != live_doc.get(field):
            raise common.ValidationError(
                "live %s does not match candidate" % field
            )

    candidate_metadata = candidate_doc.get("metadata")
    live_metadata = live_doc.get("metadata")
    if not isinstance(candidate_metadata, dict) or not isinstance(live_metadata, dict):
        raise common.ValidationError("candidate and live metadata must be objects")
    for field in ("name", "namespace"):
        if (candidate_metadata.get(field) or "") != (live_metadata.get(field) or ""):
            raise common.ValidationError(
                "live metadata.%s does not match candidate" % field
            )

    candidate_spec = candidate_doc.get("spec")
    live_spec = live_doc.get("spec")
    if not isinstance(candidate_spec, dict) or not isinstance(live_spec, dict):
        raise common.ValidationError("candidate and live spec must be objects")
    if _strict_json(candidate_spec) != _strict_json(live_spec):
        raise common.ValidationError("live spec does not exactly match candidate")
    return {"valid": True, "liveSpecVerified": True}


def guard(
    baseline_doc,
    candidate_doc,
    intended_removals=None,
    pre=None,
    allow_ambiguous=False,
    remove_seccomp_rules=None,
    keep_seccomp_rules=None,
    remove_seccomp_syscalls=None,
    keep_seccomp_syscalls=None,
):
    base_enhance = common.get_path(baseline_doc, "spec", "policy", "enhanceProtect")
    cand_enhance = common.get_path(candidate_doc, "spec", "policy", "enhanceProtect")
    if not isinstance(base_enhance, dict):
        raise common.ValidationError("baseline spec.policy.enhanceProtect is required")
    if not isinstance(cand_enhance, dict):
        raise common.ValidationError("candidate spec.policy.enhanceProtect is required")

    # Full-CRD guard: everything outside enhanceProtect must be byte-for-byte
    # identical. This blocks changes to metadata/target/enforcer/mode/
    # updateExistingWorkloads etc., not just rule edits.
    if common.stable_json(_strip_enhance(baseline_doc)) != common.stable_json(
        _strip_enhance(candidate_doc)
    ):
        raise common.ValidationError(
            "only rules under spec.policy.enhanceProtect may change; "
            "other CRD fields must remain identical"
        )

    control_error = _check_controls(base_enhance, cand_enhance)
    if control_error:
        raise common.ValidationError(control_error)

    if not isinstance(intended_removals, list):
        raise common.ValidationError(
            "intended removals are required for an exact candidate comparison"
        )
    network_proxy_removal = any(
        str(item.get("source") or "").startswith("networkProxyRawRules")
        for item in intended_removals
        if isinstance(item, dict)
    )
    network_proxy_evidence_eligible = (
        isinstance(pre, dict)
        and pre.get("networkProxyEvidenceEligible") is True
    )
    if network_proxy_removal and not network_proxy_evidence_eligible:
        raise common.ValidationError(
            "NetworkProxy evidence is ineligible; refusing NetworkProxy removal"
        )

    expected_baseline = baseline_doc
    seccomp_plan = None
    if pre is not None:
        if not isinstance(pre, dict) or pre.get("collectionComplete") is not True:
            raise common.ValidationError(
                "complete preprocessing evidence is required for Seccomp verification"
            )
        if pre.get("retentionCovered") is not True:
            raise common.ValidationError(
                "log retention coverage is not proven for Seccomp verification"
            )
        if pre.get("failures"):
            raise common.ValidationError(
                "preprocessing has invalid events; refusing Seccomp verification"
            )
        seccomp_plan = seccomp_optimizer.build_plan(
            baseline_doc,
            pre.get("seccompSyscalls") or [],
            remove_builtin_rules=remove_seccomp_rules,
            keep_builtin_rules=keep_seccomp_rules,
            remove_syscalls=remove_seccomp_syscalls,
            keep_syscalls=keep_seccomp_syscalls,
        )
        if seccomp_plan["decisionsComplete"] is not True:
            raise common.ValidationError(
                "explicit remove/keep decisions are required for every Seccomp candidate"
            )
        if seccomp_plan["ambiguousRemovals"] and not allow_ambiguous:
            raise common.ValidationError(
                "ambiguous syscall matches require explicit approval: %s"
                % ", ".join(seccomp_plan["ambiguousRemovals"])
            )
        expected_baseline = seccomp_optimizer.apply_plan(
            baseline_doc,
            seccomp_plan,
        )

    # Rebuild the only acceptable final candidate from the original policy,
    # deterministic Seccomp plan and intended model-attributed coordinates.
    authorized = {
        "marker": "vopt-authorized-removals",
        "authorized": intended_removals,
    }
    expected_doc, _ = removal_applier.apply_removals(
        expected_baseline,
        intended_removals,
        authorized,
        network_proxy_evidence_eligible=network_proxy_evidence_eligible,
    )
    if _strict_json(expected_doc) != _strict_json(candidate_doc):
        raise common.ValidationError(
            "candidate is not exactly the result of applying the intended "
            "removals to the baseline"
        )

    base_sources = _atomize(base_enhance)
    cand_sources = _atomize(cand_enhance)

    # 1) Nothing may be added or rewritten across every source.
    all_sources = set(base_sources) | set(cand_sources)
    for source in sorted(all_sources):
        base_atoms = set(base_sources.get(source, {}))
        cand_atoms = set(cand_sources.get(source, {}))
        additions = cand_atoms - base_atoms
        if additions:
            sample = _display(next(iter(additions)), cand_sources, source)
            raise common.ValidationError(
                "%s contains an added or rewritten rule: %s" % (source, sample)
            )

    # 2) Compute removed atoms.
    removed_by_source = {}
    total = 0
    for source in sorted(all_sources):
        base_atoms = set(base_sources.get(source, {}))
        cand_atoms = set(cand_sources.get(source, {}))
        removed = sorted(base_atoms - cand_atoms)
        if removed:
            removed_by_source[source] = [
                _display(atom, base_sources, source) for atom in removed
            ]
            total += len(removed)

    # 3) Every intended removal must actually be present in the diff.
    missing_intended = []
    if intended_removals:
        for item in intended_removals:
            source = item.get("source")
            display = _intended_display(item)
            if _atom(display) not in set(
                _atom(d) for d in removed_by_source.get(source, [])
            ):
                missing_intended.append("%s: %s" % (source, _short(display)))
    if missing_intended:
        raise common.ValidationError(
            "the candidate did not remove %d intended rule(s):\n- %s"
            % (len(missing_intended), "\n- ".join(missing_intended))
        )

    return {
        "valid": True,
        "totalRemoved": total,
        "removedBySource": removed_by_source,
        "seccompPlan": seccomp_plan,
    }


def _display(atom, sources, source):
    return sources.get(source, {}).get(atom)


def _intended_display(item):
    source = item.get("source")
    rule = item.get("rule")
    context = item.get("context") or {}
    if source in ("hardeningRules", "vulMitigationRules"):
        return str(rule).strip()
    if source == "attackProtectionRules":
        return {
            "rule": str(rule).strip(),
            "targets": sorted(context.get("targets") or []),
        }
    if source == "appArmorRawRules":
        return {
            "rule": _normalize_apparmor_line(str(rule)),
            "targets": sorted(context.get("targets") or []),
        }
    # BPF / Seccomp / NetworkProxy objects are compared as opaque structures.
    return rule


def _short(value):
    text = json.dumps(value, ensure_ascii=False)
    return text if len(text) <= 120 else text[:117] + "..."


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", help="original current policy YAML")
    parser.add_argument("--candidate", required=True, help="candidate policy YAML")
    parser.add_argument(
        "--pre",
        help="preprocess_aggregate output used to recompute Seccomp removals",
    )
    parser.add_argument(
        "--attribution",
        help="validated attribution with explicit remove/keep/observe decisions",
    )
    parser.add_argument("--live", help="live policy YAML fetched after replace")
    parser.add_argument(
        "--verify-live",
        action="store_true",
        help="compare candidate identity and spec with --live",
    )
    parser.add_argument(
        "--allow-ambiguous",
        action="store_true",
        help="verify a candidate containing explicitly approved ambiguous Seccomp removals",
    )
    parser.add_argument(
        "--remove-seccomp-rule",
        action="append",
        default=[],
        help="remove an observed built-in Seccomp rule (repeat; must match planning)",
    )
    parser.add_argument(
        "--keep-seccomp-rule",
        action="append",
        default=[],
        help="keep an observed built-in Seccomp rule (repeat; must match planning)",
    )
    parser.add_argument("--remove-seccomp-syscall", action="append", default=[])
    parser.add_argument("--keep-seccomp-syscall", action="append", default=[])
    args = parser.parse_args()

    try:
        result = _run(args)
    except (OSError, ValueError, common.ValidationError) as error:
        print("REMOVAL CHECK FAILED:\n%s" % error, file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, ensure_ascii=False, indent=2))


def _run(args):
    candidate_doc = common.load_yaml_doc(common.read_input(args.candidate))
    if args.verify_live:
        if not args.live:
            raise common.ValidationError("--live is required with --verify-live")
        live_doc = common.load_yaml_doc(common.read_input(args.live))
        return verify_live_spec(candidate_doc, live_doc)
    if not args.baseline or not args.pre or not args.attribution:
        raise common.ValidationError(
            "--baseline, --pre and --attribution are required for candidate guarding"
        )
    baseline_doc = common.load_yaml_doc(common.read_input(args.baseline))
    with open(args.pre, "r", encoding="utf-8") as handle:
        pre = json.load(handle)
    with open(args.attribution, "r", encoding="utf-8") as handle:
        attribution = json.load(handle)
    plan = seccomp_optimizer.build_plan(
        baseline_doc,
        pre.get("seccompSyscalls") or [],
        remove_builtin_rules=args.remove_seccomp_rule,
        keep_builtin_rules=args.keep_seccomp_rule,
        remove_syscalls=args.remove_seccomp_syscall,
        keep_syscalls=args.keep_seccomp_syscall,
    )
    if plan["decisionsComplete"] is not True:
        raise common.ValidationError(
            "explicit remove/keep decisions are required for every Seccomp candidate"
        )
    if plan["ambiguousRemovals"] and not args.allow_ambiguous:
        raise common.ValidationError(
            "ambiguous syscall matches require explicit approval: %s"
            % ", ".join(plan["ambiguousRemovals"])
        )
    post_seccomp = seccomp_optimizer.apply_plan(baseline_doc, plan)
    catalog = {
        "ruleCatalog": preprocess_aggregate.build_rule_catalog(
            post_seccomp,
            common.load_catalog(),
        )
    }
    authorized = validate_attribution.validate(
        pre,
        catalog,
        attribution,
        require_decisions=True,
    )
    intended = validate_attribution.selected_removals(authorized)

    return guard(
        baseline_doc,
        candidate_doc,
        intended,
        pre=pre,
        allow_ambiguous=args.allow_ambiguous,
        remove_seccomp_rules=args.remove_seccomp_rule,
        keep_seccomp_rules=args.keep_seccomp_rule,
        remove_seccomp_syscalls=args.remove_seccomp_syscall,
        keep_seccomp_syscalls=args.keep_seccomp_syscall,
    )


if __name__ == "__main__":
    main()
