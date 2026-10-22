#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Deterministic validation and normalization for a VarmorPolicy /
# VarmorClusterPolicy that will run in EnhanceProtect observation mode.
#
# Ported from varmor-agent/policyoptimization/policy_validation.go.
# It collects every error in one stable pass, applies safe automatic
# adjustments, and returns non-blocking risk notices separately.

import argparse
import copy
import json
import re
import sys

import vopt_common as common

MAX_POLICY_BYTES = 256 * 1024

TARGET_KINDS = ("Deployment", "StatefulSet", "DaemonSet", "Pod")

EXPECTED_API_VERSIONS = ("crd.varmor.org/v1beta1",)

# OCI LinuxSeccomp actions (opencontainers/runtime-spec). Only these are valid.
SECCOMP_ACTIONS = {
    "SCMP_ACT_ALLOW",
    "SCMP_ACT_ERRNO",
    "SCMP_ACT_LOG",
    "SCMP_ACT_KILL",
    "SCMP_ACT_KILL_PROCESS",
    "SCMP_ACT_KILL_THREAD",
    "SCMP_ACT_TRAP",
    "SCMP_ACT_TRACE",
    "SCMP_ACT_NOTIFY",
}


def _is_string_list(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


_LABEL_OPERATORS = ("In", "NotIn", "Exists", "DoesNotExist")


def _has_valid_labels(match_labels):
    return (
        isinstance(match_labels, dict)
        and bool(match_labels)
        and all(
            isinstance(k, str) and k.strip() and isinstance(v, str)
            for k, v in match_labels.items()
        )
    )


def _match_labels_error(match_labels):
    if match_labels is None:
        return None
    if not isinstance(match_labels, dict):
        return "spec.target.selector.matchLabels must be an object"
    for key, value in match_labels.items():
        if not isinstance(key, str) or not key.strip():
            return "matchLabels keys must be nonempty strings"
        if not isinstance(value, str):
            return "matchLabels values must be strings (key=%r)" % key
    return None


def _has_valid_expressions(match_expressions):
    return (
        isinstance(match_expressions, list)
        and bool(match_expressions)
        and all(_expression_is_valid(expr) for expr in match_expressions)
    )


def _expression_is_valid(expr):
    if not isinstance(expr, dict):
        return False
    key = expr.get("key")
    operator = expr.get("operator")
    values = expr.get("values")
    if not (isinstance(key, str) and key.strip()):
        return False
    if operator not in _LABEL_OPERATORS:
        return False
    # values is optional; Kubernetes treats an omitted field as empty.
    if values is None:
        values = []
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        return False
    if operator in ("In", "NotIn") and not values:
        return False
    if operator in ("Exists", "DoesNotExist") and values:
        return False
    return True


def _match_expressions_error(match_expressions):
    if match_expressions is None:
        return None
    if not isinstance(match_expressions, list):
        return "spec.target.selector.matchExpressions must be an array"
    for expr in match_expressions:
        if not isinstance(expr, dict):
            return "Each matchExpressions entry must be an object"
        key = expr.get("key")
        operator = expr.get("operator")
        values = expr.get("values")
        if not (isinstance(key, str) and key.strip()):
            return "Each matchExpressions entry requires a nonempty key"
        if operator not in _LABEL_OPERATORS:
            return "matchExpressions operator must be one of %s" % "/".join(_LABEL_OPERATORS)
        # values may be omitted (== empty) for Exists/DoesNotExist.
        if values is None:
            values = []
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            return "matchExpressions values must be an array of strings (key=%r)" % key
        if operator in ("In", "NotIn") and not values:
            return "operator %s requires nonempty values (key=%r)" % (operator, key)
        if operator in ("Exists", "DoesNotExist") and values:
            return "operator %s requires empty values (key=%r)" % (operator, key)
    return None


def structural_errors(document, allow_empty_selector=False):
    """Check structural types that are unambiguous regardless of version.

    This is intentionally NOT a full CRD schema: the target cluster's
    `--dry-run=server` remains the authoritative schema validation. It only
    rejects clearly wrong shapes early so they cannot be normalized/applied.
    Errors are collected in one pass.
    """
    errors = []

    api_version = str(document.get("apiVersion") or "").strip()
    if api_version not in EXPECTED_API_VERSIONS:
        errors.append(
            "Invalid apiVersion %r; expected %s"
            % (api_version, " or ".join(EXPECTED_API_VERSIONS))
        )

    metadata = document.get("metadata")
    if not isinstance(metadata, dict):
        errors.append("metadata must be an object")
    else:
        if not isinstance(metadata.get("name"), str) or not metadata["name"].strip():
            errors.append("metadata.name must be a nonempty string")

        # Namespace rules differ by policy type (#1 / round4 #5):
        # VarmorPolicy must state a non-empty string namespace.
        # VarmorClusterPolicy is cluster scope: the namespace field must not
        # be present at all (not even "" or a non-string value).
        kind = document.get("kind")
        if kind == "VarmorPolicy":
            ns = metadata.get("namespace")
            if not (isinstance(ns, str) and ns.strip()):
                errors.append(
                    "VarmorPolicy requires an explicit nonempty metadata.namespace"
                )
        if kind == "VarmorClusterPolicy" and "namespace" in metadata:
            errors.append(
                "VarmorClusterPolicy is cluster-scoped; metadata must not contain a namespace field"
            )

    spec = document.get("spec")
    if not isinstance(spec, dict):
        # Cannot continue structural checks without a spec.
        return errors + ["spec must be an object"]

    target = spec.get("target")
    if not isinstance(target, dict):
        errors.append("spec.target must be an object")
    else:
        # name, when present, must be a non-empty string.
        name = target.get("name")
        if name is not None and not (isinstance(name, str) and name.strip()):
            errors.append("spec.target.name must be a nonempty string")

        selector = target.get("selector")
        if selector is not None:
            if not isinstance(selector, dict):
                errors.append("spec.target.selector must be a LabelSelector object, not a string")
            else:
                unknown = [k for k in selector if k not in ("matchLabels", "matchExpressions")]
                if unknown:
                    # Unknown fields are always rejected; they could be pruned
                    # by the API server and silently collapse to match-all.
                    errors.append(
                        "spec.target.selector contains unknown field %r; only matchLabels/matchExpressions are allowed"
                        % unknown[0]
                    )
                else:
                    ml = selector.get("matchLabels")
                    me = selector.get("matchExpressions")
                    ml_error = _match_labels_error(ml)
                    me_error = _match_expressions_error(me)
                    if ml_error:
                        errors.append(ml_error)
                    if me_error:
                        errors.append(me_error)
                    if not _has_valid_labels(ml) and not _has_valid_expressions(me):
                        # No effective constraint -> match-all.
                        if not allow_empty_selector:
                            errors.append(
                                "spec.target.selector has no effective constraints (match-all; high risk requires separate confirmation)"
                            )

        containers = target.get("containers")
        if containers is not None:
            if not isinstance(containers, list) or any(
                not (isinstance(item, str) and item.strip()) for item in containers
            ):
                errors.append("spec.target.containers must be an array of nonempty strings")
            elif len(containers) != len(set(containers)):
                errors.append("spec.target.containers must not contain duplicate container names")

    update_existing = spec.get("updateExistingWorkloads")
    if not isinstance(update_existing, bool):
        # Required, explicit field: do not rely on the default (false) or
        # accept truthy strings.
        errors.append(
            "spec.updateExistingWorkloads must be explicitly set to boolean true/false"
        )

    policy_spec = spec.get("policy")
    if not isinstance(policy_spec, dict):
        errors.append("spec.policy must be an object")
        return errors

    # enhanceProtect is required and must be an object; do not silently
    # manufacture an empty one during normalization.
    enhance = policy_spec.get("enhanceProtect")
    if not isinstance(enhance, dict):
        errors.append(
            "spec.policy.enhanceProtect must be an object with privileged explicitly set"
        )
    else:
        errors.extend(_enhance_structural_errors(enhance))

    return errors


def _enhance_structural_errors(enhance):
    errors = []

    # audit/allow are auto-normalized to true; only type-check when present.
    for field in ("auditViolations", "allowViolations"):
        value = enhance.get(field)
        if value is not None and not isinstance(value, bool):
            errors.append("%s must be a boolean, not string %r" % (field, value))

    # privileged must be explicit because it selects the AppArmor/BPF baseline.
    if not isinstance(enhance.get("privileged"), bool):
        errors.append(
            "enhanceProtect.privileged must be explicitly set to boolean true/false"
        )

    # Built-in string-list rule fields: when present must be lists of strings.
    # This catches hardeningRules: 1 / {} and vulMitigationRules: {}.
    if enhance.get("hardeningRules") is not None and not _is_string_list(
        enhance["hardeningRules"]
    ):
        errors.append("hardeningRules must be an array of strings")
    if enhance.get("vulMitigationRules") is not None and not _is_string_list(
        enhance["vulMitigationRules"]
    ):
        errors.append("vulMitigationRules must be an array of strings")

    # attackProtectionRules: elements must be objects with a string list rules.
    attack = enhance.get("attackProtectionRules")
    if attack is not None:
        if not isinstance(attack, list):
            errors.append("attackProtectionRules must be an array")
        else:
            for index, group in enumerate(attack):
                if not isinstance(group, dict):
                    errors.append(
                        "attackProtectionRules[%d] must be an object" % index
                    )
                    continue
                if not _is_string_list(group.get("rules")):
                    errors.append(
                        "attackProtectionRules[%d].rules must be an array of strings" % index
                    )
                if group.get("targets") is not None and not _is_string_list(
                    group["targets"]
                ):
                    errors.append(
                        "attackProtectionRules[%d].targets must be an array of strings" % index
                    )

    # appArmorRawRules: objects with a string rules field.
    apparmor = enhance.get("appArmorRawRules")
    if apparmor is not None:
        if not isinstance(apparmor, list):
            errors.append("appArmorRawRules must be an array")
        else:
            for index, group in enumerate(apparmor):
                if not isinstance(group, dict):
                    errors.append("appArmorRawRules[%d] must be an object" % index)
                    continue
                if not isinstance(group.get("rules"), str):
                    errors.append(
                        "appArmorRawRules[%d].rules must be a string" % index
                    )
                if group.get("targets") is not None and not _is_string_list(
                    group["targets"]
                ):
                    errors.append(
                        "appArmorRawRules[%d].targets must be an array of strings" % index
                    )

    # bpfRawRules must be an object (its deep shape is left to dry-run/model).
    bpf = enhance.get("bpfRawRules")
    if bpf is not None and not isinstance(bpf, dict):
        errors.append("bpfRawRules must be an object")

    # syscallRawRules: objects with string-list names and a valid OCI action.
    syscalls = enhance.get("syscallRawRules")
    if syscalls is not None:
        if not isinstance(syscalls, list):
            errors.append("syscallRawRules must be an array")
        else:
            for index, rule in enumerate(syscalls):
                if not isinstance(rule, dict):
                    errors.append("syscallRawRules[%d] must be an object" % index)
                    continue
                if not _is_string_list(rule.get("names")):
                    errors.append(
                        "syscallRawRules[%d].names must be an array of strings" % index
                    )
                action = str(rule.get("action") or "").strip()
                if action not in SECCOMP_ACTIONS:
                    errors.append(
                        "syscallRawRules[%d].action %r is not a valid OCI Seccomp action"
                        % (index, action)
                    )

    # networkProxyRawRules must be an object.
    network_proxy = enhance.get("networkProxyRawRules")
    if network_proxy is not None and not isinstance(network_proxy, dict):
        errors.append("networkProxyRawRules must be an object")

    return errors


def validate_basic(content):
    text = (content or "").strip()
    if not text:
        return ["Policy YAML must not be empty"]
    if len(text.encode("utf-8")) > MAX_POLICY_BYTES:
        return ["Policy YAML exceeds the %d KiB limit" % (MAX_POLICY_BYTES // 1024)]
    try:
        common.load_yaml_doc(text)
    except common.ValidationError as error:
        return [str(error)]
    return []


def _built_in_rule_error(rule, field, catalog, enforcers, targeted):
    supported = common.rule_enforcers(rule, catalog)
    if not supported:
        return "Invalid built-in rule ID %r" % rule
    if not common.rule_allowed_in_field(rule, field, catalog):
        return "Built-in rule %r does not belong to %s" % (rule, field)
    if targeted and common.ENFORCER_APPARMOR not in supported:
        return "Built-in rule %r does not support attackProtectionRules.targets" % rule
    if not any(name in enforcers for name in supported):
        return "Built-in rule %r is incompatible with the enforcer; supports %s" % (
            rule,
            "/".join(supported),
        )
    return None


def validate_built_in_rules(spec, catalog, enforcers):
    """Collect all built-in rule errors once; never fail one at a time."""
    enhance = common.get_path(spec, "policy", "enhanceProtect") or {}
    errors = []
    seen = set()

    def add(message):
        if message and message not in seen:
            seen.add(message)
            errors.append(message)

    for rule in enhance.get("hardeningRules") or []:
        add(_built_in_rule_error(rule, "hardeningRules", catalog, enforcers, False))
    for rule in enhance.get("vulMitigationRules") or []:
        add(_built_in_rule_error(rule, "vulMitigationRules", catalog, enforcers, False))

    for group in enhance.get("attackProtectionRules") or []:
        group = group if isinstance(group, dict) else {}
        targets = group.get("targets")
        targeted = bool(targets)
        if targeted and common.ENFORCER_APPARMOR not in enforcers:
            add("attackProtectionRules with targets requires the AppArmor enforcer")
        for rule in group.get("rules") or []:
            add(
                _built_in_rule_error(
                    rule, "attackProtectionRules", catalog, enforcers, targeted
                )
            )
    return errors


def expand_aggregate_capability_rules(enhance, catalog):
    """Expand aggregate capability rules into atomic disable-cap-[CAP] rules.

    Returns the adjustment message (or None) and mutates enhance.
    """
    if "hardeningRules" not in enhance or enhance.get("hardeningRules") is None:
        return None
    raw_rules = enhance["hardeningRules"]
    if not isinstance(raw_rules, list) or not all(isinstance(item, str) for item in raw_rules):
        raise common.ValidationError(
            "spec.policy.enhanceProtect.hardeningRules must be an array of strings"
        )

    expansions = catalog["aggregateCapabilityExpansions"]
    expanded = set()
    aggregate_found = []
    for raw in raw_rules:
        canonical = common.canonical_rule_id(raw, catalog)
        if canonical in expansions and canonical not in aggregate_found:
            aggregate_found.append(canonical)
        if canonical in expansions:
            expanded.update(expansions[canonical])
    if not aggregate_found:
        return None

    normalized = []
    seen_concrete = set()
    net_bind_disabled = False
    for raw in raw_rules:
        canonical = common.canonical_rule_id(raw, catalog)
        if canonical in expansions:
            for concrete in expansions[canonical]:
                if concrete not in seen_concrete:
                    normalized.append(concrete)
                    seen_concrete.add(concrete)
            continue
        if canonical in expanded:
            # A concrete rule already produced by an aggregate expansion.
            if canonical in seen_concrete:
                continue
            seen_concrete.add(canonical)
        normalized.append(raw)
        if canonical == "disable-cap-net-bind-service":
            net_bind_disabled = True
    enhance["hardeningRules"] = normalized

    count = len(seen_concrete)
    if len(aggregate_found) == 1:
        rule = aggregate_found[0]
        if rule == "disable-cap-all-except-net-bind-service":
            exemption = (
                "the policy already separately restricts NET_BIND_SERVICE; expansion preserved that restriction"
                if net_bind_disabled
                else "the existing NET_BIND_SERVICE exemption is preserved"
            )
            return (
                "Expanded aggregate capability rule %s into %d concrete disable-cap-[CAP] rules; %s. "
                "This enables fine-grained optimization by actual capability usage, using the capability set in the current official vArmor implementation."
                % (rule, count, exemption)
            )
        return (
            "Expanded aggregate capability rule %s into %d concrete disable-cap-[CAP] rules. "
            "This enables fine-grained optimization by actual capability usage, using the capability set in the current official vArmor implementation."
            % (rule, count)
        )
    return (
        "Expanded aggregate capability rules %s into %d deduplicated concrete disable-cap-[CAP] rules. "
        "This enables fine-grained optimization by actual capability usage, using the capability set in the current official vArmor implementation."
        % (" and ".join(aggregate_found), count)
    )


def _string_set(value):
    if not isinstance(value, list):
        return {}
    return {str(item).strip().lower() for item in value}


def _has_standalone_word(content, word):
    tokens = re.split(r"[^a-z]+", content.lower())
    return word in tokens


def collect_action_notices(value, notices):
    if isinstance(value, dict):
        for key, child in value.items():
            key_lower = key.lower()
            if key_lower == "qualifiers":
                qualifiers = _string_set(child)
                if "deny" in qualifiers:
                    notices["Custom rules contain deny: application operations will actually be blocked"] = True
                if "allow" in qualifiers and "audit" not in qualifiers:
                    notices["Custom rules allow without audit: violation logs needed for optimization may not be generated"] = True
            elif key_lower == "action":
                action = str(child).strip().upper()
                # Anything other than ALLOW/LOG can block: ERRNO, KILL*,
                # TRAP, TRACE, NOTIFY (TRACE/NOTIFY divert the syscall).
                if action not in ("SCMP_ACT_ALLOW", "SCMP_ACT_LOG"):
                    notices["Custom rules contain a blocking Seccomp action: application operations will actually be blocked"] = True
            elif key_lower == "defaultaction":
                if str(child).strip().lower() == "deny":
                    notices["NetworkProxy defaultAction=deny: unmatched traffic will be blocked"] = True
            elif key_lower == "rules" and isinstance(child, str):
                if _has_standalone_word(child, "deny"):
                    notices["Custom rules contain deny: application operations will actually be blocked"] = True
            collect_action_notices(child, notices)
    elif isinstance(value, list):
        for child in value:
            collect_action_notices(child, notices)


def runtime_notices(spec, document):
    notices = []
    enforcer = str(common.get_path(spec, "policy", "enforcer") or "").lower()
    reasons = []
    if common.get_path(spec, "target", "kind") == "Pod":
        reasons.append("The target is a Pod; vArmor will not roll it out")
    if "seccomp" in enforcer:
        reasons.append("The policy enables Seccomp")
    if not spec.get("updateExistingWorkloads"):
        reasons.append("updateExistingWorkloads is disabled; existing workloads will not be rolled out")
    if reasons:
        if common.get_path(spec, "target", "kind") == "Pod":
            action = "After successful creation, delete and recreate the target Pod to activate the policy."
        else:
            action = "After successful creation, roll out the target workload to activate the policy."
        notices.append("; ".join(reasons) + ". " + action)

    # The policy flag and actual container privileges are distinct. Verify
    # Seccomp generation/injection rather than inferring it from this flag.
    enhance = common.get_path(spec, "policy", "enhanceProtect")
    if isinstance(enhance, dict) and enhance.get("privileged") and "seccomp" in enforcer:
        notices.append(
            "Policy privileged=true changes the AppArmor/BPF baseline, not container privileges; verify generated Seccomp content and actual Pod settings. Seccomp injection is skipped for actually privileged or explicitly Seccomp-Unconfined containers"
        )

    found = {}
    collect_action_notices(document, found)
    for message in [
        "Custom rules contain deny: application operations will actually be blocked",
        "Custom rules contain a blocking Seccomp action: application operations will actually be blocked",
        "NetworkProxy defaultAction=deny: unmatched traffic will be blocked",
        "Custom rules allow without audit: violation logs needed for optimization may not be generated",
    ]:
        if found.get(message):
            notices.append(message)
    return notices


def find_aggregate_capability_rules(enhance, catalog):
    rules = enhance.get("hardeningRules") if isinstance(enhance, dict) else None
    if not isinstance(rules, list):
        return []
    expansions = catalog["aggregateCapabilityExpansions"]
    found = []
    for rule in rules:
        canonical = common.canonical_rule_id(rule, catalog)
        if canonical in expansions and canonical not in found:
            found.append(canonical)
    return found


def normalize(
    content,
    catalog=None,
    allow_empty_selector=False,
    require_atomic_capabilities=False,
    require_observation=False,
):
    """Validate then normalize. Returns a result dict.

    {valid, errors, normalized, adjustments, notices}
    """
    catalog = catalog or common.load_catalog()
    basic_errors = validate_basic(content)
    if basic_errors:
        return {
            "valid": False,
            "errors": basic_errors,
            "normalized": None,
            "adjustments": [],
            "notices": [],
        }

    document = common.load_yaml_doc(content)
    kind = document.get("kind")
    if kind not in ("VarmorPolicy", "VarmorClusterPolicy"):
        return _invalid("The policy must be a complete VarmorPolicy or VarmorClusterPolicy")

    # Structural type validation (collected in one pass).
    structure_errors = structural_errors(document, allow_empty_selector)
    if structure_errors:
        return {
            "valid": False,
            "errors": structure_errors,
            "normalized": None,
            "adjustments": [],
            "notices": [],
        }

    spec = document["spec"]
    target = spec["target"]
    if target.get("kind") not in TARGET_KINDS:
        return _invalid(
            "spec.target.kind supports only Deployment, StatefulSet, DaemonSet, or Pod"
        )
    has_name = not common.is_blank(target.get("name"))
    has_selector = target.get("selector") is not None
    if has_name == has_selector:
        return _invalid("Exactly one of spec.target.name and spec.target.selector must be set")

    policy_spec = spec["policy"]
    if common.is_blank(policy_spec.get("enforcer")):
        return _invalid("spec.policy.enforcer must not be empty")
    enforcers, ok = common.parse_enforcers(policy_spec.get("enforcer"), catalog)
    if not ok:
        return _invalid("Invalid spec.policy.enforcer %r" % policy_spec.get("enforcer"))
    if policy_spec.get("mode") != "EnhanceProtect":
        return _invalid("Policy optimization supports only EnhanceProtect mode")

    rule_errors = validate_built_in_rules(spec, catalog, enforcers)
    if rule_errors:
        return {
            "valid": False,
            "errors": rule_errors,
            "normalized": None, "adjustments": [], "notices": [],
        }

    aggregate_rules = find_aggregate_capability_rules(
        policy_spec["enhanceProtect"], catalog
    )
    if require_atomic_capabilities and aggregate_rules:
        return _invalid(
            "Phase two requires atomized capability rules; found aggregate rules %s. "
            "First generate and submit normalized YAML using validate_policy.py in phase one, "
            "then collect logs from a new observation start"
            % ", ".join(aggregate_rules)
        )

    if require_observation:
        enhance_current = policy_spec["enhanceProtect"]
        observation_errors = []
        if enhance_current.get("auditViolations") is not True:
            observation_errors.append(
                "Phase two requires auditViolations explicitly set to true"
            )
        if enhance_current.get("allowViolations") is not True:
            observation_errors.append(
                "Phase two requires allowViolations explicitly set to true"
            )
        if observation_errors:
            return {
                "valid": False,
                "errors": observation_errors,
                "normalized": None,
                "adjustments": [],
                "notices": [],
            }

    # Normalize on a mutable copy, keeping the original for notices.
    root = copy.deepcopy(document)
    spec_map = root["spec"]
    policy_map = spec_map["policy"]
    enhance = policy_map.get("enhanceProtect")
    if not isinstance(enhance, dict):
        enhance = {}
        policy_map["enhanceProtect"] = enhance

    adjustments = []
    expansion = expand_aggregate_capability_rules(enhance, catalog)
    if expansion:
        adjustments.append(expansion)
    notices = runtime_notices(spec, document)

    # Match-all opt-in must leave an explicit high-risk notice so the artifact
    # cannot be mistaken for a narrowly scoped policy.
    target = spec.get("target")
    if (
        allow_empty_selector
        and isinstance(target, dict)
        and target.get("selector") is not None
        and not _has_valid_labels(target["selector"].get("matchLabels"))
        and not _has_valid_expressions(target["selector"].get("matchExpressions"))
    ):
        notices.insert(
            0,
            "High risk: selector matches all (explicitly confirmed), affecting every matched object; review the match list before submission",
        )

    if not enhance.get("auditViolations"):
        enhance["auditViolations"] = True
        adjustments.append("Set auditViolations: true to collect violation logs")
    if not enhance.get("allowViolations"):
        enhance["allowViolations"] = True
        adjustments.append(
            "Set allowViolations: true so built-in rules allow violations during observation"
        )

    normalized = common.dump_yaml(root)
    return {
        "valid": True,
        "errors": [],
        "normalized": normalized,
        "adjustments": adjustments,
        "notices": notices,
    }


def _invalid(message):
    return {
        "valid": False,
        "errors": [message],
        "normalized": None,
        "adjustments": [],
        "notices": [],
    }


def _run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--file", help="policy YAML file (default: stdin)")
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="output format"
    )
    parser.add_argument(
        "--allow-empty-selector",
        action="store_true",
        help="opt in to an empty selector (match-all); high-risk, confirm first",
    )
    parser.add_argument(
        "--require-atomic-capabilities",
        action="store_true",
        help="reject aggregate capability rules instead of expanding them",
    )
    parser.add_argument(
        "--require-observation",
        action="store_true",
        help="reject policies not explicitly using both observation switches",
    )
    parser.add_argument(
        "--quiet-notices",
        action="store_true",
        help="suppress advisory notices after validation",
    )
    args = parser.parse_args()

    content = common.read_input(args.file)
    result = normalize(
        content,
        allow_empty_selector=args.allow_empty_selector,
        require_atomic_capabilities=args.require_atomic_capabilities,
        require_observation=args.require_observation,
    )

    if args.format == "json":
        print(json.dumps(result, ensure_ascii=False, indent=2))
        sys.exit(0 if result["valid"] else 1)

    if not result["valid"]:
        print("Policy validation failed:", file=sys.stderr)
        for error in result["errors"]:
            print("- %s" % error, file=sys.stderr)
        sys.exit(1)
    # Informational messages go to stderr so a stdout redirect always yields a
    # pure YAML document. They remain visible when run interactively.
    if result["adjustments"]:
        print("Automatic normalization:", file=sys.stderr)
        for item in result["adjustments"]:
            print("- %s" % item, file=sys.stderr)
    if result["notices"] and not args.quiet_notices:
        print("Risk notices:", file=sys.stderr)
        for item in result["notices"]:
            print("- %s" % item, file=sys.stderr)
    print(result["normalized"])


def _fail(error):
    as_json = "--format" in sys.argv and "json" in sys.argv
    if as_json:
        payload = json.dumps(
            {
                "valid": False,
                "errors": [str(error)],
                "normalized": None,
                "adjustments": [],
                "notices": [],
            },
            ensure_ascii=False,
        )
        print(payload, file=sys.stdout)
    else:
        print("ERROR: %s" % error, file=sys.stderr)
    sys.exit(2)


def main():
    # Deterministic CLI: never leak a traceback. Catch validation errors and
    # any unexpected exception alike, and report a structured failure.
    try:
        _run()
    except Exception as error:  # noqa: BLE001 - top-level safety net
        _fail(error)


if __name__ == "__main__":
    main()
