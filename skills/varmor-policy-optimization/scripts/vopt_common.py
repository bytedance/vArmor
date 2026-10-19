#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Shared deterministic helpers for the vArmor policy optimization skill.
# Everything here is side-effect free apart from loading the bundled catalog.
# It MUST NOT make semantic judgments about business behavior.

import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on misconfigured hosts
    print(
        "missing dependency PyYAML, install it once with: pip3 install --user pyyaml",
        file=sys.stderr,
    )
    raise

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
CATALOG_PATH = os.path.join(DATA_DIR, "builtin-rules-catalog.json")

ENFORCER_APPARMOR = "AppArmor"
ENFORCER_BPF = "BPF"
ENFORCER_SECCOMP = "Seccomp"
ENFORCER_NETWORKPROXY = "NetworkProxy"


class ValidationError(Exception):
    """A deterministic policy/input validation failure."""


def load_catalog():
    with open(CATALOG_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def normalize_rule_id(rule):
    return str(rule).strip().lower().replace("_", "-")


def canonical_rule_id(rule, catalog=None):
    catalog = catalog or load_catalog()
    normalized = normalize_rule_id(rule)
    return catalog.get("aliases", {}).get(normalized, normalized)


def parse_enforcers(raw, catalog=None):
    """Parse a combined enforcer string into a set of enforcer names.

    Mirrors the Go tokenizer: tokens are matched from the current position,
    duplicates and partial matches are rejected.
    """
    catalog = catalog or load_catalog()
    remaining = (raw or "").strip().lower()
    if not remaining:
        return None, False
    result = set()
    while remaining:
        matched = False
        for entry in catalog["enforcerTokens"]:
            token, name = entry["token"], entry["name"]
            if not remaining.startswith(token):
                continue
            if name in result:
                return None, False
            result.add(name)
            remaining = remaining[len(token):]
            matched = True
            break
        if not matched:
            return None, False
    return result, True


def rule_enforcers(rule, catalog=None):
    """Return the enforcers that implement a built-in rule.

    Resolution order mirrors builtInRuleEnforcers in built_in_rules.go so the
    effective enforcer (e.g. Seccomp for disallow-create-user-ns) wins.
    """
    catalog = catalog or load_catalog()
    canonical = canonical_rule_id(rule, catalog)

    def members(key):
        return set(catalog[key])

    if canonical in members("capabilityRules"):
        return [ENFORCER_APPARMOR, ENFORCER_BPF]
    if canonical in members("seccompOnly"):
        return [ENFORCER_SECCOMP]
    if canonical in members("bpfOnly"):
        return [ENFORCER_BPF]
    if canonical in members("appArmorOnly"):
        return [ENFORCER_APPARMOR]
    if canonical in members("appArmorAndBPF"):
        return [ENFORCER_APPARMOR, ENFORCER_BPF]
    return None


def rule_allowed_in_field(rule, field, catalog=None):
    """Whether a built-in rule ID is valid for a given source field."""
    catalog = catalog or load_catalog()
    canonical = canonical_rule_id(rule, catalog)
    if field == "hardeningRules":
        return canonical in set(catalog["hardeningRules"]) or canonical in set(
            catalog["capabilityRules"]
        )
    if field == "vulMitigationRules":
        return canonical in set(catalog["vulMitigationRules"])
    if field == "attackProtectionRules":
        return canonical in set(catalog["attackProtectionRules"])
    return False


def stable_json(value):
    """Canonical JSON for structural identity.

    Object key order is ignored and arrays are sorted recursively, matching the
    Go canonical() used to match BPF/RawRule objects regardless of the
    non-deterministic ordering produced by Go map iteration.
    """
    return json.dumps(_canonicalize(value), sort_keys=True, separators=(",", ":"))


def _canonicalize(value):
    if isinstance(value, dict):
        return {key: _canonicalize(value[key]) for key in value}
    if isinstance(value, (list, tuple)):
        normalized = [_canonicalize(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, sort_keys=True))
    return value


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of silently
    keeping the last occurrence (which would drop earlier rules)."""


def _construct_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "found duplicate key %r" % (key,),
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)


def load_yaml_doc(content):
    """Parse a single YAML/JSON document; None/non-dict inputs are invalid.

    Duplicate mapping keys are rejected so rules cannot be silently dropped.
    """
    try:
        document = yaml.load(content, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise ValidationError("内容不是有效的 YAML: %s" % error)
    except (TypeError, KeyError, ValueError) as error:
        # e.g. unhashable composite mapping keys during construction
        raise ValidationError("内容不是有效的 YAML: %s" % error)
    if not isinstance(document, dict):
        raise ValidationError("内容必须是一个 YAML/JSON 对象")
    return document


def sha256_text(content):
    import hashlib

    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def dump_yaml(document):
    return yaml.safe_dump(document, allow_unicode=True, sort_keys=False, width=100000).strip()


def read_input(path=None):
    """Read YAML/JSON from a file or stdin. File errors become ValidationError
    so the CLI reports them instead of a traceback."""
    if path:
        try:
            with open(path, "r", encoding="utf-8") as handle:
                return handle.read()
        except OSError as error:
            raise ValidationError("cannot read file %r: %s" % (path, error))
    return sys.stdin.read()


def get_path(obj, *keys):
    """Traverse nested dicts, returning None when any level is missing."""
    current = obj
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def is_blank(value):
    return value is None or (isinstance(value, str) and value.strip() == "")
