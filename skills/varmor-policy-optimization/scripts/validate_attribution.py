#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Attribution boundary validator.
# It verifies that every referenced event and rule coordinate exists and that
# their enforcers are compatible. It cannot prove that the event semantically
# matches the rule; that remains model judgment and must be shown to the user.
#
# Inputs:
#   --pre <pre.json>            output of preprocess_aggregate.py
#   --catalog <catalog.json>    output of preprocess_aggregate.py catalog
#   --attribution <file>        [{eventId, summary, matches[]}], with decisions
#                              added after user review
# Output (stdout): checked event/rule coordinates consumed internally by the
# mutation scripts. The marker identifies the document shape; it is not
# cryptographic provenance or proof of user authorization.
#
# Each match must:
#   - reference an eventId present in pre.aggregatedEvents
#   - copy a rule (source + rule + context.targets) that exists in catalog
#   - the event enforcer must be among that catalog entry enforcers

import argparse
import json
import sys

import vopt_common as common

AUTH_MARKER = "vopt-authorized-removals"
DECISIONS = ("remove", "keep", "observe")


def _uses_network_proxy_evidence(source, event_enforcer):
    return (
        str(source or "").startswith("networkProxyRawRules")
        or event_enforcer == common.ENFORCER_NETWORKPROXY
    )


def _match_key(match):
    if not isinstance(match, dict):
        raise common.ValidationError("rule coordinate must be an object")
    source = match.get("source")
    if not isinstance(source, str) or not source.strip() or "rule" not in match:
        raise common.ValidationError("rule coordinate requires source and rule")
    context = match.get("context", {})
    if not isinstance(context, dict):
        raise common.ValidationError("rule coordinate context must be an object")
    if set(context) - {"targets"}:
        raise common.ValidationError("rule coordinate context only supports targets")
    targets = context.get("targets", [])
    if (
        not isinstance(targets, list)
        or any(not isinstance(target, str) or not target for target in targets)
    ):
        raise common.ValidationError("rule coordinate context.targets must be strings")
    return common.stable_json(
        {
            "source": source,
            "rule": match.get("rule"),
            "targets": sorted(targets),
        }
    )


def _catalog_index(catalog_entries):
    if not isinstance(catalog_entries, list):
        raise common.ValidationError("catalog ruleCatalog must be a list")
    index = {}
    for position, entry in enumerate(catalog_entries):
        if not isinstance(entry, dict):
            raise common.ValidationError(
                "catalog rule #%d must be an object" % position
            )
        key = _match_key(entry)
        enforcers = entry.get("enforcers")
        if (
            not isinstance(enforcers, list)
            or not enforcers
            or any(not isinstance(value, str) or not value for value in enforcers)
        ):
            raise common.ValidationError(
                "catalog rule #%d enforcers must be non-empty strings" % position
            )
        if key in index:
            raise common.ValidationError("catalog contains duplicate rule coordinates")
        index[key] = entry
    return index


def validate(pre, catalog, attribution, require_decisions=False):
    if not isinstance(pre, dict):
        raise common.ValidationError("pre must be a JSON object")
    if not isinstance(catalog, dict):
        raise common.ValidationError("catalog must be a JSON object")
    events = pre.get("aggregatedEvents")
    if not isinstance(events, list):
        raise common.ValidationError("pre.aggregatedEvents must be a list")
    event_by_id = {}
    for position, event in enumerate(events):
        if not isinstance(event, dict):
            raise common.ValidationError(
                "aggregated event #%d must be an object" % position
            )
        event_id = event.get("eventId")
        if not isinstance(event_id, str) or not event_id:
            raise common.ValidationError(
                "aggregated event #%d requires eventId" % position
            )
        if event_id in event_by_id:
            raise common.ValidationError("aggregated eventId %r is duplicated" % event_id)
        if not isinstance(event.get("enforcer"), str) or not event["enforcer"]:
            raise common.ValidationError(
                "aggregated event %r requires enforcer" % event_id
            )
        event_by_id[event_id] = event

    # Attribution is only meaningful when the collection was complete.
    if pre.get("collectionComplete") is not True:
        raise common.ValidationError(
            "collection is incomplete; attribution cannot authorize removals"
        )
    if pre.get("retentionCovered") is not True:
        raise common.ValidationError(
            "log retention coverage is not proven; attribution cannot authorize removals"
        )
    if pre.get("failures"):
        raise common.ValidationError("preprocessing contains invalid events")

    catalog_index = _catalog_index(catalog.get("ruleCatalog"))

    if not isinstance(attribution, list):
        raise common.ValidationError("attribution must be a JSON list")

    authorized = []
    seen_event_ids = set()
    for index, item in enumerate(attribution):
        if not isinstance(item, dict):
            raise common.ValidationError(
                "attribution item #%d must be an object" % index
            )
        event_id = item.get("eventId")
        if not isinstance(event_id, str) or not event_id:
            raise common.ValidationError(
                "attribution item #%d requires eventId" % index
            )
        if event_id in seen_event_ids:
            raise common.ValidationError(
                "attribution eventId %r is duplicated" % event_id
            )
        seen_event_ids.add(event_id)
        event = event_by_id.get(event_id)
        if event is None:
            raise common.ValidationError(
                "attribution eventId %r not found in aggregated events"
                % event_id
            )
        event_enforcer = event.get("enforcer")

        matches = item.get("matches")
        if not isinstance(matches, list):
            raise common.ValidationError(
                "attribution item #%d matches must be a list" % index
            )
        for match_index, match in enumerate(matches):
            if not isinstance(match, dict):
                raise common.ValidationError(
                    "attribution item #%d match #%d must be an object"
                    % (index, match_index)
                )
            key = _match_key(match)
            entry = catalog_index.get(key)
            if entry is None:
                raise common.ValidationError(
                    "match for event %r is not present in the rule catalog: %s"
                    % (event_id, key)
                )
            if event_enforcer not in (entry.get("enforcers") or []):
                raise common.ValidationError(
                    "event %r enforcer %r is incompatible with catalog entry %s"
                    % (event_id, event_enforcer, entry.get("enforcers"))
                )
            if (
                _uses_network_proxy_evidence(entry.get("source"), event_enforcer)
                and pre.get("networkProxyEvidenceEligible") is not True
            ):
                raise common.ValidationError(
                    "NetworkProxy evidence is ineligible; event %r cannot "
                    "authorize removal from %s"
                    % (event_id, entry.get("source"))
                )
            decision = match.get("decision")
            if decision is not None and decision not in DECISIONS:
                raise common.ValidationError(
                    "event %r match #%d decision must be one of %s"
                    % (event_id, match_index, ", ".join(DECISIONS))
                )
            if require_decisions and decision is None:
                raise common.ValidationError(
                    "event %r match #%d requires an explicit decision"
                    % (event_id, match_index)
                )
            authorized.append(
                {
                    "source": entry["source"],
                    "rule": entry["rule"],
                    "context": entry.get("context") or {},
                    "eventId": event_id,
                    "decision": decision,
                }
            )

    missing = sorted(set(event_by_id) - seen_event_ids)
    if missing:
        raise common.ValidationError(
            "attribution must cover every aggregated event; missing: %s"
            % ", ".join(missing)
        )

    result = {
        "marker": AUTH_MARKER,
        "window": pre.get("window"),
        "authorized": authorized,
    }
    if require_decisions:
        selected_removals(result)
    return result


def selected_removals(authorized):
    if not isinstance(authorized, dict) or authorized.get("marker") != AUTH_MARKER:
        raise common.ValidationError("validated attribution is required")
    decisions = {}
    coordinates = {}
    for index, item in enumerate(authorized.get("authorized") or []):
        decision = item.get("decision")
        if decision not in DECISIONS:
            raise common.ValidationError(
                "authorized match #%d requires an explicit decision: %s"
                % (index, ", ".join(DECISIONS))
            )
        key = _match_key(item)
        previous = decisions.get(key)
        if previous is not None and previous != decision:
            raise common.ValidationError(
                "the same rule coordinate has conflicting decisions %r and %r"
                % (previous, decision)
            )
        decisions[key] = decision
        coordinates[key] = {
            "source": item["source"],
            "rule": item["rule"],
            "context": item.get("context") or {},
        }
    return [
        coordinates[key]
        for key in coordinates
        if decisions[key] == "remove"
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pre", required=True)
    parser.add_argument("--catalog", required=True)
    parser.add_argument("--attribution", required=True)
    parser.add_argument(
        "--require-decisions",
        action="store_true",
        help="require remove/keep/observe on every match",
    )
    args = parser.parse_args()

    with open(args.pre, "r", encoding="utf-8") as handle:
        pre = json.load(handle)
    with open(args.catalog, "r", encoding="utf-8") as handle:
        catalog = json.load(handle)
    with open(args.attribution, "r", encoding="utf-8") as handle:
        attribution = json.load(handle)

    result = validate(
        pre,
        catalog,
        attribution,
        require_decisions=args.require_decisions,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, common.ValidationError) as error:
        print("ATTRIBUTION VALIDATION FAILED: %s" % error, file=sys.stderr)
        sys.exit(2)
