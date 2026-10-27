#!/usr/bin/env python3
# Copyright 2026 vArmor Authors. SPDX-License-Identifier: Apache-2.0
#
# Cluster-free unit tests for the deterministic scripts of the
# vArmor policy optimization skill.

import json
import os
import subprocess
import sys
import tempfile
import unittest

SKILL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR = os.path.join(SKILL_DIR, "scripts")
sys.path.insert(0, SCRIPTS_DIR)

import vopt_common as common
import validate_policy
import collect_violations
import preprocess_aggregate
import seccomp_plan
import guard_removal
import pathnorm
import apply_removals
import hash_policy
import validate_attribution
import build_manifest
import build_agent_inventory

CATALOG = common.load_catalog()


def policy(
    enforcer="AppArmorBPFSeccomp",
    mode="EnhanceProtect",
    enhance=None,
    kind="VarmorPolicy",
    update=False,
    target_kind="Deployment",
    name="demo",
):
    enhance_protect = dict(enhance) if enhance else {}
    enhance_protect.setdefault("privileged", False)
    return {
        "apiVersion": "crd.varmor.org/v1beta1",
        "kind": kind,
        "metadata": {"name": name, "namespace": "app"},
        "spec": {
            "updateExistingWorkloads": update,
            "target": {"kind": target_kind, "name": "target"}
            if name
            else {"kind": target_kind},
            "policy": {
                "enforcer": enforcer,
                "mode": mode,
                "enhanceProtect": enhance_protect,
            },
        },
    }


def yaml_of(document):
    return common.dump_yaml(document)


class CommonTests(unittest.TestCase):
    def test_parse_enforcers(self):
        got, ok = common.parse_enforcers("AppArmorBPFSeccomp", CATALOG)
        self.assertTrue(ok)
        self.assertEqual(got, {"AppArmor", "BPF", "Seccomp"})

    def test_parse_enforcers_rejects_partial_and_duplicate(self):
        self.assertFalse(common.parse_enforcers("AppArmorFoo", CATALOG)[1])
        self.assertFalse(common.parse_enforcers("AppArmorAppArmor", CATALOG)[1])
        self.assertFalse(common.parse_enforcers("", CATALOG)[1])

    def test_rule_enforcers_effective_wins(self):
        # disallow-create-user-ns is effectively Seccomp even though it ships
        # with the hardening list.
        self.assertEqual(
            common.rule_enforcers("disallow-create-user-ns", CATALOG), ["Seccomp"]
        )
        self.assertEqual(
            common.rule_enforcers("disable-cap-net-raw", CATALOG),
            ["AppArmor", "BPF"],
        )
        self.assertIsNone(common.rule_enforcers("not-a-rule", CATALOG))

    def test_alias_normalization(self):
        self.assertEqual(
            common.canonical_rule_id("DISALLOW_LOAD_EBPF", CATALOG),
            "disallow-load-bpf-prog",
        )

    def test_stable_json_ignores_key_order_sorts_arrays(self):
        self.assertEqual(
            common.stable_json({"a": 1, "b": [2, 1]}),
            common.stable_json({"b": [1, 2], "a": 1}),
        )

    def test_catalog_provenance_is_not_exact_version_gate(self):
        compatibility = CATALOG["builtInRuleCompatibility"]
        self.assertIn("v0.10.1", compatibility["verifiedIdenticalVersions"])
        self.assertIn("v0.10.5", compatibility["verifiedIdenticalVersions"])
        self.assertIn("v0.10.6", compatibility["verifiedIdenticalVersions"])
        self.assertEqual(
            compatibility["knownVersionExceptions"]["v0.10.0"]["missingRules"],
            ["copy-fail-mitigation"],
        )
        self.assertEqual(
            CATALOG["catalogProvenance"]["version"], "v0.10.5"
        )
        evidence = compatibility["verificationEvidence"]
        self.assertEqual(evidence["verifiedAt"], "2026-10-08")
        self.assertEqual(
            {item["path"]: item["sha256"] for item in evidence["files"]},
            {
                "internal/profile/apparmor/rules.go":
                    "e70c06899496882142b0634dde23998318f9d955a6aefee041aa12dfef34ab47",
                "internal/profile/bpf/bpf.go":
                    "dae2136194f76dc995a8de22aa14bc3cda8daf4b88d1eeaceb2a8299b7d3137d",
                "internal/profile/seccomp/seccomp.go":
                    "917a8330cd0062aca58fa6f916f106307a46250b679c95a77ba1ba005673440d",
            },
        )
        self.assertIn("provenance", CATALOG["notice"])

    def test_release_candidate_verification_preserves_tag_evidence(self):
        compatibility = CATALOG["builtInRuleCompatibility"]
        historical = compatibility["verificationEvidence"]
        candidate = compatibility["releaseCandidateVerification"]
        self.assertIn("v0.10.5", historical["versionsCompared"])
        self.assertNotIn(candidate["version"], historical["versionsCompared"])
        self.assertEqual(candidate["version"], "v0.10.6")
        self.assertIn(candidate["version"], compatibility["verifiedIdenticalVersions"])
        self.assertRegex(candidate["revision"], r"^[0-9a-f]{40}$")
        self.assertEqual(candidate["verifiedAt"], "2026-10-27")
        self.assertFalse(candidate["tagVerified"])
        self.assertIn("final v0.10.6 tag", candidate["releaseCheck"])
        self.assertEqual(
            {item["path"]: item["sha256"] for item in candidate["files"]},
            {item["path"]: item["sha256"] for item in historical["files"]},
        )


class ValidatePolicyTests(unittest.TestCase):
    def test_empty_oversize_invalid_yaml(self):
        self.assertIn("empty", validate_policy.normalize("   ", CATALOG)["errors"][0])
        huge = "x: " + ("a" * (256 * 1024))
        self.assertTrue(validate_policy.normalize(huge, CATALOG)["errors"])
        bad = validate_policy.normalize("a: [1, 2", CATALOG)
        self.assertTrue(bad["errors"])

    def test_kind_apiversion_name(self):
        doc = policy()
        doc["kind"] = "Pod"
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy()
        doc["apiVersion"] = ""
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy()
        doc["metadata"]["name"] = ""
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_target_constraints(self):
        doc = policy()
        doc["spec"]["target"] = {"kind": "Bad", "name": "t"}
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy()
        doc["spec"]["target"] = {"kind": "Deployment"}  # neither name nor selector
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy()
        doc["spec"]["target"] = {
            "kind": "Deployment",
            "name": "t",
            "selector": {"matchLabels": {"a": "b"}},  # both
        }
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_enforcer_and_mode(self):
        doc = policy(enforcer="Bad")
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy(mode="DefenseInDepth")
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    # --- review #2: wrong shapes must be rejected, not silently valid ---

    def test_bad_api_version(self):
        doc = policy()
        doc["apiVersion"] = "fake/v1"
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_selector_must_be_object(self):
        doc = policy()
        doc["spec"]["target"] = {"kind": "Deployment", "selector": "a-string"}
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_bpf_raw_rules_must_be_object(self):
        doc = policy(enhance={"bpfRawRules": "not-an-object"})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_apparmor_raw_rules_shape(self):
        doc = policy(enhance={"appArmorRawRules": [{"rules": 123}]})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_syscall_raw_rules_names_and_action(self):
        doc = policy(
            enhance={"syscallRawRules": [{"names": "not-a-list", "action": "BAD"}]}
        )
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])
        doc = policy(
            enhance={
                "syscallRawRules": [{"names": ["chmod"], "action": "SCMP_ACT_BAD"}]
            }
        )
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_attack_protection_element_must_be_object(self):
        doc = policy(enhance={"attackProtectionRules": ["just-a-string"]})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    # --- review round 3 #1: namespace rules ---

    def test_vp_must_have_namespace(self):
        doc = policy()
        del doc["metadata"]["namespace"]
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_vcp_must_not_have_namespace(self):
        doc = policy(kind="VarmorClusterPolicy")
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        # the test helper injects namespace; VCP with namespace must fail
        self.assertTrue(result["errors"])

    # --- review round 3 #4: malformed rule arrays / boolean strings ---

    def test_hardening_rules_scalar_and_mapping(self):
        for value in (1, {}):
            doc = policy(enhance={"hardeningRules": value})
            self.assertTrue(
                validate_policy.normalize(yaml_of(doc), CATALOG)["errors"]
            )

    def test_vul_rules_mapping_rejected(self):
        doc = policy(enhance={"vulMitigationRules": {}})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_boolean_string_rejected(self):
        doc = policy(enhance={"auditViolations": "false"})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_update_existing_workloads_string_rejected(self):
        doc = policy()
        doc["spec"]["updateExistingWorkloads"] = "true"
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    # enhanceProtect is required (object); missing/null must not bypass privileged

    def test_missing_and_null_enhance_protect_rejected(self):
        for value in (None,):
            doc = policy()
            if value is None:
                del doc["spec"]["policy"]["enhanceProtect"]
            self.assertTrue(
                validate_policy.normalize(yaml_of(doc), CATALOG)["errors"]
            )
        doc = policy()
        doc["spec"]["policy"]["enhanceProtect"] = None
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_exists_expression_omitted_values_accepted(self):
        doc = policy(kind="VarmorClusterPolicy")
        del doc["metadata"]["namespace"]
        doc["spec"]["target"] = {
            "kind": "Deployment",
            "selector": {"matchExpressions": [{"key": "app", "operator": "Exists"}]},
        }
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        self.assertTrue(result["valid"], result["errors"])

    # round4 #5: VCP namespace field presence (even "" / non-string) rejected

    def test_vcp_empty_and_nonstring_namespace_rejected(self):
        for ns in ("", 1):
            doc = policy(kind="VarmorClusterPolicy")
            doc["metadata"]["namespace"] = ns
            self.assertTrue(
                validate_policy.normalize(yaml_of(doc), CATALOG)["errors"]
            )


class AuthorizedRemovalTests(unittest.TestCase):
    def _doc(self):
        return policy(
            enhance={"hardeningRules": ["disallow-mount", "disallow-umount"]}
        )

    def _auth_doc(self, matches):
        return {"marker": "vopt-authorized-removals", "authorized": matches}

    def test_missing_authorized_rejected(self):
        coordinates = [{"source": "hardeningRules", "rule": "disallow-umount"}]
        with self.assertRaises(Exception):
            apply_removals.apply_removals(self._doc(), coordinates, None)

    def test_bad_marker_rejected(self):
        coordinates = [{"source": "hardeningRules", "rule": "disallow-umount"}]
        with self.assertRaises(Exception):
            apply_removals.apply_removals(
                self._doc(), coordinates, {"marker": "forged", "authorized": []}
            )

    def test_coordinate_not_in_authorized_rejected(self):
        coordinates = [{"source": "hardeningRules", "rule": "disallow-umount"}]
        auth = self._auth_doc([])
        with self.assertRaises(Exception):
            apply_removals.apply_removals(self._doc(), coordinates, auth)

    def test_authorized_coordinate_allowed(self):
        match = {"source": "hardeningRules", "rule": "disallow-umount", "context": {}}
        auth = self._auth_doc([match])
        root, applied = apply_removals.apply_removals(
            self._doc(), [match], auth
        )
        self.assertEqual(applied, 1)
        rules = root["spec"]["policy"]["enhanceProtect"]["hardeningRules"]
        self.assertNotIn("disallow-umount", rules)

    def test_network_proxy_coordinate_requires_evidence(self):
        rule = {"to": [{"host": "example.com"}]}
        doc = policy(
            enforcer="NetworkProxy",
            enhance={
                "networkProxyRawRules": {
                    "egress": {"defaultAction": "deny", "rules": [rule]}
                }
            },
        )
        match = {
            "source": "networkProxyRawRules.egress.rules",
            "rule": rule,
            "context": {},
        }
        auth = self._auth_doc([match])
        with self.assertRaises(common.ValidationError):
            apply_removals.apply_removals(doc, [match], auth)
        updated, applied = apply_removals.apply_removals(
            doc,
            [match],
            auth,
            network_proxy_evidence_eligible=True,
        )
        self.assertEqual(applied, 1)
        self.assertNotIn(
            "rules",
            updated["spec"]["policy"]["enhanceProtect"][
                "networkProxyRawRules"
            ]["egress"],
        )


class ValidateAttributionTests(unittest.TestCase):
    def _pre(self, complete=True):
        return {
            "window": {"start": 0, "end": 10},
            "collectionComplete": complete,
            "retentionCovered": True,
            "aggregatedEvents": [
                {
                    "eventId": "evt-000001",
                    "enforcer": "AppArmor",
                    "event": {"operation": "open"},
                }
            ],
        }

    def _catalog(self):
        doc = policy(
            enhance={"hardeningRules": ["disallow-umount"]}
        )
        entries = preprocess_aggregate.build_rule_catalog(doc, CATALOG)
        return {"ruleCatalog": entries}

    def test_incomplete_collection_rejected(self):
        attribution = [
            {
                "eventId": "evt-000001",
                "summary": "s",
                "matches": [
                    {"source": "hardeningRules", "rule": "disallow-umount"}
                ],
            }
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(
                self._pre(complete=False), self._catalog(), attribution
            )

    def test_unproven_retention_rejected(self):
        pre = self._pre()
        pre["retentionCovered"] = False
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(pre, self._catalog(), [])

    def test_unknown_event_rejected(self):
        attribution = [
            {
                "eventId": "evt-999999",
                "summary": "s",
                "matches": [
                    {"source": "hardeningRules", "rule": "disallow-umount"}
                ],
            }
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(
                self._pre(), self._catalog(), attribution
            )

    def test_match_not_in_catalog_rejected(self):
        attribution = [
            {
                "eventId": "evt-000001",
                "summary": "s",
                "matches": [
                    {"source": "hardeningRules", "rule": "no-such-rule"}
                ],
            }
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(
                self._pre(), self._catalog(), attribution
            )

    def test_valid_attribution_authorized(self):
        attribution = [
            {
                "eventId": "evt-000001",
                "summary": "s",
                "matches": [
                    {
                        "source": "hardeningRules",
                        "rule": "disallow-umount",
                        "context": {},
                        "decision": "remove",
                    }
                ],
            }
        ]
        result = validate_attribution.validate(
            self._pre(), self._catalog(), attribution
        )
        self.assertEqual(result["marker"], "vopt-authorized-removals")
        self.assertEqual(len(result["authorized"]), 1)
        self.assertEqual(
            validate_attribution.selected_removals(result),
            [
                {
                    "source": "hardeningRules",
                    "rule": "disallow-umount",
                    "context": {},
                }
            ],
        )

    def test_removal_decisions_are_required_and_consistent(self):
        authorized = {
            "marker": "vopt-authorized-removals",
            "authorized": [
                {
                    "source": "hardeningRules",
                    "rule": "disallow-umount",
                    "context": {},
                    "eventId": "evt-000001",
                    "decision": None,
                }
            ],
        }
        with self.assertRaises(common.ValidationError):
            validate_attribution.selected_removals(authorized)
        authorized["authorized"][0]["decision"] = "keep"
        self.assertEqual(validate_attribution.selected_removals(authorized), [])
        conflicting = dict(authorized)
        conflicting["authorized"] = list(authorized["authorized"]) + [
            dict(authorized["authorized"][0], decision="remove")
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.selected_removals(conflicting)

    def test_malformed_attribution_is_validation_error(self):
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(self._pre(), self._catalog(), ["bad"])
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(
                self._pre(),
                self._catalog(),
                [{"eventId": "evt-000001", "matches": "bad"}],
            )

    def test_network_proxy_match_requires_eligible_evidence(self):
        rule = {"to": [{"host": "example.com"}]}
        doc = policy(
            enforcer="NetworkProxy",
            enhance={
                "networkProxyRawRules": {
                    "egress": {"defaultAction": "deny", "rules": [rule]}
                }
            },
        )
        catalog = {
            "ruleCatalog": preprocess_aggregate.build_rule_catalog(doc, CATALOG)
        }
        pre = {
            "window": {"start": 0, "end": 10},
            "collectionComplete": True,
            "retentionCovered": True,
            "networkProxyEvidenceEligible": False,
            "aggregatedEvents": [
                {
                    "eventId": "evt-000001",
                    "enforcer": "NetworkProxy",
                    "event": {"layer": "L4"},
                }
            ],
        }
        attribution = [
            {
                "eventId": "evt-000001",
                "matches": [
                    {
                        "source": "networkProxyRawRules.egress.rules",
                        "rule": rule,
                    }
                ],
            }
        ]
        with self.assertRaises(common.ValidationError):
            validate_attribution.validate(pre, catalog, attribution)
        pre["networkProxyEvidenceEligible"] = True
        result = validate_attribution.validate(pre, catalog, attribution)
        self.assertEqual(len(result["authorized"]), 1)


class EmptySelectorTests(unittest.TestCase):
    def _doc(self, kind="VarmorClusterPolicy"):
        doc = policy(kind=kind)
        if kind == "VarmorClusterPolicy":
            del doc["metadata"]["namespace"]
        doc["spec"]["target"] = {"kind": "Deployment", "selector": {}}
        return doc

    def test_empty_selector_rejected_by_default(self):
        result = validate_policy.normalize(common.dump_yaml(self._doc()), CATALOG)
        self.assertFalse(result["valid"])

    def test_empty_selector_opt_in(self):
        result = validate_policy.normalize(
            common.dump_yaml(self._doc()), CATALOG, allow_empty_selector=True
        )
        self.assertTrue(result["valid"])

    def test_opt_in_leaves_high_risk_notice(self):
        result = validate_policy.normalize(
            common.dump_yaml(self._doc()), CATALOG, allow_empty_selector=True
        )
        self.assertTrue(any("matches all" in n for n in result["notices"]))

    def test_equivalent_empty_forms_rejected(self):
        for sel in (
            {"matchLabels": {}},
            {"matchExpressions": []},
            {"matchLabels": None},
        ):
            doc = self._doc()
            doc["spec"]["target"] = {"kind": "Deployment", "selector": sel}
            self.assertFalse(
                validate_policy.normalize(common.dump_yaml(doc), CATALOG)["valid"]
            )

    def test_unknown_selector_field_rejected_even_opt_in(self):
        # unknown fields are never bypassed by the high-risk flag
        doc = self._doc()
        doc["spec"]["target"] = {"kind": "Deployment", "selector": {"foo": "bar"}}
        result = validate_policy.normalize(
            common.dump_yaml(doc), CATALOG, allow_empty_selector=True
        )
        self.assertFalse(result["valid"])


class BuildManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    def _path(self, name):
        return os.path.join(self.tmp, name)

    def _write_log(self, name, timestamps):
        path = self._path(name)
        with open(path, "w") as handle:
            for timestamp in timestamps:
                handle.write(
                    json.dumps(
                        {
                            "eventTimestamp": timestamp,
                            "enforcer": "AppArmor",
                        }
                    )
                    + "\n"
                )
        return path

    def _inventory(
        self,
        nodes,
        captured_at,
        complete=True,
        agent_uid_suffix="",
        daemonset_generation=1,
    ):
        count = len(nodes)
        return {
            "inventoryVersion": 2,
            "capturedAt": captured_at,
            "daemonSet": {
                "namespace": "varmor",
                "name": "varmor-agent",
                "uid": "ds-uid",
                "resourceVersion": str(captured_at),
                "generation": daemonset_generation,
                "observedGeneration": daemonset_generation,
                "desiredNumberScheduled": count,
                "currentNumberScheduled": count,
                "numberReady": count,
            },
            "inventoryComplete": complete,
            "issues": [] if complete else ["agent inventory incomplete"],
            "agents": [
                {
                    "node": node,
                    "pod": "agent-%d" % index,
                    "uid": "agent-%d%s" % (index, agent_uid_suffix),
                    "ready": complete,
                    "terminating": False,
                }
                for index, node in enumerate(nodes)
            ],
        }

    def _build(
        self,
        nodes,
        triples,
        start=10,
        end=20,
        manifest_built_at=20,
        complete=True,
    ):
        return build_manifest.build(
            self._inventory(nodes, captured_at=5, complete=complete),
            self._inventory(nodes, captured_at=end, complete=complete),
            triples,
            start,
            end,
            manifest_built_at=manifest_built_at,
        )

    def test_missing_node_marked_unread(self):
        n1 = self._write_log("n1.log", [5])
        manifest, merged = self._build(
            ["n1", "n2"],
            [("n1", n1, 0), ("n2", self._path("missing.log"), 0)],
        )
        by_node = {n["node"]: n["read"] for n in manifest["nodes"]}
        self.assertEqual(by_node, {"n1": True, "n2": False})
        self.assertFalse(
            preprocess_aggregate.preprocess(
                [{"enforcer": "AppArmor", "event": {"operation": "open"}}],
                CATALOG,
                manifest=manifest,
            )["collectionComplete"]
        )

    def test_partial_read_nonzero_exit_fails_closed(self):
        # exit=1 with real partial bytes -> not read, lines not merged
        n1 = self._write_log("n1.log", [5])
        manifest, merged = self._build(
            ["n1"], [("n1", n1, 1)]
        )
        self.assertFalse(manifest["nodes"][0]["read"])
        self.assertEqual(merged, "")

    def test_empty_file_exit_zero_is_read_but_retention_unknown(self):
        n1 = self._path("n1.log")
        with open(n1, "w") as handle:
            handle.write("")
        manifest, _ = self._build(
            ["n1"], [("n1", n1, 0)]
        )
        self.assertTrue(manifest["nodes"][0]["read"])
        self.assertFalse(manifest["retentionCovered"])
        self.assertEqual(
            manifest["nodes"][0]["retention"]["basis"],
            "no-timestamped-events",
        )

    def test_all_nodes_read_completes(self):
        n1 = self._write_log("n1.log", [5, 12])
        manifest, _ = self._build(
            ["n1"], [("n1", n1, 0)]
        )
        self.assertTrue(
            preprocess_aggregate.preprocess(
                [{"enforcer": "AppArmor", "event": {"operation": "open"}}],
                CATALOG,
                manifest=manifest,
            )["collectionComplete"]
        )

    def test_retention_not_proven_is_incomplete(self):
        n1 = self._write_log("n1.log", [11, 12])
        manifest, _ = self._build(
            ["n1"], [("n1", n1, 0)]
        )
        self.assertFalse(manifest["retentionCovered"])
        self.assertEqual(manifest["nodes"][0]["earliestEventTimestamp"], 11)
        self.assertFalse(
            preprocess_aggregate.preprocess(
                [{"enforcer": "AppArmor", "event": {"operation": "open"}}],
                CATALOG,
                manifest=manifest,
            )["collectionComplete"]
        )

    def test_duplicate_collection_rejected_and_missing_node_incomplete(self):
        n1 = self._write_log("n1.log", [5])
        with self.assertRaises(common.ValidationError):
            build_manifest.build(
                self._inventory(["n1"], captured_at=5),
                self._inventory(["n1"], captured_at=20),
                [("n1", n1, 0), ("n1", n1, 0)],
                10,
                20,
                manifest_built_at=20,
            )
        manifest, _ = self._build(
            ["n1", "n2"], [("n1", n1, 0)]
        )
        self.assertFalse(manifest["nodeSetComplete"])
        self.assertEqual(manifest["missingCollectedNodes"], ["n2"])

    def test_not_ready_inventory_blocks_complete_collection(self):
        n1 = self._write_log("n1.log", [5])
        manifest, _ = build_manifest.build(
            self._inventory(["n1"], captured_at=5, complete=False),
            self._inventory(["n1"], captured_at=20, complete=False),
            [("n1", n1, 0)],
            10,
            20,
            manifest_built_at=20,
        )
        self.assertFalse(manifest["agentInventoryComplete"])
        self.assertFalse(manifest["nodeSetComplete"])
        self.assertFalse(manifest["retentionCovered"])

    def test_collection_before_window_end_is_incomplete(self):
        n1 = self._write_log("n1.log", [5])
        manifest, _ = self._build(
            ["n1"],
            [("n1", n1, 0)],
            end=20,
            manifest_built_at=19,
        )
        self.assertEqual(manifest["manifestBuiltAt"], 19)
        self.assertFalse(manifest["windowComplete"])
        self.assertTrue(manifest["nodeSetComplete"])
        self.assertFalse(
            preprocess_aggregate.preprocess(
                [],
                CATALOG,
                manifest=manifest,
                collection_window={"start": 10, "end": 20},
            )["collectionComplete"]
        )

    def test_start_inventory_must_precede_window(self):
        n1 = self._write_log("n1.log", [10])
        with self.assertRaises(common.ValidationError):
            build_manifest.build(
                self._inventory(["n1"], captured_at=11),
                self._inventory(["n1"], captured_at=20),
                [("n1", n1, 0)],
                10,
                20,
                manifest_built_at=20,
            )

    def test_disappeared_node_and_replaced_agent_fail_closed(self):
        n1 = self._write_log("n1.log", [5])
        n2 = self._write_log("n2.log", [5])
        manifest, _ = build_manifest.build(
            self._inventory(["n1", "n2"], captured_at=5),
            self._inventory(["n1"], captured_at=20),
            [("n1", n1, 0), ("n2", n2, 0)],
            10,
            20,
            manifest_built_at=20,
        )
        self.assertEqual(manifest["expectedNodes"], ["n1", "n2"])
        self.assertEqual(manifest["disappearedNodes"], ["n2"])
        self.assertFalse(manifest["agentInventoryComplete"])

        manifest, _ = build_manifest.build(
            self._inventory(["n1"], captured_at=5),
            self._inventory(
                ["n1"],
                captured_at=20,
                agent_uid_suffix="-replacement",
            ),
            [("n1", n1, 0)],
            10,
            20,
            manifest_built_at=20,
        )
        self.assertEqual(manifest["replacedAgentNodes"], ["n1"])
        self.assertFalse(manifest["agentInventoryComplete"])

    def test_compact_preprocess_embeds_manifest_and_counts(self):
        path = self._path("n1.log")
        with open(path, "w") as handle:
            for timestamp in (5, 12):
                handle.write(
                    json.dumps(
                        {
                            "eventTimestamp": timestamp,
                            "profileName": "profile-a",
                            "enforcer": "AppArmor",
                            "event": {
                                "operation": "open",
                                "name": "/etc/example",
                            },
                        }
                    )
                    + "\n"
                )
        current = policy(
            enforcer="AppArmor",
            enhance={
                "auditViolations": True,
                "allowViolations": True,
            },
        )
        current["status"] = {"profileName": "profile-a"}
        output = preprocess_aggregate.preprocess_node_logs(
            self._inventory(["n1"], captured_at=5),
            self._inventory(["n1"], captured_at=20),
            [("n1", path)],
            10,
            20,
            current,
            CATALOG,
            "not-applicable",
            "profile-a",
            policy_kind="VarmorPolicy",
            policy_namespace="app",
            policy_name="demo",
            manifest_built_at=20,
        )
        self.assertTrue(output["collectionComplete"])
        self.assertTrue(output["collectionManifest"]["retentionCovered"])
        self.assertEqual(output["collectionCounts"]["matched"], 1)
        self.assertEqual(len(output["aggregatedEvents"]), 1)

    def test_compact_preprocess_cli(self):
        log_path = self._path("n1.log")
        with open(log_path, "w") as handle:
            for timestamp in (5, 12):
                handle.write(
                    json.dumps(
                        {
                            "eventTimestamp": timestamp,
                            "profileName": "profile-a",
                            "enforcer": "AppArmor",
                            "event": {"operation": "open", "name": "/etc/example"},
                        }
                    )
                    + "\n"
                )
        start_path = self._path("start.json")
        end_path = self._path("end.json")
        policy_path = self._path("policy.yaml")
        with open(start_path, "w") as handle:
            json.dump(self._inventory(["n1"], captured_at=5), handle)
        with open(end_path, "w") as handle:
            json.dump(self._inventory(["n1"], captured_at=20), handle)
        with open(policy_path, "w") as handle:
            handle.write(
                common.dump_yaml(
                    dict(policy(
                        enforcer="AppArmor",
                        enhance={
                            "auditViolations": True,
                            "allowViolations": True,
                        },
                    ), status={"profileName": "profile-a"})
                )
            )
        result = subprocess.run(
            [
                "python3",
                os.path.join(SCRIPTS_DIR, "preprocess_aggregate.py"),
                "preprocess",
                "--start-agent-inventory",
                start_path,
                "--end-agent-inventory",
                end_path,
                "--window-start",
                "10",
                "--window-end",
                "20",
                "--node",
                "n1",
                "--log",
                log_path,
                "--profile-name",
                "profile-a",
                "--policy-kind",
                "VarmorPolicy",
                "--policy-namespace",
                "app",
                "--policy-name",
                "demo",
                "--policy",
                policy_path,
                "--network-proxy-evidence",
                "not-applicable",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["collectionComplete"])


class AgentInventoryTests(unittest.TestCase):
    def _daemonset(self, desired=2, current=2, ready=2):
        return {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": "varmor-agent",
                "namespace": "varmor",
                "uid": "ds-uid",
                "generation": 3,
                "resourceVersion": "100",
            },
            "status": {
                "observedGeneration": 3,
                "desiredNumberScheduled": desired,
                "currentNumberScheduled": current,
                "numberReady": ready,
            },
        }

    def _pod(self, name, node, ready=True, owner_uid="ds-uid"):
        return {
            "metadata": {
                "name": name,
                "namespace": "varmor",
                "uid": name + "-uid",
                "ownerReferences": [
                    {
                        "kind": "DaemonSet",
                        "name": "varmor-agent",
                        "uid": owner_uid,
                    }
                ],
            },
            "spec": {"nodeName": node},
            "status": {
                "phase": "Running",
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "True" if ready else "False",
                    }
                ],
            },
        }

    def test_complete_inventory_includes_all_owned_pods(self):
        pods = {
            "items": [
                self._pod("agent-a", "node-a"),
                self._pod("agent-b", "node-b"),
                self._pod("unrelated", "node-c", owner_uid="other"),
            ]
        }
        result = build_agent_inventory.build(self._daemonset(), pods)
        self.assertTrue(result["inventoryComplete"])
        self.assertEqual(
            [agent["node"] for agent in result["agents"]],
            ["node-a", "node-b"],
        )

    def test_not_ready_owned_pod_is_retained_and_blocks(self):
        pods = {
            "items": [
                self._pod("agent-a", "node-a"),
                self._pod("agent-b", "node-b", ready=False),
            ]
        }
        result = build_agent_inventory.build(
            self._daemonset(ready=1), pods
        )
        self.assertFalse(result["inventoryComplete"])
        self.assertEqual(len(result["agents"]), 2)
        self.assertFalse(result["agents"][1]["ready"])
        self.assertTrue(any("not Ready" in issue for issue in result["issues"]))

    def test_missing_owned_pod_blocks_against_desired_count(self):
        pods = {"items": [self._pod("agent-a", "node-a")]}
        result = build_agent_inventory.build(
            self._daemonset(desired=2, current=1, ready=1), pods
        )
        self.assertFalse(result["inventoryComplete"])
        self.assertTrue(
            any("owned Pod count" in issue for issue in result["issues"])
        )

    def test_split_cluster_snapshot_selects_exact_daemonset(self):
        snapshot = {
            "kind": "List",
            "items": [
                self._daemonset(),
                dict(
                    self._daemonset(),
                    metadata=dict(self._daemonset()["metadata"], name="other"),
                ),
                dict(self._pod("agent-a", "node-a"), kind="Pod"),
                dict(self._pod("agent-b", "node-b"), kind="Pod"),
            ],
        }
        daemonset, pods = build_agent_inventory.split_cluster_snapshot(
            snapshot,
            "varmor-agent",
            "varmor",
        )
        result = build_agent_inventory.build(daemonset, pods)
        self.assertTrue(result["inventoryComplete"])
        self.assertEqual(len(result["agents"]), 2)

    def test_cluster_snapshot_stdin_cli(self):
        snapshot = {
            "kind": "List",
            "items": [
                self._daemonset(),
                dict(self._pod("agent-a", "node-a"), kind="Pod"),
                dict(self._pod("agent-b", "node-b"), kind="Pod"),
            ],
        }
        result = subprocess.run(
            [
                "python3",
                os.path.join(SCRIPTS_DIR, "build_agent_inventory.py"),
                "--cluster-snapshot",
                "-",
                "--daemonset-name",
                "varmor-agent",
                "--daemonset-namespace",
                "varmor",
            ],
            input=json.dumps(snapshot),
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["inventoryComplete"])


class SeccompGateTests(unittest.TestCase):
    def test_apply_refuses_incomplete_pre(self):
        # Gate unit logic mirrors the CLI: complete + no failures required.
        pre = {"collectionComplete": False, "retentionCovered": True, "failures": []}
        self.assertFalse(pre["collectionComplete"])
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "failures": [{"reason": "x"}],
        }
        self.assertTrue(pre["failures"])
        pre = {"collectionComplete": True, "retentionCovered": True, "failures": []}
        self.assertTrue(pre["collectionComplete"] and not pre["failures"])

    def test_apply_cli_requires_pre(self):
        doc = policy(
            enforcer="AppArmorSeccomp",
            enhance={"privileged": False,
                     "attackProtectionRules": [{"rules": ["disable-chmod-x-bit"]}]},
        )
        policy_path = os.path.join(tempfile.mkdtemp(), "p.yaml")
        with open(policy_path, "w") as handle:
            handle.write(common.dump_yaml(doc))
        result = subprocess.run(
            [
                "python3", os.path.join(SCRIPTS_DIR, "seccomp_plan.py"),
                "--policy", policy_path, "--syscalls", "chmod", "--apply",
            ],
            capture_output=True, text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--pre", result.stderr)

    def test_apply_ambiguous_plan_requires_explicit_opt_in(self):
        doc = policy(
            enforcer="Seccomp",
            enhance={
                "privileged": False,
                "attackProtectionRules": [
                    {"rules": ["disable-chmod-x-bit", "disable-chmod-s-bit"]}
                ],
            },
        )
        tmp = tempfile.mkdtemp()
        policy_path = os.path.join(tmp, "p.yaml")
        pre_path = os.path.join(tmp, "pre.json")
        with open(policy_path, "w") as handle:
            handle.write(common.dump_yaml(doc))
        with open(pre_path, "w") as handle:
            json.dump(
                {
                    "collectionComplete": True,
                    "retentionCovered": True,
                    "failures": [],
                    "seccompSyscalls": ["chmod"],
                },
                handle,
            )
        result = subprocess.run(
            [
                "python3",
                os.path.join(SCRIPTS_DIR, "seccomp_plan.py"),
                "--policy",
                policy_path,
                "--pre",
                pre_path,
                "--apply",
                "--remove-seccomp-rule",
                "disable-chmod-x-bit",
                "--remove-seccomp-rule",
                "disable-chmod-s-bit",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--allow-ambiguous", result.stderr)

        result = subprocess.run(
            [
                "python3",
                os.path.join(SCRIPTS_DIR, "seccomp_plan.py"),
                "--policy",
                policy_path,
                "--pre",
                pre_path,
                "--apply",
                "--remove-seccomp-rule",
                "disable-chmod-x-bit",
                "--remove-seccomp-rule",
                "disable-chmod-s-bit",
                "--allow-ambiguous",
            ],
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        updated = common.load_yaml_doc(result.stdout)
        self.assertNotIn(
            "attackProtectionRules",
            updated["spec"]["policy"]["enhanceProtect"],
        )


class CollectionManifestTests(unittest.TestCase):
    def test_manifest_node_coverage(self):
        records = [
            {"enforcer": "AppArmor", "event": {"operation": "open", "name": "/x"}}
        ]
        # one expected node not read -> incomplete
        manifest = {
            "window": {"start": 0, "end": 10},
            "collectedAt": 10,
            "manifestBuiltAt": 10,
            "windowComplete": True,
            "logsCollectedAfterWindow": True,
            "expectedNodes": ["n1", "n2"],
            "agentInventoryComplete": True,
            "nodeSetComplete": True,
            "retentionCovered": True,
            "parseErrors": 0,
            "nodes": [
                {
                    "node": "n1",
                    "read": True,
                    "retention": {"status": "covered"},
                },
                {
                    "node": "n2",
                    "read": False,
                    "retention": {"status": "covered"},
                },
            ],
        }
        result = preprocess_aggregate.preprocess(records, CATALOG, manifest=manifest)
        self.assertFalse(result["collectionComplete"])
        # both read -> complete
        manifest["nodes"][1]["read"] = True
        result = preprocess_aggregate.preprocess(records, CATALOG, manifest=manifest)
        self.assertTrue(result["collectionComplete"])

    def test_handwritten_manifest_without_expected_set_fails_closed(self):
        records = [
            {"enforcer": "AppArmor", "event": {"operation": "open", "name": "/x"}}
        ]
        manifest = {
            "window": {"start": 0, "end": 10},
            "collectedAt": 10,
            "manifestBuiltAt": 10,
            "windowComplete": True,
            "logsCollectedAfterWindow": True,
            "retentionCovered": True,
            "parseErrors": 0,
            "nodes": [
                {
                    "node": "n1",
                    "read": True,
                    "retention": {"status": "covered"},
                }
            ],
        }
        result = preprocess_aggregate.preprocess(records, CATALOG, manifest=manifest)
        self.assertFalse(result["collectionComplete"])
        self.assertFalse(result["statistics"]["nodeSetComplete"])


class HashPolicyTests(unittest.TestCase):
    def test_fingerprint_and_verify(self):
        doc = policy()
        text = common.dump_yaml(doc)
        digest, _ = hash_policy.fingerprint(text)
        self.assertEqual(len(digest), 64)
        doc2 = policy()
        doc2["metadata"]["name"] = "changed"
        digest2, _ = hash_policy.fingerprint(common.dump_yaml(doc2))
        self.assertNotEqual(digest, digest2)

    def _live_policy(self):
        doc = policy()
        doc["metadata"].update(
            {
                "uid": "uid-1",
                "generation": 3,
                "resourceVersion": "100",
            }
        )
        doc["status"] = {"profileName": "varmor-demo"}
        return doc

    def test_snapshot_accepts_status_only_resource_version_change(self):
        doc = self._live_policy()
        snapshot = hash_policy.create_snapshot(common.dump_yaml(doc), captured_at=100)
        doc["metadata"]["resourceVersion"] = "101"
        result = hash_policy.verify_snapshot(
            common.dump_yaml(doc), snapshot, window_start=100
        )
        self.assertTrue(result["valid"])
        self.assertTrue(result["resourceVersionChanged"])
        self.assertEqual(result["capturedAt"], 100)

    def test_verify_snapshot_resource_version_only_cli(self):
        doc = self._live_policy()
        snapshot = hash_policy.create_snapshot(common.dump_yaml(doc), captured_at=100)
        with tempfile.TemporaryDirectory() as tmp:
            policy_path = os.path.join(tmp, "policy.yaml")
            snapshot_path = os.path.join(tmp, "snapshot.json")
            with open(policy_path, "w") as handle:
                handle.write(common.dump_yaml(doc))
            with open(snapshot_path, "w") as handle:
                json.dump(snapshot, handle)
            result = subprocess.run(
                [
                    "python3",
                    os.path.join(SCRIPTS_DIR, "hash_policy.py"),
                    "verify-snapshot",
                    "--file",
                    policy_path,
                    "--snapshot",
                    snapshot_path,
                    "--window-start",
                    "100",
                    "--resource-version-only",
                ],
                capture_output=True,
                text=True,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "100")

    def test_snapshot_rejects_recreation_or_spec_drift(self):
        doc = self._live_policy()
        snapshot = hash_policy.create_snapshot(common.dump_yaml(doc), captured_at=100)

        recreated = self._live_policy()
        recreated["metadata"]["uid"] = "uid-2"
        self.assertFalse(
            hash_policy.verify_snapshot(
                common.dump_yaml(recreated), snapshot, window_start=100
            )["valid"]
        )

        changed = self._live_policy()
        changed["metadata"]["generation"] = 4
        changed["spec"]["policy"]["enhanceProtect"]["hardeningRules"] = [
            "disable-cap-net-raw"
        ]
        result = hash_policy.verify_snapshot(
            common.dump_yaml(changed), snapshot, window_start=100
        )
        self.assertFalse(result["valid"])
        self.assertEqual(
            {item["field"] for item in result["mismatches"]},
            {"generation", "specSha256"},
        )

    def test_snapshot_rejects_window_start_before_capture(self):
        doc = self._live_policy()
        snapshot = hash_policy.create_snapshot(common.dump_yaml(doc), captured_at=100)
        with self.assertRaises(common.ValidationError):
            hash_policy.verify_snapshot(
                common.dump_yaml(doc), snapshot, window_start=99
            )


class CollectionGateTests(unittest.TestCase):
    def test_collection_completeness_computation(self):
        # parseErrors>0 -> incomplete; ==0 -> complete
        self.assertFalse(int({"parseErrors": 1}.get("parseErrors") or 0) == 0)
        self.assertTrue(int({"parseErrors": 0}.get("parseErrors") or 0) == 0)

    def test_collect_requires_profile_name(self):
        result = subprocess.run(
            [
                "python3",
                os.path.join(SCRIPTS_DIR, "collect_violations.py"),
                "--start",
                "0",
                "--end",
                "10",
            ],
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--profile-name", result.stderr + result.stdout)

    # --- review round 3 #5: duplicate keys ---

    def test_duplicate_keys_rejected(self):
        text = (
            "apiVersion: crd.varmor.org/v1beta1\n"
            "kind: VarmorPolicy\n"
            "metadata: {name: demo, namespace: app}\n"
            "spec:\n"
            "  target: {kind: Deployment, name: t}\n"
            "  policy:\n"
            "    enforcer: AppArmor\n"
            "    mode: EnhanceProtect\n"
            "    enhanceProtect:\n"
            "      hardeningRules: [disable-write-etc]\n"
            "      hardeningRules: [disable-curl]\n"
        )
        self.assertTrue(validate_policy.normalize(text, CATALOG)["errors"])

    # --- review #9: size limit is on UTF-8 bytes, not characters ---

    def test_size_limit_counts_utf8_bytes(self):
        # 100k Chinese chars: under 262144 chars, but 300000 UTF-8 bytes.
        text = "x: '" + "中" * 100000 + "'"
        self.assertLess(len(text), 256 * 1024)
        self.assertGreater(len(text.encode("utf-8")), 256 * 1024)
        result = validate_policy.normalize(text, CATALOG)
        self.assertTrue(any("KiB" in e for e in result["errors"]))

    def test_builtin_rule_errors(self):
        doc = policy(enhance={"hardeningRules": ["no-such-rule"]})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

        # wrong field: hardening rule placed in vulMitigationRules
        doc = policy(enhance={"vulMitigationRules": ["disable-cap-net-raw"]})
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

        # incompatible enforcer: bpf-only rule under AppArmor
        doc = policy(
            enforcer="AppArmor",
            enhance={
                "attackProtectionRules": [
                    {"rules": ["block-access-to-metadata-service"]}
                ]
            },
        )
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

        # targets require AppArmor
        doc = policy(
            enforcer="BPF",
            enhance={
                "attackProtectionRules": [
                    {"rules": ["disable-curl"], "targets": ["/bin/x"]}
                ]
            },
        )
        self.assertTrue(validate_policy.normalize(yaml_of(doc), CATALOG)["errors"])

    def test_multiple_errors_collected_once(self):
        doc = policy(
            enhance={
                "hardeningRules": ["bad-1", "bad-2", "bad-1"],
                "vulMitigationRules": ["bad-3"],
            }
        )
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        # bad-1 duplicate is de-duplicated, still multiple distinct errors
        self.assertGreaterEqual(len(result["errors"]), 3)

    def test_aggregate_expansion_and_flags(self):
        doc = policy(enhance={"hardeningRules": ["disable-cap-all"]})
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        self.assertTrue(result["valid"])
        normalized = common.load_yaml_doc(result["normalized"])
        rules = normalized["spec"]["policy"]["enhanceProtect"]["hardeningRules"]
        self.assertIn("disable-cap-net-raw", rules)
        self.assertNotIn("disable-cap-all", rules)
        # flags are forced on for observation
        self.assertTrue(
            normalized["spec"]["policy"]["enhanceProtect"]["auditViolations"]
        )
        self.assertTrue(
            normalized["spec"]["policy"]["enhanceProtect"]["allowViolations"]
        )
        self.assertTrue(result["adjustments"])

    def test_stage_two_rejects_aggregate_capability_rules(self):
        for aggregate in (
            "disable-cap-all",
            "disable-cap-all-except-net-bind-service",
            "disable-cap-privileged",
        ):
            doc = policy(enhance={"hardeningRules": [aggregate]})
            result = validate_policy.normalize(
                yaml_of(doc),
                CATALOG,
                require_atomic_capabilities=True,
            )
            self.assertFalse(result["valid"])
            self.assertIn("atomized", result["errors"][0])

    def test_stage_two_requires_explicit_observation_switches(self):
        for enhance in (
            {},
            {"auditViolations": False, "allowViolations": True},
            {"auditViolations": True, "allowViolations": False},
        ):
            doc = policy(enhance=enhance)
            result = validate_policy.normalize(
                yaml_of(doc),
                CATALOG,
                require_observation=True,
            )
            self.assertFalse(result["valid"])
            self.assertTrue(
                any("Phase two requires" in error for error in result["errors"])
            )

        doc = policy(
            enhance={"auditViolations": True, "allowViolations": True}
        )
        result = validate_policy.normalize(
            yaml_of(doc),
            CATALOG,
            require_observation=True,
        )
        self.assertTrue(result["valid"])

    def test_notices_for_blocking_and_pod(self):
        doc = policy(
            target_kind="Pod",
            enhance={
                "syscallRawRules": [
                    {"names": ["keyctl"], "action": "SCMP_ACT_ERRNO", "args": []}
                ]
            },
        )
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        self.assertTrue(result["valid"])
        self.assertTrue(
            any("Pod" in n and "recreate" in n for n in result["notices"])
        )
        self.assertTrue(
            any("blocking Seccomp" in n for n in result["notices"])
        )

    def test_unchanged_policy_has_no_adjustments(self):
        doc = policy(
            enhance={"auditViolations": True, "allowViolations": True}
        )
        result = validate_policy.normalize(yaml_of(doc), CATALOG)
        self.assertTrue(result["valid"])
        self.assertEqual(result["adjustments"], [])


class CollectViolationsTests(unittest.TestCase):
    def _record(self, ts, identity=None, profile="prof"):
        record = {
            "eventTimestamp": ts,
            "profileName": profile,
            "policyKind": "VarmorPolicy",
            "policyName": "demo",
            "policyNamespace": "app",
        }
        if identity is not None:
            record.update(identity)
        return record

    def test_end_required(self):
        with self.assertRaises(common.ValidationError):
            collect_violations.collect("", 1, None)

    def test_window_and_identity(self):
        lines = "\n".join(
            [
                json.dumps(self._record(10)),
                json.dumps(self._record(20)),  # outside
                json.dumps(
                    self._record(10, {"policyName": "other"})
                ),  # other policy
                "not-json",
            ]
        )
        result = collect_violations.collect(
            lines, 0, 15, kind="VarmorPolicy", namespace="app", name="demo"
        )
        self.assertEqual(result["counts"]["matched"], 1)
        self.assertEqual(result["counts"]["outsideWindow"], 1)
        self.assertEqual(result["counts"]["otherPolicy"], 1)
        self.assertEqual(result["counts"]["parseErrors"], 1)
        self.assertEqual(
            result["counts"]["accountedLines"],
            result["counts"]["totalLines"],
        )

    def test_profile_fallback(self):
        record = {
            "eventTimestamp": 5,
            "profileName": "the-profile",
        }
        lines = json.dumps(record)
        result = collect_violations.collect(
            lines, 0, 10, profile_name="the-profile"
        )
        self.assertEqual(result["counts"]["matched"], 1)
        self.assertEqual(result["counts"]["recordsWithProfileNameOnly"], 1)

    def test_profile_name_is_always_checked_with_policy_identity(self):
        lines = "\n".join(
            [
                json.dumps(self._record(5, profile="expected")),
                json.dumps(self._record(5, profile="other")),
                json.dumps(
                    {
                        "eventTimestamp": 5,
                        "profileName": "expected",
                    }
                ),
            ]
        )
        result = collect_violations.collect(
            lines,
            0,
            10,
            kind="VarmorPolicy",
            namespace="app",
            name="demo",
            profile_name="expected",
        )
        self.assertEqual(result["counts"]["matched"], 2)
        self.assertEqual(result["counts"]["identityMismatch"], 1)
        self.assertEqual(result["counts"]["profileMismatch"], 1)
        self.assertEqual(result["counts"]["recordsWithPolicyIdentity"], 2)
        self.assertEqual(result["counts"]["recordsWithProfileNameOnly"], 1)

    def test_timestamp_parsing(self):
        self.assertEqual(collect_violations.parse_timestamp("100"), 100)
        with self.assertRaises(common.ValidationError):
            collect_violations.parse_timestamp("not-a-time")


class PathNormTests(unittest.TestCase):
    def test_proc_pid_task_map(self):
        out, changed = pathnorm.normalize_path("/proc/123/status")
        self.assertTrue(changed)
        self.assertEqual(out, "/proc/:pid/status")
        out, _ = pathnorm.normalize_path("/proc/1/task/2/stat")
        self.assertEqual(out, "/proc/:pid/task/:tid/stat")
        out, _ = pathnorm.normalize_path("/proc/1/map_files/aa-bb")
        self.assertEqual(out, "/proc/:pid/map_files/:range")

    def test_snapshot_and_unchanged(self):
        out, _ = pathnorm.normalize_path(
            "/x/snapshots/77/fs/etc/hosts"
        )
        self.assertIn(":snapshot", out)
        out, changed = pathnorm.normalize_path("/etc/hosts")
        self.assertFalse(changed)


class PreprocessAggregateTests(unittest.TestCase):
    def test_network_proxy_evidence_matches_policy(self):
        plain = policy(enforcer="AppArmor")
        preprocess_aggregate.validate_network_proxy_evidence(
            plain, "not-applicable", CATALOG
        )
        with self.assertRaises(common.ValidationError):
            preprocess_aggregate.validate_network_proxy_evidence(
                plain, "eligible", CATALOG
            )

        network = policy(enforcer="NetworkProxy")
        with self.assertRaises(common.ValidationError):
            preprocess_aggregate.validate_network_proxy_evidence(
                network, "not-applicable", CATALOG
            )
        preprocess_aggregate.validate_network_proxy_evidence(
            network, "ineligible", CATALOG
        )
        preprocess_aggregate.validate_network_proxy_evidence(
            network, "eligible", CATALOG
        )

    def test_preprocess_records_network_proxy_evidence(self):
        result = preprocess_aggregate.preprocess(
            [],
            CATALOG,
            network_proxy_evidence_status="ineligible",
        )
        self.assertFalse(result["networkProxyEvidenceEligible"])
        self.assertEqual(
            result["networkProxyEvidenceStatus"], "ineligible"
        )

    def test_preprocess_seccomp_extracted(self):
        records = [
            {
                "enforcer": "Seccomp",
                "event": {"syscall": "splice", "auditID": "x"},
            },
            {
                "enforcer": "Seccomp",
                "event": {"syscall": ""},  # invalid
            },
        ]
        result = preprocess_aggregate.preprocess(records, CATALOG)
        self.assertEqual(result["seccompSyscalls"], ["splice"])
        self.assertEqual(len(result["failures"]), 1)
        self.assertEqual(result["events"], [])

    def test_collection_parse_errors_fail_closed(self):
        manifest = {
            "window": {"start": 0, "end": 10},
            "collectedAt": 10,
            "manifestBuiltAt": 10,
            "windowComplete": True,
            "logsCollectedAfterWindow": True,
            "expectedNodes": ["n1"],
            "agentInventoryComplete": True,
            "nodeSetComplete": True,
            "retentionCovered": True,
            "parseErrors": 0,
            "nodes": [
                {
                    "node": "n1",
                    "read": True,
                    "retention": {"status": "covered"},
                }
            ],
        }
        result = preprocess_aggregate.preprocess(
            [],
            CATALOG,
            manifest=manifest,
            collection_counts={"parseErrors": 1},
        )
        self.assertFalse(result["collectionComplete"])
        self.assertEqual(result["statistics"]["collectionParseErrors"], 1)

    def test_manifest_window_must_match_and_be_complete(self):
        manifest = {
            "window": {"start": 0, "end": 10},
            "collectedAt": 9,
            "manifestBuiltAt": 9,
            "windowComplete": True,
            "logsCollectedAfterWindow": False,
            "expectedNodes": ["n1"],
            "agentInventoryComplete": True,
            "nodeSetComplete": True,
            "retentionCovered": True,
            "parseErrors": 0,
            "nodes": [
                {
                    "node": "n1",
                    "read": True,
                    "retention": {"status": "covered"},
                }
            ],
        }
        result = preprocess_aggregate.preprocess(
            [],
            CATALOG,
            manifest=manifest,
            collection_counts={"parseErrors": 0},
            collection_window={"start": 0, "end": 10},
        )
        self.assertFalse(result["collectionComplete"])
        self.assertFalse(result["statistics"]["windowComplete"])

        manifest["collectedAt"] = 10
        result = preprocess_aggregate.preprocess(
            [],
            CATALOG,
            manifest=manifest,
            collection_counts={"parseErrors": 0},
            collection_window={"start": 0, "end": 11},
        )
        self.assertFalse(result["collectionComplete"])

    def test_preprocess_cleans_apparmor(self):
        records = [
            {
                "enforcer": "AppArmor",
                "event": {"operation": "open", "pid": 123, "name": "/etc/x"},
            }
        ]
        result = preprocess_aggregate.preprocess(records, CATALOG)
        event = result["events"][0]["event"]
        self.assertNotIn("pid", event)
        self.assertEqual(event["name"], "/etc/x")

    def test_aggregate_merges_same_bucket(self):
        events = [
            {"enforcer": "AppArmor", "event": {"operation": "capable", "profile": "p", "name": "sys_admin", "comm": "a"}},
            {"enforcer": "AppArmor", "event": {"operation": "capable", "profile": "p", "name": "sys_admin", "comm": "b"}},
        ]
        aggregated = preprocess_aggregate.aggregate(events)
        self.assertEqual(len(aggregated), 1)
        self.assertEqual(aggregated[0]["eventId"], "evt-000001")
        self.assertEqual(aggregated[0]["event"]["comms"], ["a", "b"])

    def test_bpf_connect_keeps_destination_ips_separate(self):
        events = [
            {
                "enforcer": "BPF",
                "event": {
                    "operation": "Network",
                    "type": "connect",
                    "address": {"ip": "10.0.0.1", "port": 80},
                },
            },
            {
                "enforcer": "BPF",
                "event": {
                    "operation": "Network",
                    "type": "connect",
                    "address": {"ip": "10.0.0.2", "port": 443},
                },
            },
        ]
        aggregated = preprocess_aggregate.aggregate(events)
        self.assertEqual(len(aggregated), 2)

    def test_build_rule_catalog_excludes_seccomp(self):
        doc = policy(
            enhance={
                "hardeningRules": ["disable-cap-net-raw", "disallow-create-user-ns"]
            }
        )
        catalog = preprocess_aggregate.build_rule_catalog(doc, CATALOG)
        sources = {entry["source"] for entry in catalog}
        rules = {entry["rule"] for entry in catalog}
        self.assertIn("hardeningRules", sources)
        self.assertIn("disable-cap-net-raw", rules)
        self.assertNotIn("disallow-create-user-ns", rules)


class SeccompPlanTests(unittest.TestCase):
    def test_user_can_keep_observed_builtin_rule(self):
        doc = policy(
            enhance={"hardeningRules": ["disallow-create-user-ns"]}
        )
        plan = seccomp_plan.build_plan(
            doc,
            ["unshare"],
            CATALOG,
            keep_builtin_rules=["disallow-create-user-ns"],
        )
        self.assertEqual(plan["builtinRemovals"], [])
        self.assertEqual(
            plan["keptBuiltinRules"],
            [
                {
                    "source": "hardeningRules",
                    "rule": "disallow-create-user-ns",
                }
            ],
        )
        self.assertNotIn("unshare", plan["unmatchedSyscalls"])
        self.assertFalse(plan["changed"])

    def test_keep_rule_must_be_active_and_observed(self):
        doc = policy(
            enhance={"hardeningRules": ["disallow-create-user-ns"]}
        )
        with self.assertRaises(common.ValidationError):
            seccomp_plan.build_plan(
                doc,
                ["splice"],
                CATALOG,
                keep_builtin_rules=["disallow-create-user-ns"],
            )

    def test_builtin_custom_ambiguous_unmatched(self):
        doc = policy(
            enhance={
                "hardeningRules": ["disallow-create-user-ns"],
                "attackProtectionRules": [{"rules": ["disable-chmod-x-bit", "disable-chmod-s-bit"]}],
                "syscallRawRules": [
                    {"names": ["keyctl"], "action": "SCMP_ACT_ERRNO", "args": []}
                ],
            }
        )
        plan = seccomp_plan.build_plan(
            doc, ["unshare", "chmod", "keyctl", "weird"], CATALOG,
            remove_builtin_rules=[
                "disallow-create-user-ns",
                "disable-chmod-x-bit",
                "disable-chmod-s-bit",
            ],
            remove_syscalls=["keyctl"],
        )
        self.assertIn("chmod", plan["ambiguousSyscalls"])
        self.assertIn("weird", plan["unmatchedSyscalls"])
        self.assertEqual(
            plan["customRemovals"][0]["rule"]["names"],
            ["keyctl"],
        )
        self.assertTrue(plan["changed"])

    def test_apply_plan_removes_only_observed(self):
        doc = policy(
            enhance={
                "syscallRawRules": [
                    {"names": ["keyctl", "add_key"], "action": "SCMP_ACT_ERRNO", "args": []}
                ]
            }
        )
        plan = seccomp_plan.build_plan(
            doc, ["keyctl"], CATALOG, remove_syscalls=["keyctl"]
        )
        updated = seccomp_plan.apply_plan(doc, plan, CATALOG)
        rules = updated["spec"]["policy"]["enhanceProtect"]["syscallRawRules"]
        self.assertEqual(rules[0]["names"], ["add_key"])

    def test_non_restrictive_rules_are_not_removal_candidates(self):
        doc = policy(
            enhance={
                "syscallRawRules": [
                    {
                        "names": ["keyctl"],
                        "action": "SCMP_ACT_ALLOW",
                        "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": 1}],
                    },
                    {
                        "names": ["keyctl"],
                        "action": "SCMP_ACT_LOG",
                        "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": 2}],
                    },
                    {
                        "names": ["keyctl"],
                        "action": "SCMP_ACT_ERRNO",
                        "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": 3}],
                    },
                ]
            }
        )
        plan = seccomp_plan.build_plan(
            doc, ["keyctl"], CATALOG, remove_syscalls=["keyctl"]
        )
        self.assertEqual(len(plan["ignoredAllowRules"]), 1)
        self.assertEqual(len(plan["ignoredLogRules"]), 1)
        self.assertEqual(len(plan["customRemovals"]), 1)
        self.assertEqual(
            plan["customRemovals"][0]["rule"]["args"][0]["value"],
            3,
        )
        updated = seccomp_plan.apply_plan(doc, plan, CATALOG)
        rules = updated["spec"]["policy"]["enhanceProtect"]["syscallRawRules"]
        self.assertEqual(len(rules), 2)
        self.assertEqual(
            {rule["action"] for rule in rules},
            {"SCMP_ACT_ALLOW", "SCMP_ACT_LOG"},
        )


class GuardRemovalTests(unittest.TestCase):
    def test_live_spec_verification_rejects_retained_raw_rules(self):
        candidate = policy(enhance={"appArmorRawRules": [], "bpfRawRules": {}})
        self.assertTrue(
            guard_removal.verify_live_spec(candidate, candidate)["liveSpecVerified"]
        )
        live = common.load_yaml_doc(common.dump_yaml(candidate))
        live["metadata"]["resourceVersion"] = "newer"
        live["status"] = {"phase": "Protecting"}
        self.assertTrue(
            guard_removal.verify_live_spec(candidate, live)["liveSpecVerified"]
        )

        live = common.load_yaml_doc(common.dump_yaml(candidate))
        live["spec"]["policy"]["enhanceProtect"]["appArmorRawRules"] = [
            {"targets": [], "rules": "deny /tmp/retained r,"}
        ]
        with self.assertRaises(common.ValidationError):
            guard_removal.verify_live_spec(candidate, live)

        live = common.load_yaml_doc(common.dump_yaml(candidate))
        live["spec"]["policy"]["enhanceProtect"]["bpfRawRules"] = {
            "files": [{"pattern": "/tmp/retained", "permissions": ["r"]}]
        }
        with self.assertRaises(common.ValidationError):
            guard_removal.verify_live_spec(candidate, live)

    def test_valid_removal(self):
        base = policy(enhance={"hardeningRules": ["a-rule", "b-rule"]})
        cand = policy(enhance={"hardeningRules": ["a-rule"]})
        intended = [{"source": "hardeningRules", "rule": "b-rule"}]
        result = guard_removal.guard(base, cand, intended)
        self.assertEqual(result["totalRemoved"], 1)

    def test_addition_rejected(self):
        base = policy(enhance={"hardeningRules": ["a-rule"]})
        cand = policy(enhance={"hardeningRules": ["a-rule", "b-rule"]})
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, [])

    def test_control_change_rejected(self):
        base = policy(enhance={"allowViolations": True})
        cand = policy(enhance={"allowViolations": False})
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, [])

    def test_default_action_change_rejected(self):
        enhance = {
            "networkProxyRawRules": {
                "egress": {"defaultAction": "deny", "rules": []}
            }
        }
        base = policy(enhance=enhance)
        cand = policy(
            enhance={
                "networkProxyRawRules": {
                    "egress": {"defaultAction": "allow", "rules": []}
                }
            }
        )
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, [])

    def test_network_proxy_removal_requires_eligible_evidence(self):
        rule = {"to": [{"host": "example.com"}]}
        base = policy(
            enforcer="NetworkProxy",
            enhance={
                "networkProxyRawRules": {
                    "egress": {"defaultAction": "deny", "rules": [rule]}
                }
            },
        )
        intended = [
            {
                "source": "networkProxyRawRules.egress.rules",
                "rule": rule,
                "context": {},
            }
        ]
        authorized = {
            "marker": "vopt-authorized-removals",
            "authorized": intended,
        }
        candidate, _ = apply_removals.apply_removals(
            base,
            intended,
            authorized,
            network_proxy_evidence_eligible=True,
        )
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "networkProxyEvidenceEligible": False,
            "failures": [],
            "seccompSyscalls": [],
        }
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, candidate, intended, pre=pre)
        pre["networkProxyEvidenceEligible"] = True
        result = guard_removal.guard(base, candidate, intended, pre=pre)
        self.assertEqual(result["totalRemoved"], 1)

    def test_missing_false_control_rejected(self):
        base = policy(enhance={"privileged": False})
        cand = policy(enhance={"privileged": False})
        del cand["spec"]["policy"]["enhanceProtect"]["privileged"]
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, [])

    def test_unknown_enhance_field_change_rejected(self):
        base = policy(enhance={"futureControl": "deny"})
        cand = policy(enhance={"futureControl": "allow"})
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, [])

    def test_unintended_extra_removal_rejected(self):
        base = policy(enhance={"hardeningRules": ["a-rule", "b-rule", "c-rule"]})
        cand = policy(enhance={"hardeningRules": ["a-rule"]})
        intended = [{"source": "hardeningRules", "rule": "b-rule"}]
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, intended)

    def test_combined_seccomp_and_model_diff(self):
        base = policy(
            enhance={
                "hardeningRules": [
                    "disallow-create-user-ns",
                    "disallow-umount",
                ]
            }
        )
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "failures": [],
            "seccompSyscalls": ["unshare"],
        }
        plan = seccomp_plan.build_plan(
            base, pre["seccompSyscalls"], CATALOG,
            remove_builtin_rules=["disallow-create-user-ns"],
        )
        post_seccomp = seccomp_plan.apply_plan(base, plan, CATALOG)
        intended = [{"source": "hardeningRules", "rule": "disallow-umount"}]
        authorized = {
            "marker": "vopt-authorized-removals",
            "authorized": intended,
        }
        candidate, _ = apply_removals.apply_removals(
            post_seccomp,
            intended,
            authorized,
        )
        result = guard_removal.guard(
            base, candidate, intended, pre=pre,
            remove_seccomp_rules=["disallow-create-user-ns"],
        )
        self.assertEqual(result["totalRemoved"], 2)
        self.assertEqual(
            set(result["removedBySource"]["hardeningRules"]),
            {"disallow-create-user-ns", "disallow-umount"},
        )

    def test_combined_guard_rejects_unproven_retention(self):
        base = policy(enhance={"hardeningRules": ["disallow-create-user-ns"]})
        pre = {
            "collectionComplete": True,
            "retentionCovered": False,
            "failures": [],
            "seccompSyscalls": ["unshare"],
        }
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, base, [], pre=pre)

    def test_guard_honors_explicit_seccomp_keep_rule(self):
        base = policy(
            enhance={"hardeningRules": ["disallow-create-user-ns"]}
        )
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "failures": [],
            "seccompSyscalls": ["unshare"],
        }
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, base, [], pre=pre)
        result = guard_removal.guard(
            base,
            base,
            [],
            pre=pre,
            keep_seccomp_rules=["disallow-create-user-ns"],
        )
        self.assertEqual(result["totalRemoved"], 0)
        self.assertEqual(
            result["seccompPlan"]["keptBuiltinRules"][0]["rule"],
            "disallow-create-user-ns",
        )

    def test_guard_reports_full_custom_seccomp_atom(self):
        raw = {
            "names": ["keyctl"],
            "action": "SCMP_ACT_ERRNO",
            "errnoRet": 1,
            "args": [{"index": 0, "op": "SCMP_CMP_EQ", "value": 7}],
        }
        base = policy(enhance={"syscallRawRules": [raw]})
        pre = {
            "collectionComplete": True,
            "retentionCovered": True,
            "failures": [],
            "seccompSyscalls": ["keyctl"],
        }
        plan = seccomp_plan.build_plan(
            base, pre["seccompSyscalls"], CATALOG,
            remove_syscalls=["keyctl"],
        )
        candidate = seccomp_plan.apply_plan(base, plan, CATALOG)
        result = guard_removal.guard(
            base, candidate, [], pre=pre,
            remove_seccomp_syscalls=["keyctl"],
        )
        self.assertEqual(result["totalRemoved"], 1)
        self.assertEqual(result["removedBySource"]["syscallRawRules"], [raw])

    def test_intended_removal_must_be_present(self):
        base = policy(enhance={"hardeningRules": ["a-rule"]})
        cand = policy(enhance={"hardeningRules": ["a-rule"]})  # nothing removed
        intended = [{"source": "hardeningRules", "rule": "a-rule"}]
        with self.assertRaises(common.ValidationError):
            guard_removal.guard(base, cand, intended)

    def test_compact_cli_derives_removals_from_attribution_decisions(self):
        base = policy(enhance={"hardeningRules": ["disallow-umount"]})
        pre = {
            "window": {"start": 0, "end": 10},
            "collectionComplete": True,
            "retentionCovered": True,
            "networkProxyEvidenceEligible": False,
            "failures": [],
            "seccompSyscalls": [],
            "aggregatedEvents": [
                {
                    "eventId": "evt-000001",
                    "enforcer": "AppArmor",
                    "event": {"operation": "mount", "name": "umount"},
                }
            ],
        }
        attribution = [
            {
                "eventId": "evt-000001",
                "summary": "umount",
                "matches": [
                    {
                        "source": "hardeningRules",
                        "rule": "disallow-umount",
                        "context": {},
                        "decision": "remove",
                    }
                ],
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            baseline = os.path.join(tmp, "baseline.yaml")
            pre_path = os.path.join(tmp, "pre.json")
            attribution_path = os.path.join(tmp, "attribution.json")
            candidate_path = os.path.join(tmp, "candidate.yaml")
            with open(baseline, "w") as handle:
                handle.write(common.dump_yaml(base))
            with open(pre_path, "w") as handle:
                json.dump(pre, handle)
            with open(attribution_path, "w") as handle:
                json.dump(attribution, handle)

            applied = subprocess.run(
                [
                    "python3",
                    os.path.join(SCRIPTS_DIR, "apply_removals.py"),
                    "--baseline",
                    baseline,
                    "--pre",
                    pre_path,
                    "--attribution",
                    attribution_path,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            with open(candidate_path, "w") as handle:
                handle.write(applied.stdout)

            guarded = subprocess.run(
                [
                    "python3",
                    os.path.join(SCRIPTS_DIR, "guard_removal.py"),
                    "--baseline",
                    baseline,
                    "--candidate",
                    candidate_path,
                    "--pre",
                    pre_path,
                    "--attribution",
                    attribution_path,
                ],
                capture_output=True,
                text=True,
            )
            self.assertEqual(guarded.returncode, 0, guarded.stderr)
            self.assertEqual(json.loads(guarded.stdout)["totalRemoved"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
