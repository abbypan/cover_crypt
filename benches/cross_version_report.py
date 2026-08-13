#!/usr/bin/env python3
"""Validate and summarize cross-build Boolean and wire-compatibility results."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def write(path: str, value: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def index_cases(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = {case["name"]: case for case in document["cases"]}
    if len(cases) != len(document["cases"]):
        raise ValueError("duplicate Boolean case name")
    return cases


def boolean_report(baseline_path: str, lp_path: str) -> dict[str, Any]:
    baseline = load(baseline_path)
    lp = load(lp_path)
    if baseline["variant"] != "covercrypt" or lp["variant"] != "lp-covercrypt":
        raise ValueError("unexpected Boolean result variants")
    if baseline["complete_key_policies"] != lp["complete_key_policies"]:
        raise ValueError("complete-key corpus differs across builds")

    baseline_cases = index_cases(baseline)
    lp_cases = index_cases(lp)
    if set(baseline_cases) != set(lp_cases):
        raise ValueError("Boolean case corpus differs across builds")

    rows = []
    preservation = 0
    different_x = 0
    for name in baseline_cases:
        cc = baseline_cases[name]
        lp_case = lp_cases[name]
        if (cc["source"], cc["class"]) != (lp_case["source"], lp_case["class"]):
            raise ValueError(f"metadata differs for {name}")

        decisions_equal = None
        rights_equal = None
        if cc["accepted"] and lp_case["accepted"]:
            decisions_equal = cc["complete_key_decisions"] == lp_case["complete_key_decisions"]
            rights_equal = cc["canonical_rights"] == lp_case["canonical_rights"]

        if cc["class"] == "preservation":
            preservation += 1
            if not cc["accepted"] or not lp_case["accepted"] or not decisions_equal:
                raise ValueError(f"authorization preservation failed for {name}")
            if not rights_equal:
                different_x += 1
        elif cc["class"] == "rejected_input":
            if cc["accepted"] or lp_case["accepted"]:
                raise ValueError(f"unknown input was accepted for {name}")

        rows.append(
            {
                "name": name,
                "source": cc["source"],
                "class": cc["class"],
                "covercrypt_accepted": cc["accepted"],
                "lp_accepted": lp_case["accepted"],
                "authorization_decisions_equal": decisions_equal,
                "canonical_right_sets_equal": rights_equal,
                "covercrypt_rights": len(cc.get("canonical_rights", [])),
                "lp_rights": len(lp_case.get("canonical_rights", [])),
            }
        )

    if different_x == 0:
        raise ValueError("corpus did not exercise ciphertext minimization")

    return {
        "baseline_ref": "089a548",
        "complete_downward_closed_keys": len(baseline["complete_key_policies"]),
        "cases": len(rows),
        "preservation_cases": preservation,
        "authorization_equivalent_on_preservation_cases": True,
        "preservation_cases_with_different_canonical_x": different_x,
        "intentional_language_changes": [
            row for row in rows if row["class"] == "intentional_language_change"
        ],
        "rows": rows,
    }


def compatibility_report(paths: list[str]) -> dict[str, Any]:
    documents = [load(path) for path in paths]
    expected_keys = {
        (scenario, producer, consumer)
        for scenario in ("classic", "hybridized")
        for producer in ("covercrypt", "lp-covercrypt")
        for consumer in ("covercrypt", "lp-covercrypt")
    }
    actual_keys = {
        (doc["scenario"], doc["producer"], doc["consumer"]) for doc in documents
    }
    if actual_keys != expected_keys or len(documents) != len(expected_keys):
        raise ValueError("compatibility matrix is incomplete or contains duplicates")

    for doc in documents:
        same = doc["producer"] == doc["consumer"]
        stateful = doc["stateful_objects"]
        observed = (
            stateful["access_structure_deserialized"],
            stateful["msk_deserialized"],
            stateful["mpk_deserialized"],
        )
        if observed != (same, same, same):
            raise ValueError(f"unexpected stateful compatibility in {doc}")
        wire = doc["stateless_wire_objects"]
        if not wire["usk_deserialized"] or not wire["pke_ciphertexts_deserialized"]:
            raise ValueError("USK or PKE wire deserialization failed")
        if any(row["actual"] != row["expected"] for row in wire["decisions"]):
            raise ValueError("cross-version authorization decision mismatch")

    def decision(
        scenario: str, producer: str, consumer: str, case: str
    ) -> bool:
        document = next(
            doc
            for doc in documents
            if (doc["scenario"], doc["producer"], doc["consumer"])
            == (scenario, producer, consumer)
        )
        return next(
            row["actual"]
            for row in document["stateless_wire_objects"]["decisions"]
            if row["case"] == case
        )

    for scenario in ("classic", "hybridized"):
        if not decision(
            scenario,
            "covercrypt",
            "lp-covercrypt",
            "omitted_key_concrete_dimension",
        ):
            raise ValueError("legacy v15 omission key unexpectedly narrowed")
        if decision(
            scenario,
            "lp-covercrypt",
            "covercrypt",
            "omitted_key_concrete_dimension",
        ):
            raise ValueError("LP omission key unexpectedly broadened")

    documents.sort(key=lambda doc: (doc["scenario"], doc["producer"], doc["consumer"]))
    return {
        "baseline_ref": "089a548",
        "rows": len(documents),
        "scenarios": ["classic", "hybridized"],
        "stateful_objects_same_version_only": ["AccessStructure", "MSK", "MPK"],
        "cross_version_wire_objects": ["USK", "PKE ciphertext"],
        "all_expected_decisions_observed": True,
        "legacy_v15_omission_key_remains_broad_when_consumed_by_lp": True,
        "lp_omission_key_remains_closed_when_consumed_by_v15": True,
        "matrix": documents,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-boolean", required=True)
    parser.add_argument("--lp-boolean", required=True)
    parser.add_argument("--compatibility", nargs="+", required=True)
    parser.add_argument("--boolean-output", required=True)
    parser.add_argument("--matrix-output", required=True)
    args = parser.parse_args()

    boolean = boolean_report(args.baseline_boolean, args.lp_boolean)
    matrix = compatibility_report(args.compatibility)
    write(args.boolean_output, boolean)
    write(args.matrix_output, matrix)
    print(json.dumps({"boolean": boolean, "compatibility": matrix}, indent=2))


if __name__ == "__main__":
    main()
