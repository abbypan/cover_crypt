#!/usr/bin/env python3
"""Validate and summarize cross-build Boolean and wire-compatibility results."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
from pathlib import Path
from typing import Any


DIMENSIONS = ("SEC", "DPT", "CTR")
COORDINATE_VALUES: dict[str, tuple[str | None, ...]] = {
    "SEC": (None, "LOW", "MED", "HIG", "$"),
    "DPT": (None, "DEV", "MKG", "$"),
    "CTR": (None, "EN", "FR", "$"),
}


def load(path: str) -> dict[str, Any]:
    with Path(path).open(encoding="utf-8") as stream:
        return json.load(stream)


def write(path: str, value: dict[str, Any]) -> None:
    with Path(path).open("w", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def sha256(path: str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def policy_coordinates(source: str) -> dict[str, str | None]:
    coordinates: dict[str, str | None] = dict.fromkeys(DIMENSIONS)
    for term in source.split(" && "):
        dimension, value = term.split("::", 1)
        if dimension not in coordinates or coordinates[dimension] is not None:
            raise ValueError(f"invalid normalized key policy: {source}")
        coordinates[dimension] = value
    return coordinates


def expected_key_coordinates(
    source: str, *, unrestricted_completion: bool
) -> set[tuple[str | None, ...]]:
    policy = policy_coordinates(source)
    dimension_values = []
    for dimension in DIMENSIONS:
        value = policy[dimension]
        universe = COORDINATE_VALUES[dimension]
        if value is None:
            allowed = universe if unrestricted_completion else (None,)
        elif dimension == "SEC":
            allowed = universe[: universe.index(value) + 1]
        elif value == "$":
            allowed = universe
        else:
            allowed = (None, value)
        dimension_values.append(allowed)
    return set(itertools.product(*dimension_values))


def index_probes(document: dict[str, Any]) -> dict[tuple[str | None, ...], str]:
    probes: dict[tuple[str | None, ...], str] = {}
    for row in document["coordinate_probes"]:
        coordinate = tuple(row["coordinates"][dimension] for dimension in DIMENSIONS)
        if coordinate in probes:
            raise ValueError(f"duplicate coordinate probe: {coordinate}")
        probes[coordinate] = row["encoded_right"]
    if len(probes) != 80 or len(set(probes.values())) != 80:
        raise ValueError("coordinate probes do not encode the 80-right universe injectively")
    return probes


def index_keys(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    keys = {row["source"]: row for row in document["keys"]}
    if len(keys) != 79 or len(keys) != len(document["keys"]):
        raise ValueError("expected 79 distinct normalized key policies")
    return keys


def key_rights_report(
    baseline_path: str,
    lp_path: str,
    rust_generator: str,
    lp_ref: str,
    lp_worktree_dirty: bool,
) -> dict[str, Any]:
    baseline = load(baseline_path)
    lp = load(lp_path)
    if baseline["variant"] != "covercrypt" or lp["variant"] != "lp-covercrypt":
        raise ValueError("unexpected key-right result variants")
    if baseline["scenario"] != "classic" or lp["scenario"] != "classic":
        raise ValueError("key-right validation must use the Classic encoder")

    baseline_probes = index_probes(baseline)
    lp_probes = index_probes(lp)
    if baseline_probes != lp_probes:
        raise ValueError("the two builds do not share the same coordinate encoding")

    baseline_keys = index_keys(baseline)
    lp_keys = index_keys(lp)
    if set(baseline_keys) != set(lp_keys):
        raise ValueError("normalized key corpus differs across builds")

    rows = []
    for source in baseline_keys:
        expected_unrestricted = sorted(
            baseline_probes[coordinate]
            for coordinate in expected_key_coordinates(
                source, unrestricted_completion=True
            )
        )
        expected_lp = sorted(
            lp_probes[coordinate]
            for coordinate in expected_key_coordinates(
                source, unrestricted_completion=False
            )
        )
        actual_baseline = sorted(baseline_keys[source]["encoded_rights"])
        actual_lp = sorted(lp_keys[source]["encoded_rights"])
        baseline_equal = actual_baseline == expected_unrestricted
        lp_equal = actual_lp == expected_lp
        if not baseline_equal or not lp_equal:
            raise ValueError(
                f"encoded key-right equality failed for {source}: "
                f"covercrypt={baseline_equal}, lp={lp_equal}"
            )
        rows.append(
            {
                "source": source,
                "covercrypt_implementation_source": baseline_keys[source][
                    "implementation_source"
                ],
                "lp_implementation_source": lp_keys[source]["implementation_source"],
                "expected_unrestricted_encoded_rights": expected_unrestricted,
                "covercrypt_encoded_rights": actual_baseline,
                "covercrypt_set_equal": baseline_equal,
                "expected_default_minimal_encoded_rights": expected_lp,
                "lp_encoded_rights": actual_lp,
                "lp_set_equal": lp_equal,
            }
        )

    return {
        "baseline_ref": "089a548",
        "lp_ref": lp_ref,
        "lp_git_head": lp_ref,
        "lp_worktree_dirty": lp_worktree_dirty,
        "scenario": "classic",
        "coordinate_universe_rights": len(baseline_probes),
        "normalized_key_policies": len(rows),
        "shared_coordinate_encoding": True,
        "all_covercrypt_sets_equal_independent_unrestricted_model": True,
        "all_lp_sets_equal_independent_default_minimal_model": True,
        "generator_files_sha256": {
            Path(rust_generator).name: sha256(rust_generator),
            Path(__file__).name: sha256(__file__),
        },
        "rows": rows,
    }


def index_cases(document: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = {case["name"]: case for case in document["cases"]}
    if len(cases) != len(document["cases"]):
        raise ValueError("duplicate Boolean case name")
    return cases


def boolean_report(
    baseline_path: str,
    lp_path: str,
    lp_ref: str,
    lp_worktree_dirty: bool,
) -> dict[str, Any]:
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
        "lp_git_head": lp_ref,
        "lp_worktree_dirty": lp_worktree_dirty,
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


def compatibility_report(
    paths: list[str], lp_ref: str, lp_worktree_dirty: bool
) -> dict[str, Any]:
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
        "lp_git_head": lp_ref,
        "lp_worktree_dirty": lp_worktree_dirty,
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
    parser.add_argument("--baseline-key-rights", required=True)
    parser.add_argument("--lp-key-rights", required=True)
    parser.add_argument("--rust-generator", required=True)
    parser.add_argument("--lp-ref", required=True)
    parser.add_argument("--lp-worktree-dirty", choices=("true", "false"), required=True)
    parser.add_argument("--compatibility", nargs="+", required=True)
    parser.add_argument("--boolean-output", required=True)
    parser.add_argument("--key-rights-output", required=True)
    parser.add_argument("--matrix-output", required=True)
    args = parser.parse_args()

    lp_worktree_dirty = args.lp_worktree_dirty == "true"
    boolean = boolean_report(
        args.baseline_boolean,
        args.lp_boolean,
        args.lp_ref,
        lp_worktree_dirty,
    )
    key_rights = key_rights_report(
        args.baseline_key_rights,
        args.lp_key_rights,
        args.rust_generator,
        args.lp_ref,
        lp_worktree_dirty,
    )
    matrix = compatibility_report(
        args.compatibility, args.lp_ref, lp_worktree_dirty
    )
    write(args.boolean_output, boolean)
    write(args.key_rights_output, key_rights)
    write(args.matrix_output, matrix)
    print(
        json.dumps(
            {
                "outputs": {
                    "boolean": args.boolean_output,
                    "key_rights": args.key_rights_output,
                    "compatibility": args.matrix_output,
                },
                "validated": {
                    "boolean_preservation_cases": boolean["preservation_cases"],
                    "encoded_key_sets": key_rights["normalized_key_policies"],
                    "coordinate_universe_rights": key_rights[
                        "coordinate_universe_rights"
                    ],
                    "compatibility_rows": matrix["rows"],
                },
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
