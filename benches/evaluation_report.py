#!/usr/bin/env python3
"""Merge Covercrypt/LP-Covercrypt CSV files and generate paper table values."""

from __future__ import annotations

import argparse
import csv
import json
import platform
import subprocess
from collections import defaultdict
from pathlib import Path
from statistics import fmean


EXPECTED = {
    "pairs": 6241,
    "same": 2844,
    "different": 3397,
    "oracle_positive": 1135,
    "oracle_negative": 5106,
    "groups": {"TP_TP": 275, "TN_TN": 1680, "TN_FP": 1442},
}

DIMENSIONS = ("SEC", "DPT", "CTR")
SECURITY_RANK = {None: 0, "LOW": 1, "MED": 2, "HIG": 3, "$": 4}


def policy_coordinates(policy: str) -> dict[str, str | None]:
    """Parse one conjunction from the fixed paper corpus without Covercrypt."""
    coordinates: dict[str, str | None] = dict.fromkeys(DIMENSIONS)
    for term in policy.split(" && "):
        dimension, value = term.split("::", 1)
        if dimension not in coordinates or coordinates[dimension] is not None:
            raise ValueError(f"invalid corpus policy: {policy}")
        coordinates[dimension] = value
    return coordinates


def specification_allows(enc_policy: str, user_policy: str) -> bool:
    """Evaluate SpecAuth for the paper corpus independently of both compilers."""
    enc = policy_coordinates(enc_policy)
    user = policy_coordinates(user_policy)
    for dimension in DIMENSIONS:
        requirement = enc[dimension]
        grant = user[dimension]
        if dimension == "SEC":
            if SECURITY_RANK[grant] < SECURITY_RANK[requirement]:
                return False
        elif requirement is not None and grant != "$" and grant != requirement:
            return False
    return True


def read_csv(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    keyed = {(row["enc_ap"], row["user_ap"]): row for row in rows}
    if len(rows) != len(keyed):
        raise ValueError(f"{path}: duplicate policy pairs")
    return keyed


def average_us(rows: list[dict[str, str]], variant: str) -> float:
    return fmean(float(row[f"{variant}_mean_ns"]) for row in rows) / 1_000.0


def command_output(command: list[str], fallback: str = "unknown") -> str:
    try:
        return subprocess.check_output(command, text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return fallback


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def total_memory_gib() -> float | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemTotal:"):
                return round(int(line.split()[1]) / 1024 / 1024, 1)
    except OSError:
        pass
    return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--covercrypt", type=Path, required=True)
    parser.add_argument("--lp", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--merged", type=Path, required=True)
    parser.add_argument("--scenario", choices=["classic", "hybridized"], required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--pinned", choices=["0", "1"], default="0")
    args = parser.parse_args()

    cover = read_csv(args.covercrypt)
    lp = read_csv(args.lp)
    if cover.keys() != lp.keys():
        raise ValueError("the two variants did not benchmark identical policy pairs")
    if len(cover) != EXPECTED["pairs"]:
        raise ValueError(f"expected {EXPECTED['pairs']} pairs, got {len(cover)}")
    if {row["scenario"] for row in cover.values()} != {args.scenario}:
        raise ValueError("Covercrypt rows do not match the requested scenario")
    if {row["scenario"] for row in lp.values()} != {args.scenario}:
        raise ValueError("LP-Covercrypt rows do not match the requested scenario")

    merged: list[dict[str, str]] = []
    for pair in sorted(cover):
        c_row, lp_row = cover[pair], lp[pair]
        relation = c_row["y_relation"]
        if relation != lp_row["y_relation"]:
            raise ValueError(f"Y classification differs for {pair}")
        c_outcome = c_row["decryption_result"]
        lp_outcome = lp_row["decryption_result"]
        oracle_outcome = "success" if specification_allows(*pair) else "failure"
        if lp_outcome != oracle_outcome:
            raise ValueError(
                f"LP result disagrees with the independent oracle for {pair}: "
                f"oracle={oracle_outcome}, lp={lp_outcome}"
            )
        if relation == "same" and c_row["user_rights"] != lp_row["user_rights"]:
            raise ValueError(f"same-Y rights count differs for {pair}")
        if relation == "different" and int(c_row["user_rights"]) <= int(lp_row["user_rights"]):
            raise ValueError(f"Covercrypt did not have a larger Y for {pair}")

        if relation == "same" and c_outcome == oracle_outcome:
            group = "same"
        elif oracle_outcome == "success" and c_outcome == "success":
            group = "TP_TP"
        elif oracle_outcome == "failure" and c_outcome == "failure":
            group = "TN_TN"
        elif oracle_outcome == "failure" and c_outcome == "success":
            group = "TN_FP"
        else:
            group = "unexpected"

        merged.append(
            {
                "enc_ap": pair[0],
                "user_ap": pair[1],
                "y_relation": relation,
                "group": group,
                "oracle_outcome": oracle_outcome,
                "covercrypt_rights": c_row["user_rights"],
                "lp_rights": lp_row["user_rights"],
                "covercrypt_outcome": c_outcome,
                "lp_outcome": lp_outcome,
                "covercrypt_mean_ns": c_row["mean_ns"],
                "lp_mean_ns": lp_row["mean_ns"],
            }
        )

    with args.merged.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(merged[0]))
        writer.writeheader()
        writer.writerows(merged)

    same = [row for row in merged if row["group"] == "same"]
    different = [row for row in merged if row["y_relation"] == "different"]
    oracle_positive = [row for row in merged if row["oracle_outcome"] == "success"]
    oracle_negative = [row for row in merged if row["oracle_outcome"] == "failure"]
    grouped = defaultdict(list)
    for row in different:
        grouped[row["group"]].append(row)

    if len(same) != EXPECTED["same"] or len(different) != EXPECTED["different"]:
        raise ValueError("same/different Y pair counts do not match the paper corpus")
    if (
        len(oracle_positive) != EXPECTED["oracle_positive"]
        or len(oracle_negative) != EXPECTED["oracle_negative"]
    ):
        raise ValueError("independent oracle counts do not match the paper corpus")
    result_pairs = ["TP_TP", "TN_TN", "TN_FP"]
    actual_groups = {name: len(grouped[name]) for name in result_pairs}
    if actual_groups != EXPECTED["groups"] or grouped["unexpected"]:
        raise ValueError(
            f"outcome groups do not match the paper: {actual_groups}, "
            f"unexpected={len(grouped['unexpected'])}"
        )

    same_outcomes = {}
    for outcome in ["success", "failure"]:
        rows = [row for row in same if row["oracle_outcome"] == outcome]
        if any(row["covercrypt_outcome"] != outcome for row in rows):
            raise ValueError(f"same-Y {outcome} outcomes differ between variants")
        lp_us = average_us(rows, "lp")
        cover_us = average_us(rows, "covercrypt")
        same_outcomes[outcome] = {
            "pairs": len(rows),
            "lp_us": round(lp_us, 2),
            "covercrypt_us": round(cover_us, 2),
            "reduction_percent": round((cover_us - lp_us) / cover_us * 100, 2),
        }

    group_results = {}
    for name in result_pairs:
        rows = grouped[name]
        lp_us = average_us(rows, "lp")
        cover_us = average_us(rows, "covercrypt")
        group_results[name] = {
            "pairs": len(rows),
            "lp_us": round(lp_us, 2),
            "covercrypt_us": round(cover_us, 2),
            "reduction_percent": round((cover_us - lp_us) / cover_us * 100, 2),
        }

    iterations = int(next(iter(lp.values()))["iterations"])
    summary = {
        "scenario": args.scenario,
        "baseline_ref": next(iter(cover.values()))["baseline_ref"],
        "iterations_per_pair": iterations,
        "policy_corpus": {
            "ciphertext_policies": 79,
            "user_policies": 79,
            "pairs": len(merged),
            "oracle_positive_pairs": len(oracle_positive),
            "oracle_negative_pairs": len(oracle_negative),
            "same_y_pairs": len(same),
            "different_y_pairs": len(different),
        },
        "same_y": same_outcomes,
        "different_y": group_results,
        "environment": {
            "workers": args.workers,
            "workers_cpu_pinned": args.pinned == "1",
            "lp_git_head": command_output(["git", "rev-parse", "HEAD"]),
            "lp_worktree_dirty": bool(command_output(["git", "status", "--porcelain"], "")),
            "os": platform.platform(),
            "cpu": cpu_model(),
            "memory_gib": total_memory_gib(),
            "rustc": command_output(["rustc", "--version"]),
            "cargo": command_output(["cargo", "--version"]),
        },
    }
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
