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
    "pairs": 3713,
    "same": 1692,
    "different": 2021,
    "groups": {"A": 224, "B": 800, "C": 997},
}


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
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--pinned", choices=["0", "1"], default="0")
    args = parser.parse_args()

    cover = read_csv(args.covercrypt)
    lp = read_csv(args.lp)
    if cover.keys() != lp.keys():
        raise ValueError("the two variants did not benchmark identical policy pairs")
    if len(cover) != EXPECTED["pairs"]:
        raise ValueError(f"expected {EXPECTED['pairs']} pairs, got {len(cover)}")

    merged: list[dict[str, str]] = []
    for pair in sorted(cover):
        c_row, lp_row = cover[pair], lp[pair]
        relation = c_row["y_relation"]
        if relation != lp_row["y_relation"]:
            raise ValueError(f"Y classification differs for {pair}")
        c_outcome = c_row["decryption_result"]
        lp_outcome = lp_row["decryption_result"]
        if relation == "same" and c_row["user_rights"] != lp_row["user_rights"]:
            raise ValueError(f"same-Y rights count differs for {pair}")
        if relation == "different" and int(c_row["user_rights"]) <= int(lp_row["user_rights"]):
            raise ValueError(f"Covercrypt did not have a larger Y for {pair}")

        if relation == "same":
            group = "same"
        elif c_outcome == "success" and lp_outcome == "success":
            group = "A"
        elif c_outcome == "failure" and lp_outcome == "failure":
            group = "B"
        elif c_outcome == "success" and lp_outcome == "failure":
            group = "C"
        else:
            group = "unexpected"

        merged.append(
            {
                "enc_ap": pair[0],
                "user_ap": pair[1],
                "y_relation": relation,
                "group": group,
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
    grouped = defaultdict(list)
    for row in different:
        grouped[row["group"]].append(row)

    if len(same) != EXPECTED["same"] or len(different) != EXPECTED["different"]:
        raise ValueError("same/different Y pair counts do not match the paper corpus")
    actual_groups = {name: len(grouped[name]) for name in ["A", "B", "C"]}
    if actual_groups != EXPECTED["groups"] or grouped["unexpected"]:
        raise ValueError(
            f"outcome groups do not match the paper: {actual_groups}, "
            f"unexpected={len(grouped['unexpected'])}"
        )

    same_outcomes = {}
    for outcome in ["success", "failure"]:
        rows = [row for row in same if row["lp_outcome"] == outcome]
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
    for name in ["A", "B", "C"]:
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
        "baseline_ref": next(iter(cover.values()))["baseline_ref"],
        "iterations_per_pair": iterations,
        "policy_corpus": {
            "ciphertext_policies": 47,
            "user_policies": 79,
            "pairs": len(merged),
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
