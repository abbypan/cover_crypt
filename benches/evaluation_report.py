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
from statistics import fmean, median


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


def ciphertext_rights(
    rows: dict[tuple[str, str], dict[str, str]], variant: str
) -> dict[str, str] | None:
    """Return one stable canonical ciphertext-right encoding per source policy."""
    if "ciphertext_rights_hex" not in next(iter(rows.values())):
        return None
    compiled: dict[str, str] = {}
    for (enc_policy, _), row in rows.items():
        encoded = row["ciphertext_rights_hex"]
        previous = compiled.setdefault(enc_policy, encoded)
        if previous != encoded:
            raise ValueError(
                f"{variant} compiled {enc_policy!r} inconsistently across key pairs"
            )
    return compiled


def average_us(rows: list[dict[str, str]], variant: str) -> float:
    """Unweighted mean of the fixed-count timed-loop mean for each policy pair."""
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
    parser.add_argument(
        "--environment-from-summary",
        type=Path,
        help=(
            "reuse environment metadata from an existing summary when "
            "regenerating a historical raw-data artifact"
        ),
    )
    args = parser.parse_args()

    preserved_environment = None
    if args.environment_from_summary is not None:
        preserved_summary = json.loads(
            args.environment_from_summary.read_text(encoding="utf-8")
        )
        if preserved_summary.get("scenario") != args.scenario:
            raise ValueError("environment summary scenario does not match --scenario")
        preserved_environment = preserved_summary["environment"]

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

    cover_iterations = {int(row["iterations"]) for row in cover.values()}
    lp_iterations = {int(row["iterations"]) for row in lp.values()}
    if len(cover_iterations) != 1 or cover_iterations != lp_iterations:
        raise ValueError(
            "all policy pairs and both variants must use one identical iteration count"
        )

    cover_x = ciphertext_rights(cover, "Covercrypt")
    lp_x = ciphertext_rights(lp, "LP-Covercrypt")
    if (cover_x is None) != (lp_x is None):
        raise ValueError("only one raw CSV records canonical ciphertext rights")
    if cover_x is not None and lp_x is not None:
        if len(cover_x) != 79 or len(lp_x) != 79:
            raise ValueError(
                "expected 79 distinct ciphertext policies in each implementation"
            )
        ciphertext_compiler_observation = {
            "recorded": True,
            "scope": "79 normalized single-conjunction policies",
            "policies_checked": len(cover_x),
            "canonical_right_sets_equal_on_corpus": cover_x == lp_x,
        }
    else:
        ciphertext_compiler_observation = {
            "recorded": False,
            "scope": "canonical ciphertext rights absent from historical raw CSV schema",
            "policies_checked": 0,
            "canonical_right_sets_equal_on_corpus": None,
        }

    implementation_policy_recorded = all(
        "implementation_user_ap" in next(iter(rows.values()))
        for rows in (cover, lp)
    )
    if implementation_policy_recorded != any(
        "implementation_user_ap" in next(iter(rows.values()))
        for rows in (cover, lp)
    ):
        raise ValueError("only one raw CSV records implementation policy text")

    merged: list[dict[str, str]] = []
    for pair in sorted(cover):
        c_row, lp_row = cover[pair], lp[pair]
        relation = c_row["y_relation"]
        if relation != lp_row["y_relation"]:
            raise ValueError(f"Y classification differs for {pair}")
        c_outcome = c_row["decryption_result"]
        lp_outcome = lp_row["decryption_result"]
        expected_baseline_policy = (
            pair[1]
            .replace("DPT::$", "(DPT::DEV || DPT::MKG || DPT::$)")
            .replace("CTR::$", "(CTR::EN || CTR::FR || CTR::$)")
        )
        if implementation_policy_recorded:
            if c_row["implementation_user_ap"] != expected_baseline_policy:
                raise ValueError(f"unexpected baseline policy translation for {pair}")
            if lp_row["implementation_user_ap"] != pair[1]:
                raise ValueError(f"LP implementation policy differs from source for {pair}")
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
                "covercrypt_implementation_user_ap": c_row.get(
                    "implementation_user_ap", ""
                ),
                "lp_implementation_user_ap": lp_row.get(
                    "implementation_user_ap", ""
                ),
                "covercrypt_ciphertext_rights_hex": (
                    cover_x[pair[0]] if cover_x is not None else ""
                ),
                "lp_ciphertext_rights_hex": (
                    lp_x[pair[0]] if lp_x is not None else ""
                ),
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
        writer = csv.DictWriter(
            stream, fieldnames=list(merged[0]), lineterminator="\n"
        )
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

    user_metrics: dict[str, tuple[str, int, int, int, int]] = {}
    for row in merged:
        pair = (row["enc_ap"], row["user_ap"])
        metrics = (
            row["y_relation"],
            int(row["covercrypt_rights"]),
            int(row["lp_rights"]),
            int(cover[pair]["user_key_bytes"]),
            int(lp[pair]["user_key_bytes"]),
        )
        previous = user_metrics.setdefault(row["user_ap"], metrics)
        if previous != metrics:
            raise ValueError(f"inconsistent key metrics for {row['user_ap']!r}")

    ciphertext_metrics: dict[str, tuple[int, int]] = {}
    for row in merged:
        pair = (row["enc_ap"], row["user_ap"])
        metrics = (
            int(cover[pair]["ciphertext_bytes"]),
            int(lp[pair]["ciphertext_bytes"]),
        )
        previous = ciphertext_metrics.setdefault(row["enc_ap"], metrics)
        if previous != metrics:
            raise ValueError(
                f"inconsistent ciphertext sizes for {row['enc_ap']!r}"
            )

    all_user_metrics = list(user_metrics.values())
    different_user_metrics = [
        metrics for metrics in all_user_metrics if metrics[0] == "different"
    ]
    if len(all_user_metrics) != 79 or len(different_user_metrics) != 43:
        raise ValueError("unexpected unique user-policy counts")

    def reduction_percent(baseline: float, lp: float) -> float:
        return round((baseline - lp) / baseline * 100, 2)

    cover_rights_all = fmean(row[1] for row in all_user_metrics)
    lp_rights_all = fmean(row[2] for row in all_user_metrics)
    cover_rights_different = fmean(row[1] for row in different_user_metrics)
    lp_rights_different = fmean(row[2] for row in different_user_metrics)
    cover_key_bytes_all = fmean(row[3] for row in all_user_metrics)
    lp_key_bytes_all = fmean(row[4] for row in all_user_metrics)
    cover_key_bytes_different = fmean(row[3] for row in different_user_metrics)
    lp_key_bytes_different = fmean(row[4] for row in different_user_metrics)
    cover_ciphertext_bytes = fmean(row[0] for row in ciphertext_metrics.values())
    lp_ciphertext_bytes = fmean(row[1] for row in ciphertext_metrics.values())
    compiled_policy_and_sizes = {
        "unique_user_policies": len(all_user_metrics),
        "different_y_user_policies": len(different_user_metrics),
        "mean_rights_all": {
            "covercrypt": round(cover_rights_all, 2),
            "lp": round(lp_rights_all, 2),
            "reduction_percent": reduction_percent(cover_rights_all, lp_rights_all),
        },
        "mean_rights_different_y": {
            "covercrypt": round(cover_rights_different, 2),
            "lp": round(lp_rights_different, 2),
            "reduction_percent": reduction_percent(
                cover_rights_different, lp_rights_different
            ),
        },
        "median_rights_different_y": {
            "covercrypt": round(median(row[1] for row in different_user_metrics), 2),
            "lp": round(median(row[2] for row in different_user_metrics), 2),
        },
        "mean_user_key_bytes_all": {
            "covercrypt": round(cover_key_bytes_all, 2),
            "lp": round(lp_key_bytes_all, 2),
            "reduction_percent": reduction_percent(
                cover_key_bytes_all, lp_key_bytes_all
            ),
        },
        "mean_user_key_bytes_different_y": {
            "covercrypt": round(cover_key_bytes_different, 2),
            "lp": round(lp_key_bytes_different, 2),
            "reduction_percent": reduction_percent(
                cover_key_bytes_different, lp_key_bytes_different
            ),
        },
        "mean_ciphertext_bytes": {
            "covercrypt": round(cover_ciphertext_bytes, 2),
            "lp": round(lp_ciphertext_bytes, 2),
            "reduction_percent": reduction_percent(
                cover_ciphertext_bytes, lp_ciphertext_bytes
            ),
        },
    }

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

    native = [
        row
        for row in merged
        if "$" not in row["enc_ap"] and "$" not in row["user_ap"]
    ]
    native_enc_policies = {row["enc_ap"] for row in native}
    native_user_policies = {row["user_ap"] for row in native}
    if (
        len(native_enc_policies) != 35
        or len(native_user_policies) != 35
        or len(native) != 1_225
    ):
        raise ValueError("unexpected v15-native sensitivity corpus size")

    native_user_metrics: dict[str, tuple[int, int, int, int]] = {}
    for row in native:
        pair = (row["enc_ap"], row["user_ap"])
        metrics = (
            int(row["covercrypt_rights"]),
            int(row["lp_rights"]),
            int(cover[pair]["user_key_bytes"]),
            int(lp[pair]["user_key_bytes"]),
        )
        previous = native_user_metrics.setdefault(row["user_ap"], metrics)
        if previous != metrics:
            raise ValueError(f"inconsistent key metrics for {row['user_ap']!r}")

    native_oracle_positive = sum(
        row["oracle_outcome"] == "success" for row in native
    )
    native_oracle_negative = len(native) - native_oracle_positive
    native_cover_fp = sum(
        row["oracle_outcome"] == "failure"
        and row["covercrypt_outcome"] == "success"
        for row in native
    )
    native_lp_fp = sum(
        row["oracle_outcome"] == "failure" and row["lp_outcome"] == "success"
        for row in native
    )
    if (
        native_oracle_positive != 214
        or native_oracle_negative != 1_011
        or native_cover_fp != 352
        or native_lp_fp != 0
    ):
        raise ValueError("unexpected v15-native sensitivity outcomes")

    native_metric_rows = list(native_user_metrics.values())
    cover_rights = fmean(row[0] for row in native_metric_rows)
    lp_rights = fmean(row[1] for row in native_metric_rows)
    cover_bytes = fmean(row[2] for row in native_metric_rows)
    lp_bytes = fmean(row[3] for row in native_metric_rows)
    native_sensitivity = {
        "criterion": "both source policies contain no dimension-local maximum '$'",
        "ciphertext_policies": len(native_enc_policies),
        "user_policies": len(native_user_policies),
        "pairs": len(native),
        "oracle_positive_pairs": native_oracle_positive,
        "oracle_negative_pairs": native_oracle_negative,
        "covercrypt_false_positive_pairs": native_cover_fp,
        "lp_false_positive_pairs": native_lp_fp,
        "covercrypt_oracle_relative_precision_percent": round(
            native_oracle_positive / (native_oracle_positive + native_cover_fp) * 100,
            2,
        ),
        "lp_oracle_relative_precision_percent": 100.0,
        "unique_user_policy_mean_rights": {
            "covercrypt": round(cover_rights, 2),
            "lp": round(lp_rights, 2),
            "reduction_percent": round(
                (cover_rights - lp_rights) / cover_rights * 100, 2
            ),
        },
        "unique_user_policy_mean_key_bytes": {
            "covercrypt": round(cover_bytes, 2),
            "lp": round(lp_bytes, 2),
            "reduction_percent": round(
                (cover_bytes - lp_bytes) / cover_bytes * 100, 2
            ),
        },
    }

    iterations = lp_iterations.pop()
    oracle_relative_enforcement = {
        "covercrypt": {
            "true_positive": len(oracle_positive),
            "false_positive": len(grouped["TN_FP"]),
            "true_negative": len(oracle_negative) - len(grouped["TN_FP"]),
            "false_negative": 0,
            "precision_percent": round(
                len(oracle_positive)
                / (len(oracle_positive) + len(grouped["TN_FP"]))
                * 100,
                2,
            ),
        },
        "lp": {
            "true_positive": len(oracle_positive),
            "false_positive": 0,
            "true_negative": len(oracle_negative),
            "false_negative": 0,
            "precision_percent": 100.0,
        },
    }
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
        "raw_schema_evidence": {
            "implementation_policy_recorded": implementation_policy_recorded,
        },
        "ciphertext_compiler_observation": ciphertext_compiler_observation,
        "compiled_policy_and_sizes": compiled_policy_and_sizes,
        "oracle_relative_enforcement": oracle_relative_enforcement,
        "same_y": same_outcomes,
        "different_y": group_results,
        "v15_native_sensitivity": native_sensitivity,
        "environment": preserved_environment
        or {
            "workers": args.workers,
            "workers_cpu_pinned": args.pinned == "1",
            "lp_git_head": command_output(["git", "rev-parse", "HEAD"]),
            "lp_worktree_dirty": bool(
                command_output(
                    [
                        "git",
                        "status",
                        "--porcelain",
                        "--untracked-files=all",
                        "--",
                        ".",
                        ":(exclude)benchmark-results/**",
                    ],
                    "",
                )
            ),
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
