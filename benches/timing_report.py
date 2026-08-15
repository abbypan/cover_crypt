#!/usr/bin/env python3
"""Select a balanced timing corpus and summarize replicated paired batches."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import platform
import random
import subprocess
from collections import defaultdict
from pathlib import Path
from statistics import fmean, stdev


STRATA = (
    "same_success",
    "same_failure",
    "diff_tp_tp",
    "diff_tn_tn",
    "diff_tn_fp",
)
T_CRITICAL_975 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    21: 2.080,
    22: 2.074,
    23: 2.069,
    24: 2.064,
    25: 2.060,
    26: 2.056,
    27: 2.052,
    28: 2.048,
    29: 2.045,
}


def row_stratum(row: dict[str, str]) -> str:
    if row["group"] == "same":
        return f"same_{row['oracle_outcome']}"
    mapping = {"TP_TP": "diff_tp_tp", "TN_TN": "diff_tn_tn", "TN_FP": "diff_tn_fp"}
    try:
        return mapping[row["group"]]
    except KeyError as error:
        raise ValueError(f"unexpected full-corpus group: {row['group']}") from error


def read_dict_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


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


def select(args: argparse.Namespace) -> None:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in read_dict_rows(args.pairs):
        grouped[row_stratum(row)].append(row)
    if set(grouped) != set(STRATA):
        raise ValueError(f"missing timing strata: {set(STRATA) - set(grouped)}")

    rng = random.Random(args.seed)
    selected: list[tuple[str, str, str]] = []
    for stratum in STRATA:
        candidates = sorted(grouped[stratum], key=lambda row: (row["enc_ap"], row["user_ap"]))
        if len(candidates) < args.per_stratum:
            raise ValueError(f"{stratum} has only {len(candidates)} candidates")
        for row in sorted(
            rng.sample(candidates, args.per_stratum),
            key=lambda row: (row["enc_ap"], row["user_ap"]),
        ):
            selected.append((row["enc_ap"], row["user_ap"], stratum))

    with args.output.open("w", encoding="utf-8", newline="") as stream:
        stream.write("enc_ap\tuser_ap\tstratum\n")
        for enc_ap, user_ap, stratum in selected:
            stream.write(f"{enc_ap}\t{user_ap}\t{stratum}\n")


def read_selection(path: Path) -> dict[tuple[str, str], str]:
    selected: dict[tuple[str, str], str] = {}
    with path.open(encoding="utf-8") as stream:
        header = stream.readline().rstrip("\n")
        if header != "enc_ap\tuser_ap\tstratum":
            raise ValueError(f"{path}: unexpected TSV header")
        for line_number, line in enumerate(stream, 2):
            enc_ap, user_ap, stratum = line.rstrip("\n").split("\t")
            if stratum not in STRATA:
                raise ValueError(f"{path}:{line_number}: unknown stratum")
            pair = (enc_ap, user_ap)
            if pair in selected:
                raise ValueError(f"{path}:{line_number}: duplicate pair")
            selected[pair] = stratum
    return selected


def mean_ci(values: list[float]) -> dict[str, float]:
    if len(values) < 2:
        raise ValueError("at least two batches are required for a confidence interval")
    mean = fmean(values)
    critical = T_CRITICAL_975.get(len(values) - 1, 1.96)
    half = critical * stdev(values) / math.sqrt(len(values))
    return {
        "mean": round(mean, 2),
        "ci95_low": round(mean - half, 2),
        "ci95_high": round(mean + half, 2),
    }


def keyed_raw(path: Path) -> dict[tuple[str, str], dict[str, str]]:
    rows = read_dict_rows(path)
    keyed = {(row["enc_ap"], row["user_ap"]): row for row in rows}
    if len(rows) != len(keyed):
        raise ValueError(f"{path}: duplicate policy pairs")
    return keyed


def summarize(args: argparse.Namespace) -> None:
    selection = read_selection(args.pairs)
    expected_per_stratum = {name: 0 for name in STRATA}
    for stratum in selection.values():
        expected_per_stratum[stratum] += 1
    if len(set(expected_per_stratum.values())) != 1:
        raise ValueError("selection is not balanced across strata")

    batch_rows: list[dict[str, object]] = []
    batch_metrics: dict[tuple[str, int, str], dict[str, float]] = {}
    iteration_counts: set[int] = set()
    warm_order_counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))

    for scenario in ("classic", "hybridized"):
        for batch in range(1, args.batches + 1):
            prefix = f"timing-b{batch:02d}-{scenario}"
            cover = keyed_raw(args.results_dir / f"{prefix}-covercrypt.csv")
            lp = keyed_raw(args.results_dir / f"{prefix}-lp-covercrypt.csv")
            if set(cover) != set(selection) or set(lp) != set(selection):
                raise ValueError(f"{prefix}: raw pairs differ from timing selection")
            cover_positions = {int(row["order_position"]) for row in cover.values()}
            lp_positions = {int(row["order_position"]) for row in lp.values()}
            if len(cover_positions) != 1 or len(lp_positions) != 1:
                raise ValueError(f"{prefix}: inconsistent order positions")
            cover_position = cover_positions.pop()
            lp_position = lp_positions.pop()
            if {cover_position, lp_position} != {1, 2}:
                raise ValueError(f"{prefix}: variants are not a paired two-position batch")
            first = "covercrypt" if cover_position == 1 else "lp-covercrypt"
            warm_order_counts[scenario][first] += 1

            for rows, variant in ((cover, "covercrypt"), (lp, "lp-covercrypt")):
                if {int(row["batch_id"]) for row in rows.values()} != {batch}:
                    raise ValueError(f"{prefix}: wrong {variant} batch identifier")
                iteration_counts.update(int(row["iterations"]) for row in rows.values())
                if {row["scenario"] for row in rows.values()} != {scenario}:
                    raise ValueError(f"{prefix}: scenario mismatch")

            for stratum in STRATA:
                pairs = [pair for pair, value in selection.items() if value == stratum]
                cover_us = fmean(float(cover[pair]["mean_ns"]) for pair in pairs) / 1_000
                lp_us = fmean(float(lp[pair]["mean_ns"]) for pair in pairs) / 1_000
                reduction = (cover_us - lp_us) / cover_us * 100
                metrics = {
                    "covercrypt_us": cover_us,
                    "lp_us": lp_us,
                    "reduction_percent": reduction,
                }
                batch_metrics[(scenario, batch, stratum)] = metrics
                batch_rows.append(
                    {
                        "scenario": scenario,
                        "batch": batch,
                        "first_variant": first,
                        "stratum": stratum,
                        "sampled_pairs": len(pairs),
                        "covercrypt_us": f"{cover_us:.3f}",
                        "lp_us": f"{lp_us:.3f}",
                        "reduction_percent": f"{reduction:.3f}",
                        "control_adjusted_reduction_percent": "",
                    }
                )

            controls = {"diff_tp_tp": "same_success", "diff_tn_tn": "same_failure"}
            for stratum, control in controls.items():
                metric = batch_metrics[(scenario, batch, stratum)]
                control_metric = batch_metrics[(scenario, batch, control)]
                adjusted = 100 * (
                    1
                    - (metric["lp_us"] / metric["covercrypt_us"])
                    / (control_metric["lp_us"] / control_metric["covercrypt_us"])
                )
                metric["control_adjusted_reduction_percent"] = adjusted
                for row in reversed(batch_rows):
                    if (
                        row["scenario"] == scenario
                        and row["batch"] == batch
                        and row["stratum"] == stratum
                    ):
                        row["control_adjusted_reduction_percent"] = f"{adjusted:.3f}"
                        break

    if len(iteration_counts) != 1:
        raise ValueError(f"inconsistent iteration counts: {iteration_counts}")
    for scenario, counts in warm_order_counts.items():
        if abs(counts["covercrypt"] - counts["lp-covercrypt"]) > 1:
            raise ValueError(f"{scenario}: implementation order is not balanced")

    with args.batch_output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(batch_rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(batch_rows)

    results: dict[str, dict[str, object]] = {}
    for scenario in ("classic", "hybridized"):
        scenario_results: dict[str, object] = {}
        for stratum in STRATA:
            metrics = [batch_metrics[(scenario, batch, stratum)] for batch in range(1, args.batches + 1)]
            reduction_values = [metric["reduction_percent"] for metric in metrics]
            entry: dict[str, object] = {
                "sampled_pairs": expected_per_stratum[stratum],
                "covercrypt_us_mean_of_batches": round(fmean(metric["covercrypt_us"] for metric in metrics), 2),
                "lp_us_mean_of_batches": round(fmean(metric["lp_us"] for metric in metrics), 2),
                "paired_reduction_percent": mean_ci(reduction_values),
                "reduction_by_first_variant": {
                    first: round(
                        fmean(
                            batch_metrics[(scenario, batch, stratum)]["reduction_percent"]
                            for batch in range(1, args.batches + 1)
                            if ("covercrypt" if batch % 2 == 1 else "lp-covercrypt") == first
                        ),
                        2,
                    )
                    for first in ("covercrypt", "lp-covercrypt")
                },
            }
            adjusted_values = [
                metric["control_adjusted_reduction_percent"]
                for metric in metrics
                if "control_adjusted_reduction_percent" in metric
            ]
            if adjusted_values:
                entry["control_adjusted_reduction_percent"] = mean_ci(adjusted_values)
            scenario_results[stratum] = entry
        results[scenario] = scenario_results

    digest = hashlib.sha256(args.pairs.read_bytes()).hexdigest()
    source_manifest_bytes = args.source_manifest.read_bytes()
    source_manifest_digest = hashlib.sha256(source_manifest_bytes).hexdigest()
    source_metadata = json.loads(source_manifest_bytes)
    if source_metadata.get("schema") != "lp-covercrypt-timing-source-v1":
        raise ValueError("unexpected timing source-manifest schema")
    if not isinstance(source_metadata.get("git_head"), str):
        raise ValueError("timing source manifest has no git_head")
    if not isinstance(source_metadata.get("git_worktree_dirty"), bool):
        raise ValueError("timing source manifest has no worktree state")
    summary = {
        "design": {
            "replicated_batches": args.batches,
            "workers": 1,
            "warmup_decryptions_per_pair_per_batch": args.warmup,
            "timed_iterations_per_pair_per_batch": iteration_counts.pop(),
            "sampled_pairs_per_stratum": next(iter(expected_per_stratum.values())),
            "strata": list(STRATA),
            "variant_order": "alternating and balanced within each scenario",
            "scenario_order": "alternating across batches",
            "confidence_interval": "two-sided 95% Student-t interval over paired batch reductions",
            "selection_sha256": digest,
            "selection_seed": args.selection_seed,
            "source_manifest": args.source_manifest.name,
            "source_manifest_sha256": source_manifest_digest,
            "cpu_pinned": args.pin_cpu != "",
            "pinned_cpu": int(args.pin_cpu) if args.pin_cpu != "" else None,
            "source_state_captured_before_results": True,
        },
        "results": results,
        "environment": {
            "os": platform.platform(),
            "cpu": cpu_model(),
            "rustc": command_output(["rustc", "--version"]),
            "cargo": command_output(["cargo", "--version"]),
            "lp_git_head": source_metadata["git_head"],
            "lp_worktree_dirty": source_metadata["git_worktree_dirty"],
        },
    }
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    select_parser = subparsers.add_parser("select")
    select_parser.add_argument("--pairs", type=Path, required=True)
    select_parser.add_argument("--output", type=Path, required=True)
    select_parser.add_argument("--per-stratum", type=int, default=20)
    select_parser.add_argument("--seed", type=int, default=20260813)
    select_parser.set_defaults(func=select)

    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--results-dir", type=Path, required=True)
    summary_parser.add_argument("--pairs", type=Path, required=True)
    summary_parser.add_argument("--batches", type=int, required=True)
    summary_parser.add_argument("--batch-output", type=Path, required=True)
    summary_parser.add_argument("--output", type=Path, required=True)
    summary_parser.add_argument("--warmup", type=int, required=True)
    summary_parser.add_argument("--selection-seed", type=int, required=True)
    summary_parser.add_argument("--pin-cpu", default="")
    summary_parser.add_argument("--source-manifest", type=Path, required=True)
    summary_parser.set_defaults(func=summarize)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
