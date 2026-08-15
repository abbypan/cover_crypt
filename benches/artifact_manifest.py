#!/usr/bin/env python3
"""Create and verify source/result manifests for the paper evaluation artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


SOURCE_FIXED = (
    "Cargo.toml",
    "Cargo.lock",
    "examples/evaluation_benchmark.rs",
    "examples/cross_version_validation.rs",
    "examples/compiler_scaling.rs",
    "benches/run_all_evaluation.sh",
    "benches/run_evaluation.sh",
    "benches/run_cross_version_validation.sh",
    "benches/run_timing_batches.sh",
    "benches/evaluation_report.py",
    "benches/cross_version_report.py",
    "benches/timing_report.py",
    "benches/artifact_manifest.py",
)

UNIFIED_FIXED_RESULTS = (
    "classic-covercrypt.csv",
    "classic-lp-covercrypt.csv",
    "classic-pairs.csv",
    "classic-summary.json",
    "classic-summary.stdout.json",
    "hybridized-covercrypt.csv",
    "hybridized-lp-covercrypt.csv",
    "hybridized-pairs.csv",
    "hybridized-summary.json",
    "hybridized-summary.stdout.json",
    "boolean-cross-build.json",
    "key-rights-cross-build.json",
    "compatibility-matrix.json",
    "compiler-scaling.csv",
    "compiler-scaling-metadata.json",
    "unit-validation.log",
    "unit-validation-metadata.json",
    "timing-pairs.tsv",
    "timing-batches.csv",
    "timing-summary.json",
    "timing-summary.stdout.json",
    "timing-run.log",
    "timing-source-manifest.json",
    "timing-artifact-manifest.json",
)


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def git_output(repo: Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def file_entry(root: Path, path: Path) -> dict[str, object]:
    return {
        "path": path.relative_to(root).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": digest(path),
    }


def write_json(path: Path, value: dict[str, object]) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def clean_head(repo: Path) -> str:
    head = git_output(repo, "rev-parse", "HEAD")
    dirty = git_output(
        repo,
        "status",
        "--porcelain",
        "--untracked-files=all",
        "--",
        ".",
        ":(exclude)benchmark-results/**",
    )
    if dirty:
        raise ValueError("evaluation provenance requires a clean tracked worktree")
    return head


def source_files(repo: Path) -> list[Path]:
    paths = [repo / name for name in SOURCE_FIXED]
    paths.extend(sorted((repo / "src").rglob("*.rs")))
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"missing source inputs: {missing}")
    return sorted(set(paths))


def create_source(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    paths = source_files(repo)
    baseline_commit = (
        git_output(repo, "rev-parse", f"{args.baseline_ref}^{{commit}}")
        if args.baseline_ref
        else None
    )
    manifest = {
        "schema": "lp-covercrypt-timing-source-v1",
        "purpose": (
            "Source snapshot captured before the timing runner modifies canonical "
            "result files; binds the run to its implementation and tool inputs"
        ),
        "git_head": git_output(repo, "rev-parse", "HEAD"),
        "git_worktree_dirty": bool(
            git_output(
                repo,
                "status",
                "--porcelain",
                "--untracked-files=all",
                "--",
                ".",
                ":(exclude)benchmark-results/**",
            )
        ),
        "baseline_git_commit": baseline_commit,
        "files": [file_entry(repo, path) for path in paths],
    }
    write_json(args.output, manifest)
    print(digest(args.output))


def create_stage(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    output_file = args.data_file.resolve()
    if not output_file.is_file():
        raise ValueError(f"missing stage output: {output_file}")
    manifest = {
        "schema": "lp-covercrypt-evaluation-stage-v1",
        "stage": args.stage,
        "command": args.command,
        "lp_git_head": clean_head(repo),
        "lp_worktree_dirty": False,
        "file": file_entry(repo, output_file),
    }
    write_json(args.output, manifest)
    print(digest(args.output))


def result_files(repo: Path, results: Path) -> list[Path]:
    paths = [
        results / "timing-pairs.tsv",
        results / "timing-batches.csv",
        results / "timing-summary.json",
        results / "timing-summary.stdout.json",
        results / "timing-run.log",
        results / "timing-source-manifest.json",
    ]
    raw = sorted(results.glob("timing-b??-*-*.csv"))
    if len(raw) != 40:
        raise ValueError(f"expected 40 raw timing CSVs, found {len(raw)}")
    paths.extend(raw)
    paths.extend(repo / name for name in SOURCE_FIXED[2:])
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"missing result inputs: {missing}")
    return sorted(set(paths))


def create_results(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    results = args.results_dir.resolve()
    manifest = {
        "schema": "lp-covercrypt-timing-results-v1",
        "purpose": (
            "Checksums binding the canonical timing data to the archived "
            "reproduction sources and scripts"
        ),
        "files": [file_entry(repo, path) for path in result_files(repo, results)],
    }
    write_json(args.output, manifest)
    print(digest(args.output))


def load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def unified_result_files(results: Path) -> list[Path]:
    paths = [results / name for name in UNIFIED_FIXED_RESULTS]
    raw_timing = sorted(results.glob("timing-b??-*-*.csv"))
    if len(raw_timing) != 40:
        raise ValueError(f"expected 40 raw timing CSVs, found {len(raw_timing)}")
    paths.extend(raw_timing)
    missing = [path for path in paths if not path.is_file()]
    if missing:
        raise ValueError(f"missing unified result inputs: {missing}")
    return sorted(set(paths))


def create_all_results(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    results = args.results_dir.resolve()
    head = clean_head(repo)

    provenance: dict[str, str] = {}
    dirty_flags: dict[str, bool] = {}
    for scenario in ("classic", "hybridized"):
        summary = load_json(results / f"{scenario}-summary.json")
        environment = summary["environment"]
        provenance[f"corpus_{scenario}"] = str(environment["lp_git_head"])
        dirty_flags[f"corpus_{scenario}"] = bool(environment["lp_worktree_dirty"])

    for name in (
        "boolean-cross-build.json",
        "key-rights-cross-build.json",
        "compatibility-matrix.json",
    ):
        document = load_json(results / name)
        provenance[name] = str(document["lp_git_head"])
        dirty_flags[name] = bool(document["lp_worktree_dirty"])

    for name in (
        "compiler-scaling-metadata.json",
        "unit-validation-metadata.json",
    ):
        document = load_json(results / name)
        provenance[name] = str(document["lp_git_head"])
        dirty_flags[name] = bool(document["lp_worktree_dirty"])

    timing = load_json(results / "timing-summary.json")
    timing_source = load_json(results / "timing-source-manifest.json")
    provenance["controlled_timing"] = str(timing["environment"]["lp_git_head"])
    dirty_flags["controlled_timing"] = bool(
        timing["environment"]["lp_worktree_dirty"]
    )
    provenance["timing_source_manifest"] = str(timing_source["git_head"])
    dirty_flags["timing_source_manifest"] = bool(
        timing_source["git_worktree_dirty"]
    )

    mismatched = {name: value for name, value in provenance.items() if value != head}
    dirty = {name: value for name, value in dirty_flags.items() if value}
    if mismatched:
        raise ValueError(
            f"result classes do not share current clean commit {head}: {mismatched}"
        )
    if dirty:
        raise ValueError(f"result classes record dirty source states: {dirty}")

    manifest = {
        "schema": "lp-covercrypt-unified-evaluation-v1",
        "purpose": (
            "Binds every paper experiment to one final clean LP-Covercrypt "
            "commit and to the retained flat benchmark result set"
        ),
        "lp_git_head": head,
        "lp_worktree_dirty": False,
        "baseline_git_commit": git_output(
            repo, "rev-parse", f"{args.baseline_ref}^{{commit}}"
        ),
        "result_class_revisions": provenance,
        "all_result_classes_same_clean_revision": True,
        "files": [file_entry(repo, path) for path in unified_result_files(results)],
    }
    write_json(args.output, manifest)
    print(digest(args.output))


def verify(args: argparse.Namespace) -> None:
    repo = args.repo_root.resolve()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    failures: list[str] = []
    for entry in manifest["files"]:
        path = repo / entry["path"]
        if not path.is_file():
            failures.append(f"missing: {entry['path']}")
        elif path.stat().st_size != entry["bytes"]:
            failures.append(f"size: {entry['path']}")
        elif digest(path) != entry["sha256"]:
            failures.append(f"sha256: {entry['path']}")
    if failures:
        raise SystemExit("manifest verification failed:\n" + "\n".join(failures))
    print(f"verified {len(manifest['files'])} files")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    source = subparsers.add_parser("source")
    source.add_argument("--repo-root", type=Path, required=True)
    source.add_argument("--baseline-ref")
    source.add_argument("--output", type=Path, required=True)
    source.set_defaults(func=create_source)

    stage = subparsers.add_parser("stage")
    stage.add_argument("--repo-root", type=Path, required=True)
    stage.add_argument("--stage", required=True)
    stage.add_argument("--command", required=True)
    stage.add_argument("--data-file", type=Path, required=True)
    stage.add_argument("--output", type=Path, required=True)
    stage.set_defaults(func=create_stage)

    results = subparsers.add_parser("results")
    results.add_argument("--repo-root", type=Path, required=True)
    results.add_argument("--results-dir", type=Path, required=True)
    results.add_argument("--output", type=Path, required=True)
    results.set_defaults(func=create_results)

    all_results = subparsers.add_parser("all-results")
    all_results.add_argument("--repo-root", type=Path, required=True)
    all_results.add_argument("--results-dir", type=Path, required=True)
    all_results.add_argument("--baseline-ref", required=True)
    all_results.add_argument("--output", type=Path, required=True)
    all_results.set_defaults(func=create_all_results)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo-root", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
