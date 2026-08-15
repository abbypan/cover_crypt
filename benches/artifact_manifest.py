#!/usr/bin/env python3
"""Create and verify source/result manifests for the timing artifact."""

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
    "benches/run_timing_batches.sh",
    "benches/timing_report.py",
    "benches/artifact_manifest.py",
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
    manifest = {
        "schema": "lp-covercrypt-timing-source-v1",
        "purpose": (
            "Source snapshot captured before the timing runner modifies canonical "
            "result files; binds the run to its implementation and tool inputs"
        ),
        "git_head": git_output(repo, "rev-parse", "HEAD"),
        "git_worktree_dirty": bool(git_output(repo, "status", "--porcelain")),
        "files": [file_entry(repo, path) for path in paths],
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
    source.add_argument("--output", type=Path, required=True)
    source.set_defaults(func=create_source)

    results = subparsers.add_parser("results")
    results.add_argument("--repo-root", type=Path, required=True)
    results.add_argument("--results-dir", type=Path, required=True)
    results.add_argument("--output", type=Path, required=True)
    results.set_defaults(func=create_results)

    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--repo-root", type=Path, required=True)
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.set_defaults(func=verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
