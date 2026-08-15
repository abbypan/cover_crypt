#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
results_dir="$repo_dir/benchmark-results"
baseline_ref=089a548
lp_head=$(git -C "$repo_dir" rev-parse HEAD)

full_iterations=${FULL_ITERATIONS:-1}
full_warmup=${FULL_WARMUP:-0}
full_jobs=${FULL_JOBS:-12}
full_pin_workers=${FULL_PIN_WORKERS:-1}
timing_iterations=${TIMING_ITERATIONS:-300}
timing_warmup=${TIMING_WARMUP:-20}
timing_batches=${TIMING_BATCHES:-10}
timing_sample=${TIMING_SAMPLE_PER_STRATUM:-20}
timing_seed=${TIMING_SELECTION_SEED:-20260813}
timing_cpu=${TIMING_PIN_CPU:-0}

assert_same_clean_head() {
    local current
    current=$(git -C "$repo_dir" rev-parse HEAD)
    if [[ "$current" != "$lp_head" ]]; then
        echo "LP HEAD changed during evaluation: expected $lp_head, found $current" >&2
        exit 2
    fi
    if [[ -n $(git -C "$repo_dir" status --porcelain --untracked-files=all -- \
        . ':(exclude)benchmark-results/**') ]]; then
        echo "all paper experiments require one clean tracked source worktree" >&2
        git -C "$repo_dir" status --short -- . ':(exclude)benchmark-results/**' >&2
        exit 2
    fi
}

assert_same_clean_head
mkdir -p "$results_dir"

echo "[1/5] Running the complete default test suite at $lp_head"
cargo test --offline --locked --manifest-path "$repo_dir/Cargo.toml" 2>&1 \
    | tee "$results_dir/unit-validation.log"
assert_same_clean_head
python3 "$repo_dir/benches/artifact_manifest.py" stage \
    --repo-root "$repo_dir" \
    --stage unit-validation \
    --command "cargo test --offline --locked" \
    --data-file "$results_dir/unit-validation.log" \
    --output "$results_dir/unit-validation-metadata.json"

echo "[2/5] Running compiler scaling"
cargo run --quiet --offline --locked --release \
    --manifest-path "$repo_dir/Cargo.toml" \
    --example compiler_scaling \
    | tee "$results_dir/compiler-scaling.csv"
assert_same_clean_head
python3 "$repo_dir/benches/artifact_manifest.py" stage \
    --repo-root "$repo_dir" \
    --stage compiler-scaling \
    --command "cargo run --quiet --offline --locked --release --example compiler_scaling" \
    --data-file "$results_dir/compiler-scaling.csv" \
    --output "$results_dir/compiler-scaling-metadata.json"

echo "[3/5] Running Boolean, encoded-right, and migration cross-build validation"
EXPECTED_LP_HEAD="$lp_head" RESULTS_DIR="$results_dir" \
    "$repo_dir/benches/run_cross_version_validation.sh"
assert_same_clean_head

echo "[4/5] Running the exhaustive semantic and size corpus"
EXPECTED_LP_HEAD="$lp_head" \
ITERATIONS="$full_iterations" WARMUP="$full_warmup" \
JOBS="$full_jobs" PIN_WORKERS="$full_pin_workers" \
RESULTS_DIR="$results_dir" \
    "$repo_dir/benches/run_evaluation.sh"
assert_same_clean_head

echo "[5/5] Running controlled end-to-end PKE timing"
EXPECTED_LP_HEAD="$lp_head" \
ITERATIONS="$timing_iterations" WARMUP="$timing_warmup" \
BATCHES="$timing_batches" SAMPLE_PER_STRATUM="$timing_sample" \
SELECTION_SEED="$timing_seed" PIN_CPU="$timing_cpu" \
RESULTS_DIR="$results_dir" \
    "$repo_dir/benches/run_timing_batches.sh"
assert_same_clean_head

python3 "$repo_dir/benches/artifact_manifest.py" all-results \
    --repo-root "$repo_dir" \
    --results-dir "$results_dir" \
    --baseline-ref "$baseline_ref" \
    --output "$results_dir/evaluation-artifact-manifest.json"

python3 "$repo_dir/benches/artifact_manifest.py" verify \
    --repo-root "$repo_dir" \
    --manifest "$results_dir/timing-artifact-manifest.json"
python3 "$repo_dir/benches/artifact_manifest.py" verify \
    --repo-root "$repo_dir" \
    --manifest "$results_dir/evaluation-artifact-manifest.json"

echo "All paper experiments completed at one clean LP commit: $lp_head"
