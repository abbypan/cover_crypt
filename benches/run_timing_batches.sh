#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=089a548
iterations=${ITERATIONS:-300}
warmup=${WARMUP:-20}
batches=${BATCHES:-10}
per_stratum=${SAMPLE_PER_STRATUM:-20}
selection_seed=${SELECTION_SEED:-20260813}
results_dir=${RESULTS_DIR:-"$repo_dir/benchmark-results"}
pin_cpu=${PIN_CPU:-}
baseline_dir=$(mktemp -d)
trap 'rm -rf "$baseline_dir"' EXIT

for value in "$iterations" "$batches" "$per_stratum"; do
    if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
        echo "iterations, batches, and sample size must be positive integers" >&2
        exit 2
    fi
done
if ! [[ "$warmup" =~ ^[0-9]+$ ]]; then
    echo "WARMUP must be a nonnegative integer" >&2
    exit 2
fi
if [[ -n "$pin_cpu" ]] && ! command -v taskset >/dev/null 2>&1; then
    echo "PIN_CPU requires taskset" >&2
    exit 2
fi

mkdir -p "$results_dir"
selection="$results_dir/timing-pairs.tsv"
source_manifest="$results_dir/timing-source-manifest.json"
# Capture source provenance before touching any tracked result file.  The
# summary reads this manifest instead of treating newly written benchmark
# outputs as source-tree dirtiness.
python3 "$repo_dir/benches/artifact_manifest.py" source \
    --repo-root "$repo_dir" \
    --baseline-ref "$baseline_ref" \
    --output "$source_manifest"
: > "$results_dir/timing-run.log"
python3 "$repo_dir/benches/timing_report.py" select \
    --pairs "$results_dir/classic-pairs.csv" \
    --output "$selection" \
    --per-stratum "$per_stratum" \
    --seed "$selection_seed"

echo "Preparing original Covercrypt at $baseline_ref"
git -C "$repo_dir" archive "$baseline_ref" | tar -x -C "$baseline_dir"
cp "$repo_dir/examples/evaluation_benchmark.rs" "$baseline_dir/examples/evaluation_benchmark.rs"
# The historical baseline did not track a lockfile.  Use the same tracked lock
# as the LP build so both binaries have an exact, shared dependency resolution.
cp "$repo_dir/Cargo.lock" "$baseline_dir/Cargo.lock"

echo "Building both release binaries"
cargo build --quiet --offline --locked --release \
    --manifest-path "$baseline_dir/Cargo.toml" \
    --example evaluation_benchmark
cargo build --quiet --offline --locked --release \
    --manifest-path "$repo_dir/Cargo.toml" \
    --example evaluation_benchmark

baseline_binary="$baseline_dir/target/release/examples/evaluation_benchmark"
lp_binary="$repo_dir/target/release/examples/evaluation_benchmark"

run_one() {
    local batch=$1
    local scenario=$2
    local variant=$3
    local position=$4
    local binary=$lp_binary
    if [[ "$variant" == "covercrypt" ]]; then
        binary=$baseline_binary
    fi
    local -a command=("$binary")
    if [[ -n "$pin_cpu" ]]; then
        command=(taskset -c "$pin_cpu" "$binary")
    fi
    local batch_label
    batch_label=$(printf '%02d' "$batch")
    echo "batch $batch/$batches $scenario position $position: $variant"
    "${command[@]}" \
        --variant "$variant" \
        --scenario "$scenario" \
        --iterations "$iterations" \
        --warmup "$warmup" \
        --pairs-file "$selection" \
        --batch-id "$batch" \
        --order-position "$position" \
        --output "$results_dir/timing-b$batch_label-$scenario-$variant.csv" \
        2>> "$results_dir/timing-run.log"
}

for ((batch = 1; batch <= batches; batch++)); do
    if ((batch % 2 == 1)); then
        scenarios=(classic hybridized)
        variants=(covercrypt lp-covercrypt)
    else
        scenarios=(hybridized classic)
        variants=(lp-covercrypt covercrypt)
    fi
    for scenario in "${scenarios[@]}"; do
        run_one "$batch" "$scenario" "${variants[0]}" 1
        run_one "$batch" "$scenario" "${variants[1]}" 2
    done
done

python3 "$repo_dir/benches/timing_report.py" summarize \
    --results-dir "$results_dir" \
    --pairs "$selection" \
    --batches "$batches" \
    --warmup "$warmup" \
    --selection-seed "$selection_seed" \
    --pin-cpu "$pin_cpu" \
    --source-manifest "$source_manifest" \
    --batch-output "$results_dir/timing-batches.csv" \
    --output "$results_dir/timing-summary.json" \
    | tee "$results_dir/timing-summary.stdout.json"

python3 "$repo_dir/benches/artifact_manifest.py" results \
    --repo-root "$repo_dir" \
    --results-dir "$results_dir" \
    --output "$results_dir/timing-artifact-manifest.json"

echo "Balanced timing results written to $results_dir"
