#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=089a548
iterations=${ITERATIONS:-20}
warmup=${WARMUP:-20}
jobs=${JOBS:-1}
pin_workers=${PIN_WORKERS:-0}
results_dir=${RESULTS_DIR:-"$repo_dir/benchmark-results"}
baseline_dir=$(mktemp -d)
trap 'rm -rf "$baseline_dir"' EXIT

if ! [[ "$jobs" =~ ^[1-9][0-9]*$ ]]; then
    echo "JOBS must be a positive integer" >&2
    exit 2
fi
if [[ "$pin_workers" != "0" && "$pin_workers" != "1" ]]; then
    echo "PIN_WORKERS must be 0 or 1" >&2
    exit 2
fi
if [[ "$pin_workers" == "1" ]]; then
    if ! command -v taskset >/dev/null 2>&1; then
        echo "PIN_WORKERS=1 requires taskset" >&2
        exit 2
    fi
    if ((jobs > $(nproc))); then
        echo "cannot pin $jobs workers to only $(nproc) logical CPUs" >&2
        exit 2
    fi
fi

mkdir -p "$results_dir"

echo "Preparing original Covercrypt at $baseline_ref"
git -C "$repo_dir" archive "$baseline_ref" | tar -x -C "$baseline_dir"
cp "$repo_dir/examples/evaluation_benchmark.rs" "$baseline_dir/examples/evaluation_benchmark.rs"

run_shards() {
    local scenario=$1
    local variant=$2
    local binary=$3
    local -a pids=()

    for ((shard = 0; shard < jobs; shard++)); do
        local -a command=("$binary")
        if [[ "$pin_workers" == "1" ]]; then
            command=(taskset -c "$shard" "$binary")
        fi
        "${command[@]}" \
            --variant "$variant" \
            --scenario "$scenario" \
            --iterations "$iterations" \
            --warmup "$warmup" \
            --shard-index "$shard" \
            --shard-count "$jobs" \
            --output "$results_dir/$scenario-$variant.part-$shard.csv" &
        pids+=("$!")
    done
    local failed=0
    for pid in "${pids[@]}"; do
        if ! wait "$pid"; then
            failed=1
        fi
    done
    if ((failed)); then
        echo "$variant benchmark worker failed" >&2
        return 1
    fi

    head -n 1 "$results_dir/$scenario-$variant.part-0.csv" \
        > "$results_dir/$scenario-$variant.csv"
    for ((shard = 0; shard < jobs; shard++)); do
        tail -n +2 "$results_dir/$scenario-$variant.part-$shard.csv" \
            >> "$results_dir/$scenario-$variant.csv"
        rm "$results_dir/$scenario-$variant.part-$shard.csv"
    done
}

echo "Building original Covercrypt"
cargo build --quiet --release \
    --manifest-path "$baseline_dir/Cargo.toml" \
    --example evaluation_benchmark
echo "Benchmarking original Covercrypt ($iterations iterations per pair, $jobs worker(s))"
for scenario in classic hybridized; do
    run_shards "$scenario" covercrypt \
        "$baseline_dir/target/release/examples/evaluation_benchmark"
done

echo "Building LP-Covercrypt"
cargo build --quiet --release \
    --manifest-path "$repo_dir/Cargo.toml" \
    --example evaluation_benchmark
echo "Benchmarking LP-Covercrypt ($iterations iterations per pair, $jobs worker(s))"
for scenario in classic hybridized; do
    run_shards "$scenario" lp-covercrypt \
        "$repo_dir/target/release/examples/evaluation_benchmark"
done

for scenario in classic hybridized; do
    python3 "$repo_dir/benches/evaluation_report.py" \
        --scenario "$scenario" \
        --covercrypt "$results_dir/$scenario-covercrypt.csv" \
        --lp "$results_dir/$scenario-lp-covercrypt.csv" \
        --merged "$results_dir/$scenario-pairs.csv" \
        --output "$results_dir/$scenario-summary.json" \
        --workers "$jobs" \
        --pinned "$pin_workers" \
        | tee "$results_dir/$scenario-summary.stdout.json"
done

echo "Results written to $results_dir"
