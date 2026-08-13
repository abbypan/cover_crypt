#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
baseline_ref=089a548
results_dir=${RESULTS_DIR:-"$repo_dir/benchmark-results"}
baseline_dir=$(mktemp -d)
work_dir=$(mktemp -d)
trap 'rm -rf "$baseline_dir" "$work_dir"' EXIT

mkdir -p "$results_dir"
git -C "$repo_dir" archive "$baseline_ref" | tar -x -C "$baseline_dir"
cp "$repo_dir/examples/cross_version_validation.rs" \
    "$baseline_dir/examples/cross_version_validation.rs"

cargo build --release --manifest-path "$baseline_dir/Cargo.toml" \
    --example cross_version_validation
cargo build --release --manifest-path "$repo_dir/Cargo.toml" \
    --example cross_version_validation

baseline_bin="$baseline_dir/target/release/examples/cross_version_validation"
lp_bin="$repo_dir/target/release/examples/cross_version_validation"

"$baseline_bin" boolean covercrypt "$work_dir/boolean-covercrypt.json"
"$lp_bin" boolean lp-covercrypt "$work_dir/boolean-lp-covercrypt.json"

compatibility_outputs=()
for scenario in classic hybridized; do
    for producer in covercrypt lp-covercrypt; do
        producer_dir="$work_dir/$scenario-$producer"
        if [[ "$producer" == covercrypt ]]; then
            producer_bin=$baseline_bin
        else
            producer_bin=$lp_bin
        fi
        "$producer_bin" produce "$producer" "$scenario" "$producer_dir"

        for consumer in covercrypt lp-covercrypt; do
            if [[ "$consumer" == covercrypt ]]; then
                consumer_bin=$baseline_bin
            else
                consumer_bin=$lp_bin
            fi
            output="$work_dir/$scenario-$producer-to-$consumer.json"
            "$consumer_bin" consume "$consumer" "$producer" "$scenario" \
                "$producer_dir" "$output"
            compatibility_outputs+=("$output")
        done
    done
done

python3 "$repo_dir/benches/cross_version_report.py" \
    --baseline-boolean "$work_dir/boolean-covercrypt.json" \
    --lp-boolean "$work_dir/boolean-lp-covercrypt.json" \
    --compatibility "${compatibility_outputs[@]}" \
    --boolean-output "$results_dir/boolean-cross-build.json" \
    --matrix-output "$results_dir/compatibility-matrix.json"

echo "Cross-version results written to $results_dir"
