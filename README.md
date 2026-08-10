# LP-Covercrypt Paper Benchmark

This repository contains the benchmark artifact used in the LP-Covercrypt
paper. The benchmark compares:

- the released Covercrypt v15 baseline at commit `089a548`; and
- LP-Covercrypt from the current working tree.

The same benchmark source is compiled against both implementations. The runner
measures authorization outcomes, compiled user rights, serialized user-key and
ciphertext sizes, and decryption latency. It does not run the Criterion
microbenchmarks in `benches/benches.rs`.

## Experiment design

The policy corpus uses the three ETSI example dimensions:

```text
SEC = {bottom, LOW, MED, HIG, $}
DPT = {bottom, DEV, MKG, $}
CTR = {bottom, EN,  FR,  $}
```

The all-bottom tuple is represented by Covercrypt's global broadcast policy and
is excluded. This leaves 79 ciphertext policies and 79 user policies, or 6,241
policy pairs per scenario.

Two scenarios are measured independently:

- **Classic**: all non-bottom rights use the Ristretto25519-based component;
- **Hybridized**: all non-bottom rights additionally use ML-KEM-512.

The paper run performs 20 warm-up decryptions followed by 2,000 timed
decryptions for every pair. It assigns the corpus to 12 worker processes pinned
to distinct logical CPUs. Operations for an individual pair remain serial.

## Requirements

Run the benchmark on Linux from the repository root. The following commands
must be available:

- `bash`, `git`, `tar`, and standard GNU command-line utilities;
- Rust and Cargo (the paper used Rust 1.97.1 and Cargo 1.97.1);
- Python 3;
- `taskset` and `nproc` when CPU pinning is enabled.

The Git object for the baseline commit must exist locally:

```bash
git rev-parse --verify '089a548^{commit}'
```

Cargo may need network access on the first run to download dependencies. The
runner creates an isolated temporary checkout for the baseline and removes it
when the run finishes.

## Quick smoke test

The smoke test builds both implementations and processes the complete policy
corpus, but times each pair only once and skips warm-up:

```bash
ITERATIONS=1 \
WARMUP=0 \
JOBS=1 \
RESULTS_DIR=/tmp/lp-covercrypt-smoke \
benches/run_evaluation.sh
```

A successful run ends with:

```text
Results written to /tmp/lp-covercrypt-smoke
```

It also validates the policy-pair counts and authorization groups described in
the paper. The smoke test checks the pipeline and semantic results; its timing
values are not suitable for performance comparisons.

## Reproduce the paper run

The paper used an AMD Ryzen 9 5900 12-Core Processor and one pinned worker per
logical CPU used by the experiment:

```bash
ITERATIONS=2000 \
WARMUP=20 \
JOBS=12 \
PIN_WORKERS=1 \
RESULTS_DIR="$PWD/benchmark-results" \
benches/run_evaluation.sh
```

For uncontended single-core latency, use `JOBS=1` and leave
`PIN_WORKERS=0`. Those results will not reproduce the paper's 12-worker
execution environment.

The runner accepts these environment variables:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `ITERATIONS` | `2000` | Timed decryptions per policy pair |
| `WARMUP` | `20` | Untimed warm-up decryptions per pair |
| `JOBS` | `1` | Independent policy shards and worker processes |
| `PIN_WORKERS` | `0` | Set to `1` to pin worker `N` to logical CPU `N` |
| `RESULTS_DIR` | `benchmark-results/` | Output directory, relative to the repository root by default |

Use a quiet machine with a fixed performance policy when comparing latency.
Record the current commit and avoid changing the source during the run. The
generated summary records the OS, CPU, memory, Rust/Cargo versions, worker
count, pinning status, current commit, and whether the working tree is dirty.

## What the runner does

`benches/run_evaluation.sh` performs the complete experiment:

1. exports baseline commit `089a548` to a temporary directory;
2. copies the common benchmark source into the baseline tree;
3. builds release binaries for the baseline and current LP-Covercrypt tree;
4. runs all policy pairs for Classic and Hybridized scenarios;
5. merges the two implementations' raw rows; and
6. validates and aggregates the paper results.

The aggregation step fails if either implementation is missing a policy pair,
if scenarios are mixed, if LP-Covercrypt disagrees with the independent
source-policy oracle, or if the corpus does not have the expected structure:

| Classification | Expected pairs per scenario |
| --- | ---: |
| Same compiled rights (`Same-Y`) | 2,844 |
| Different compiled rights (`Diff-Y`) | 3,397 |
| Diff-Y: LP TP / Covercrypt TP | 275 |
| Diff-Y: LP TN / Covercrypt TN | 1,680 |
| Diff-Y: LP TN / Covercrypt FP | 1,442 |

## Results

For each of `classic` and `hybridized`, the output directory contains:

| File | Contents |
| --- | --- |
| `<scenario>-covercrypt.csv` | Raw measurements from Covercrypt v15 |
| `<scenario>-lp-covercrypt.csv` | Raw measurements from LP-Covercrypt |
| `<scenario>-pairs.csv` | Joined per-pair results and classifications |
| `<scenario>-summary.json` | Validated aggregate values and environment metadata |
| `<scenario>-summary.stdout.json` | Copy of the summary printed during the run |

Inspect the two primary summaries with:

```bash
python3 -m json.tool benchmark-results/classic-summary.json
python3 -m json.tool benchmark-results/hybridized-summary.json
```

Latency is reported as mean nanoseconds in raw CSV rows and mean microseconds
in the summary. Classic and Hybridized results must be interpreted separately;
the report does not pool them.

## Artifact files

- [`examples/evaluation_benchmark.rs`](examples/evaluation_benchmark.rs): shared
  measurement program compiled against both implementations;
- [`benches/run_evaluation.sh`](benches/run_evaluation.sh): build, sharding, and
  execution driver;
- [`benches/evaluation_report.py`](benches/evaluation_report.py): validation,
  merge, and aggregation logic;
- [`benches/EVALUATION.md`](benches/EVALUATION.md): concise benchmark notes.

If the baseline check fails, obtain repository history containing commit
`089a548` before running the experiment. If `PIN_WORKERS=1` fails, verify that
`taskset` is installed and that `JOBS` does not exceed the number reported by
`nproc`.
