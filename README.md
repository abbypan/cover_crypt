# LP-Covercrypt Paper Benchmark

This repository contains the benchmark artifact used in the LP-Covercrypt
paper. The benchmark compares:

- the released Covercrypt v15 baseline at commit `089a548`; and
- LP-Covercrypt from one final clean source commit shared by every experiment.

The same benchmark source is compiled against both implementations. The runner
measures authorization outcomes, compiled user rights, serialized user-key and
PKE ciphertext sizes, and controlled `PkeAc::decrypt` call latency on prebuilt
inputs. It does not run the Criterion microbenchmarks in
`benches/benches.rs`.

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

These are uniform-mode scenarios. Mixed per-attribute Classic/Hybridized
structures are not evaluated.

The full $79\times79$ corpus supplies authorization, compiled-right, and
serialized-size results.  Decryption timing uses a fixed, seeded stratified
sample: 20 pairs from each of the two Same-Y and three Diff-Y outcome strata
(100 pairs per scenario). It runs 10 replicated single-worker batches, with
20 warm-ups and 300 timed decryptions per pair and batch.  Implementation and
scenario order alternate between batches, so each implementation runs first
in five batches per scenario.  Batch observations and all raw pair means are
retained for paired 95% Student-t confidence intervals.
The intervals describe this fixed sample and host; consecutive batches can
remain temporally correlated and are not evidence for arbitrary deployments.
The timed region excludes parsing, normalization, policy compilation, key
generation, encryption, serialization, I/O, setup, update, and rotation; the
results are therefore decrypt-call measurements, not end-to-end deployment
latency.

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

Run `cargo fetch --locked` once if the locked dependencies are not cached. The
canonical runners build offline and locked. They create isolated temporary
checkouts for the baseline, supply both builds with the repository's tracked
`Cargo.lock`, and remove the checkouts when the run finishes.

## Validate Boolean-policy semantics

The unified runner below invokes the complete default test suite, scaling, and
cross-build checks. The following commands remain useful as diagnostics, but
their outputs must not be mixed into the canonical artifact when run from a
different revision:

```bash
cargo test test_exhaustive_small_model_semantics_144_policies
cargo test test_maximum_has_explicit_key_and_ciphertext_polarity
cargo test test_missing_dimension_scaling_matches_cartesian_product
cargo run --release --example compiler_scaling
benches/run_cross_version_validation.sh
```

The first command compares exact ciphertext/key right sets and all 20,736
authorization decisions for 144 policies covering disjunction, DNF expansion,
deduplication, subsumption, repeated hierarchical values, explicit maxima, and
mixed broadcast. It also checks rejection of unknown names and incompatible
anarchic conjunctions. The third command checks the
predicted Cartesian-product growth on synthetic structures with two through
five dimensions; the release example reports the corresponding compiler cost.
The polarity test makes the two uses of `D::$` explicit: it is a full lower-set
grant in a key policy and a single maximum-coordinate requirement in a
ciphertext policy. The cross-version runner builds clean public v15 and LP
binaries. It checks every actual key-right set in the 79-policy corpus against
an independently selected set over all 80 encoded coordinate rights, compares
focused Boolean authorization decisions, and executes the Classic/Hybridized
producer-consumer compatibility matrix.

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

## Reproduce the paper results

Start from a clean tracked source state and run every paper experiment through
the unified entry point:

```bash
benches/run_all_evaluation.sh
```

The driver fixes the source HEAD before the first command, rejects source-tree
changes or a HEAD change between stages, and writes every result directly into
the flat `benchmark-results/` directory. It runs all default tests, compiler
scaling, Boolean/key-right/migration cross-build validation, the exhaustive
Classic/Hybridized corpus, and controlled timing. The final
`evaluation-artifact-manifest.json` rejects the run unless every result class
records that same clean LP source revision.

Commit all source and runner changes before invoking the driver. Because the
generated files themselves record the tested source commit, they may then be
archived in a results-only commit; that archival commit is not a second tested
revision.

The canonical paper data are in `benchmark-results/`. The tracked raw CSVs
use the current schema: they retain both the source and exact implementation
policies and the sorted canonical ciphertext-right encoding. The report also
supports older schemas and labels fields that were not recorded rather than
inventing them.

The crate and artifact use the `BUSL-1.1` license declared in `Cargo.toml`.
On the paper's Ryzen 9 5900 host, allow roughly 25 minutes for the controlled
timing command; the exhaustive one-call corpus and cross-version checks take a
few minutes each. Runtime is machine dependent.

The unified runner uses one measured call for the non-performance corpus, 12
CPU-pinned corpus workers, and the controlled timing parameters reported in the
paper. Its `FULL_*` and `TIMING_*` environment variables may be changed for
diagnostics, but doing so changes the canonical experimental design. The
standalone exhaustive-corpus runner accepts these environment variables:

| Variable | Default | Meaning |
| --- | ---: | --- |
| `ITERATIONS` | `2000` | Timed decryptions per policy pair |
| `WARMUP` | `20` | Untimed warm-up decryptions per pair |
| `JOBS` | `1` | Independent policy shards and worker processes |
| `PIN_WORKERS` | `0` | Set to `1` to pin worker `N` to logical CPU `N` |
| `RESULTS_DIR` | `benchmark-results/` | Output directory, relative to the repository root by default |

The standalone timing runner accepts `ITERATIONS` (300), `WARMUP` (20), `BATCHES` (10),
`SAMPLE_PER_STRATUM` (20), `SELECTION_SEED` (20260813), `PIN_CPU` (unset), and
`RESULTS_DIR`. Set `PIN_CPU` to one CPU allowed by the host. Use a quiet machine
with a fixed performance policy, and avoid changing the source during the run.
The timing summary records the host, toolchain, clean LP commit, selection
digest, pinning, order balance, and confidence-interval design. Its pre-run
source manifest also records the full baseline commit and hashes the common
tracked lockfile used by both builds.

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

## Canonical paper snapshot

The checked-in paper snapshot compares baseline commit
`089a548d4373dd099a57bb1c5219ad0a4cf25fe4` with clean LP source commit
`55f5094806c24853b9f912a8202e22177e4868e4`. The generated files may be stored
in a later results-only commit; the tested source revision is the one embedded
in the summaries and manifests. The unified manifest must report
`all_result_classes_same_clean_revision: true`.

The main comparator is `CC+T`, not an unchanged stock-v15 deployment. Both
builds use the same 80-right universe with a registered `$` in every dimension.
On the v15 key path only, adapter `T` expands an anarchic `D::$` into `$` plus
all concrete values; it is the identity on token-free policies. Stock-v15 key,
setup, MSK, and MPK sizes without registered maxima are not measured.

The expected aggregates for each Classic or Hybridized 6,241-pair corpus are:

| Metric | `CC+T` | LP-Covercrypt |
| --- | ---: | ---: |
| Oracle-relative TP / FP / TN / FN | 1,135 / 1,442 / 3,664 / 0 | 1,135 / 0 / 5,106 / 0 |
| Oracle-relative precision | 44.04% | 100% |
| Mean compiled user rights, 79 policies | 33.62 | 15.37 |
| Mean Classic USK bytes, 79 policies | 1,409.08 | 728.19 |
| Mean Hybridized USK bytes, 79 policies | 54,645.33 | 24,175.28 |
| Mean Classic / Hybridized PKE bytes, 79 policies | 178 / 946 | 178 / 946 |

These are synthetic-corpus results. They do not estimate real-world omission
prevalence, and the USK reductions do not include the unmeasured expansion of
setup, MSK, or MPK state. Controlled latency values and nominal confidence
intervals are retained in `timing-summary.json`.

## Results

For each of `classic` and `hybridized`, the output directory contains:

| File | Contents |
| --- | --- |
| `<scenario>-covercrypt.csv` | Raw measurements from Covercrypt v15 |
| `<scenario>-lp-covercrypt.csv` | Raw measurements from LP-Covercrypt |
| `<scenario>-pairs.csv` | Joined per-pair results and classifications |
| `<scenario>-summary.json` | Validated aggregates, no-`$` sensitivity results, and environment metadata |
| `<scenario>-summary.stdout.json` | Copy of the summary printed during the run |

Inspect the two primary summaries with:

```bash
python3 -m json.tool benchmark-results/classic-summary.json
python3 -m json.tool benchmark-results/hybridized-summary.json
```

The exhaustive summaries can be rebuilt from stored raw rows without rerunning
cryptography:

```bash
for scenario in classic hybridized; do
  python3 benches/evaluation_report.py \
    --scenario "$scenario" \
    --covercrypt "benchmark-results/$scenario-covercrypt.csv" \
    --lp "benchmark-results/$scenario-lp-covercrypt.csv" \
    --merged "benchmark-results/$scenario-pairs.csv" \
    --output "benchmark-results/$scenario-summary.json" \
    --environment-from-summary \
      "benchmark-results/$scenario-summary.json" \
    --workers 12 --pinned 1 \
    | tee "benchmark-results/$scenario-summary.stdout.json"
done
```

The controlled timing summary can likewise be rebuilt from its retained raw
rows:

```bash
python3 benches/timing_report.py summarize \
  --results-dir benchmark-results \
  --pairs benchmark-results/timing-pairs.tsv \
  --batches 10 --warmup 20 --selection-seed 20260813 --pin-cpu 0 \
  --source-manifest benchmark-results/timing-source-manifest.json \
  --batch-output benchmark-results/timing-batches.csv \
  --output benchmark-results/timing-summary.json
```

Verify all retained timing files, including the source-manifest file, with:

```bash
python3 benches/artifact_manifest.py verify \
  --repo-root "$PWD" \
  --manifest benchmark-results/timing-artifact-manifest.json
```

The timing source manifest is created before the timing stage writes canonical
timing results. It records the same clean LP source commit as every earlier
stage, the full baseline commit, and hashes the tracked implementation and all
evaluation inputs. The timing result manifest binds that snapshot to the
selection TSV, all 40 raw CSVs, batch aggregate, summary, and run log.

The unified `evaluation-artifact-manifest.json` additionally hashes the unit,
scaling, cross-build, exhaustive-corpus, migration, and timing outputs. Its
`all_result_classes_same_clean_revision` field is emitted only after every
embedded revision and worktree-state check succeeds. Verify it with:

```bash
python3 benches/artifact_manifest.py verify \
  --repo-root "$PWD" \
  --manifest benchmark-results/evaluation-artifact-manifest.json
```

Classic and Hybridized timing results are interpreted separately; no result
pools the scenarios.

The cross-build validation writes three additional top-level files:

| File | Contents |
| --- | --- |
| `boolean-cross-build.json` | Fourteen focused v15/LP Boolean cases over 36 complete downward-closed keys |
| `key-rights-cross-build.json` | Exact v15/unrestricted and LP/default-minimal encoded-set equalities for all 79 normalized keys over the 80-right universe |
| `compatibility-matrix.json` | Eight Classic/Hybridized v15/LP producer-consumer rows for stateful and wire objects |

The timing experiment also writes only top-level files in
`benchmark-results/`: `timing-pairs.tsv`, forty
`timing-bNN-<scenario>-<variant>.csv` raw files, `timing-batches.csv`,
`timing-summary.json`, `timing-summary.stdout.json`, `timing-run.log`,
`timing-source-manifest.json`, and `timing-artifact-manifest.json`.
The complete run also writes `unit-validation.log`,
`unit-validation-metadata.json`, `compiler-scaling.csv`,
`compiler-scaling-metadata.json`, and `evaluation-artifact-manifest.json` at
that same top level.

The Boolean report requires all 360 decisions in the ten shared-preservation
cases to agree, while recording the repeated-hierarchy and incompatible-anarchy
language changes separately. The compatibility report requires V1/V2
AccessStructure, MSK, and MPK objects to reject cross-version loading, while
USKs and PKE ciphertexts remain consumable in their original MSK domain. It
also verifies that deserializing a legacy v15 omission-key under LP does not
silently narrow its authority.

## Artifact files

- [`benches/run_all_evaluation.sh`](benches/run_all_evaluation.sh): canonical
  clean-revision driver for every paper experiment;
- [`examples/evaluation_benchmark.rs`](examples/evaluation_benchmark.rs): shared
  measurement program compiled against both implementations;
- [`benches/run_evaluation.sh`](benches/run_evaluation.sh): build, sharding, and
  execution driver;
- [`benches/evaluation_report.py`](benches/evaluation_report.py): validation,
  merge, and aggregation logic;
- [`benches/run_timing_batches.sh`](benches/run_timing_batches.sh): balanced,
  single-worker replicated-batch timing driver;
- [`benches/timing_report.py`](benches/timing_report.py): seeded sample
  selection, raw-batch validation, and paired confidence intervals;
- [`benches/artifact_manifest.py`](benches/artifact_manifest.py): exact-source
  and unified-result checksum creation and verification;
- [`examples/cross_version_validation.rs`](examples/cross_version_validation.rs):
  common v15/LP key-right, Boolean, and serialization test program;
- [`benches/run_cross_version_validation.sh`](benches/run_cross_version_validation.sh):
  clean cross-build and compatibility-matrix driver;
- [`benches/cross_version_report.py`](benches/cross_version_report.py): strict
  validator and aggregator for both cross-build reports;
- [`benches/EVALUATION.md`](benches/EVALUATION.md): concise benchmark notes.

If the baseline check fails, obtain repository history containing commit
`089a548` before running the experiment. If `PIN_WORKERS=1` fails, verify that
`taskset` is installed and that `JOBS` does not exceed the number reported by
`nproc`.
