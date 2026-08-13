# Paper evaluation benchmark

Validate the Boolean-language compiler before running the timed corpus:

```sh
cargo test test_exhaustive_small_model_semantics_144_policies
cargo test test_maximum_has_explicit_key_and_ciphertext_polarity
cargo test test_missing_dimension_scaling_matches_cartesian_product
cargo run --release --example compiler_scaling
benches/run_cross_version_validation.sh
```

These checks compare the implementation with an independently encoded finite
model over 144 valid policies and 20,736 decisions, exercise invalid-input
rejection, and report cardinality and compilation cost through five synthetic
dimensions.

`D::$` is polarity-sensitive. In a user-key policy it selects the full lower
set of `D`; in a ciphertext policy it is the single maximum-coordinate
requirement. A concrete `D::v` key therefore does not satisfy ciphertext
`D::$`, while a maximum-bearing key satisfies maximum, concrete, and omitted
ciphertext requirements. The named unit test checks all four decisions.

The cross-version runner uses the same public-API Rust source in a clean v15
checkout and the LP tree. Its Boolean report checks 14 focused cases against 36
complete downward-closed keys: all 360 decisions in the ten preservation cases
must agree, even when canonical ciphertext rights differ. Repeated hierarchy
normalization and incomparable-anarchy rejection are recorded as intentional
language changes rather than compatibility claims.

Run the complete experiment from the repository root:

```sh
benches/run_evaluation.sh
```

The exhaustive runner writes raw and aggregated results to the flat
`benchmark-results/` directory. Its timing column is not used for the paper's
performance table. For a structural, semantic, and size run, use one measured
call without changing the corpus:

```sh
ITERATIONS=1 WARMUP=0 RESULTS_DIR=/tmp/covercrypt-smoke \
  benches/run_evaluation.sh
```

Policy pairs can be split across independent workers. Each worker owns its
Covercrypt instance, key material, and RNG, and measures each assigned pair
serially:

```sh
JOBS=6 benches/run_evaluation.sh
```

Use `JOBS=1` (the default) when uncontended single-core latency is required.
Set `PIN_WORKERS=1` on Linux to bind shard `N` to logical CPU `N`.

The runner benchmarks two separate builds:

- original Covercrypt from release commit `089a548`;
- LP-Covercrypt from the current working tree.

Both builds execute the same Rust measurement source. Classic and Hybridized
scenarios are reported separately. Each uses 79 ciphertext policies and 79
user policies over `SEC`, `DPT`, and `CTR`, for 6,241 pairs. The report
generator rejects results unless each corpus splits into 2,844 same-$Y$ and
3,397 different-$Y$ pairs, and unless the latter has exactly 275/1,680/1,442
pairs with LP/CC results TP/TP, TN/TN, and TN/FP, respectively.

The report generator labels every pair with a corpus-specific implementation
of the paper's source-level `SpecAuth` relation. This oracle parses the fixed
SEC/DPT/CTR conjunctions and applies their declared orders without consulting
either compiler or decryption result. The report is rejected if an
LP-Covercrypt result disagrees with its oracle label.

Before randomized encapsulation, a current-schema binary calls its public
`ap_to_enc_rights` implementation for every ciphertext policy. The runner sorts
the canonical `Right` byte encodings and stores each implementation's value in
`ciphertext_rights_hex`. The report checks stability within each implementation
and records whether the sets happen to be equal on these 79 normalized
single-conjunction policies. This observation is not a claim of compiler
equality for general Boolean policies: LP may normalize and subsume redundant
v15 clauses. The canonical paper rows use this current schema. Historical raw
CSVs without the field remain reportable and are explicitly marked as lacking
canonical-right evidence.

Release `089a548` predates the structural maximum attribute. For the baseline
user-key policy only, an explicit maximum in an anarchic dimension is expanded
to a disjunction of all values in that dimension. Ciphertext policies are never
translated: doing so would change a maximum requirement into a disjunction.
The key-only translation supplies the paper's `$` grant semantics while
leaving the original implementation's missing-dimension expansion--the behavior
being compared--unchanged. Translation, parsing, rights compilation, key
generation, and warm-up all occur before `Instant::now()`; only repeated
decryption is timed.

The paper's timing experiment is separate:

```sh
ITERATIONS=300 WARMUP=20 BATCHES=10 SAMPLE_PER_STRATUM=20 \
  SELECTION_SEED=20260813 PIN_CPU=0 \
  RESULTS_DIR="$PWD/benchmark-results" benches/run_timing_batches.sh
```

From the exhaustive Classic classification, a fixed seed selects 20 pairs from
each of `same_success`, `same_failure`, `diff_tp_tp`, `diff_tn_tn`, and
`diff_tn_fp`. The identical 100-pair selection is used in both scenarios and
both builds. Each of 10 replicated batches regenerates keys and ciphertexts,
performs 20 untimed warm-ups, and times 300 calls to public
`PkeAc::decrypt` per pair. A single worker is pinned to the requested CPU.
Scenario order alternates by batch; implementation order is balanced so each
variant runs first in five batches per scenario.

The batches are consecutive replications, not proven statistically independent
draws; the intervals describe the fixed sample on the measured host. The
stratified design estimates each outcome class separately and is not a
deployment-weighted average.

The raw row stores the loop total and per-pair mean. `timing-batches.csv`
retains the unweighted stratum mean for each implementation and batch.
`timing-summary.json` reports the mean of the 10 paired percentage reductions
and a two-sided 95% Student-t interval over those batch reductions. It also
reports each reduction split by first-running implementation and, for
Diff-Y TP/TP and TN/TN, a Same-Y outcome-matched control-adjusted ratio.
Successful and failed calls have identical external setup boundaries, though
their internal post-decapsulation paths differ.

Generated files:

- `<scenario>-covercrypt.csv` and `<scenario>-lp-covercrypt.csv`: raw per-pair
  measurements, including both `user_ap` and the exact
  `implementation_user_ap` passed to that binary, plus the sorted canonical
  ciphertext-right encoding;
- `<scenario>-pairs.csv`: joined measurements, both implementation policies,
  both canonical ciphertext-right encodings, and group assignments;
- `<scenario>-summary.json`: validated table values, the adapter-free subset
  excluding `$` from both source policies, and environment metadata.
- `timing-pairs.tsv`: fixed seeded 100-pair timing selection;
- `timing-bNN-<scenario>-<variant>.csv`: retained raw pair means for every
  timing batch, scenario, and implementation;
- `timing-batches.csv` and `timing-summary.json`: paired batch observations and
  confidence-interval aggregates;
- `timing-source-manifest.json` and `timing-artifact-manifest.json`: SHA-256
  checksums for the archived reproduction sources and every canonical timing
  result; the source manifest is a post-run snapshot, not historical execution
  provenance;
- `boolean-cross-build.json`: shared-domain authorization comparison and
  explicitly classified language changes;
- `compatibility-matrix.json`: all eight producer-consumer rows. Cross-version
  V1/V2 AccessStructure, MSK, and MPK loading is rejected; USK and PKE
  ciphertext wire objects remain usable in their original MSK domain. A legacy
  v15 omission-key remains broad after LP deserialization and must be retired.
