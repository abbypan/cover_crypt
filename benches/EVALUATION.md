# Paper evaluation benchmark

Validate the Boolean-language compiler before running the timed corpus:

```sh
cargo test test_exhaustive_small_model_semantics_144_policies
cargo test test_missing_dimension_scaling_matches_cartesian_product
cargo run --release --example compiler_scaling
```

These checks compare the implementation with an independently encoded finite
model over 144 valid policies and 20,736 decisions, exercise invalid-input
rejection, and report cardinality and compilation cost through five synthetic
dimensions.

Run the complete experiment from the repository root:

```sh
benches/run_evaluation.sh
```

The default run measures every policy pair 2,000 times and writes raw and
aggregated results to the flat `benchmark-results/` directory, which also
contains the archived paper artifact. For a quick structural check, use fewer
iterations without changing the corpus:

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
v15 clauses. Historical raw CSVs without this field remain reportable and are
explicitly marked as lacking canonical-right evidence.

Release `089a548` predates the structural maximum attribute. For the baseline
only, an explicit maximum in an anarchic dimension is expanded to a disjunction
of all values in that dimension. This supplies the paper's `$` semantics while
leaving the original implementation's missing-dimension expansion--the behavior
being compared--unchanged. Translation, parsing, rights compilation, key
generation, and warm-up all occur before `Instant::now()`; only repeated
decryption is timed.

For each policy pair and binary, one timer encloses exactly 2,000 calls to the same
public `PkeAc::decrypt` method over an already-built key and ciphertext. The raw
row stores the loop total and its per-pair mean (`total_ns / 2,000`). Each Table 5
stratum is the unweighted arithmetic mean of those per-pair means, so every
policy pair has equal weight. Because every pair uses the same count, this is
also the arithmetic mean over all timed calls in the stratum, although
individual-call samples are not retained. Successful and failed calls have the
same external setup boundaries. Their internal paths differ: a success derives
the authenticated-encryption key and decrypts the AES-256-GCM payload after
decapsulation, whereas a failure returns `None` after decapsulation.

The archived paper timing is one fixed-order batch: all baseline measurements
precede all LP measurements, and no independent batch samples or confidence
intervals are available. Treat its percentages as descriptive. Performance
claims require repeated batches, reversed or randomized implementation order,
and an uncontended `JOBS=1` sensitivity run.

Generated files:

- `<scenario>-covercrypt.csv` and `<scenario>-lp-covercrypt.csv`: raw per-pair
  measurements, including both `user_ap` and the exact
  `implementation_user_ap` passed to that binary, plus the sorted canonical
  ciphertext-right encoding;
- `<scenario>-pairs.csv`: joined measurements, both implementation policies
  when recorded by the raw schema, and group assignments;
- `<scenario>-summary.json`: validated table values, the adapter-free subset
  excluding `$` from both source policies, and environment metadata.
