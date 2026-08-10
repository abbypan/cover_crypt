# Paper evaluation benchmark

Run the complete experiment from the repository root:

```sh
benches/run_evaluation.sh
```

The default run measures every policy pair 2,000 times and writes raw and
aggregated results to `benchmark-results/`. For a quick structural check, use
fewer iterations without changing the corpus:

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

Release `089a548` predates the structural maximum attribute. For the baseline
only, an explicit maximum in an anarchic dimension is expanded to a disjunction
of all values in that dimension. This supplies the paper's `$` semantics while
leaving the original implementation's missing-dimension expansion—the behavior
being compared—unchanged.

Generated files:

- `<scenario>-covercrypt.csv` and `<scenario>-lp-covercrypt.csv`: raw per-pair
  measurements;
- `<scenario>-pairs.csv`: joined measurements and group assignments;
- `<scenario>-summary.json`: validated table values and environment metadata.
