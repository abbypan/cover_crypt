//! Reproduce the policy-pair decryption experiment from the paper.
//!
//! This source is intentionally compatible with both the unmodified
//! Covercrypt baseline (`089a548`) and LP-Covercrypt.  The runner copies it
//! into a clean checkout of the baseline so that both implementations execute
//! exactly the same policy corpus and measurement loop.

use cosmian_cover_crypt::{
    api::Covercrypt, traits::PkeAc, AccessPolicy, AccessStructure, EncryptionHint, Error,
    MasterPublicKey, MasterSecretKey, QualifiedAttribute,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Serializable, Serializer},
    Aes256Gcm,
};
use std::{
    env,
    fs::File,
    hint::black_box,
    io::{BufWriter, Write},
    path::PathBuf,
    time::Instant,
};

const BASELINE_REF: &str = "089a548";
const MAXIMUM: &str = "$";
const DEFAULT_ITERATIONS: u32 = 2_000;
const DEFAULT_WARMUP: u32 = 20;
const PLAINTEXT: &[u8] = b"LP-Covercrypt evaluation benchmark";

#[derive(Debug)]
struct Config {
    variant: String,
    iterations: u32,
    warmup: u32,
    output: PathBuf,
    shard_index: usize,
    shard_count: usize,
}

fn usage() -> &'static str {
    "usage: evaluation_benchmark --variant <covercrypt|lp-covercrypt> \
     --output <csv> [--iterations N] [--warmup N] \
     [--shard-index N --shard-count N]"
}

fn parse_args() -> Result<Config, String> {
    let mut variant = None;
    let mut iterations = DEFAULT_ITERATIONS;
    let mut warmup = DEFAULT_WARMUP;
    let mut output = None;
    let mut shard_index = 0usize;
    let mut shard_count = 1usize;
    let mut args = env::args().skip(1);

    while let Some(arg) = args.next() {
        let value = match arg.as_str() {
            "--variant" | "--output" | "--iterations" | "--warmup" | "--shard-index"
            | "--shard-count" => args
                .next()
                .ok_or_else(|| format!("missing value after {arg}"))?,
            "--help" | "-h" => return Err(usage().to_string()),
            _ => return Err(format!("unknown argument: {arg}\n{}", usage())),
        };

        match arg.as_str() {
            "--variant" => variant = Some(value),
            "--output" => output = Some(PathBuf::from(value)),
            "--iterations" => {
                iterations = value
                    .parse()
                    .map_err(|_| "--iterations must be a positive integer".to_string())?;
            }
            "--warmup" => {
                warmup = value
                    .parse()
                    .map_err(|_| "--warmup must be an integer".to_string())?;
            }
            "--shard-index" => {
                shard_index = value
                    .parse()
                    .map_err(|_| "--shard-index must be an integer".to_string())?;
            }
            "--shard-count" => {
                shard_count = value
                    .parse()
                    .map_err(|_| "--shard-count must be a positive integer".to_string())?;
            }
            _ => unreachable!(),
        }
    }

    let variant = variant.ok_or_else(|| format!("--variant is required\n{}", usage()))?;
    if variant != "covercrypt" && variant != "lp-covercrypt" {
        return Err("--variant must be covercrypt or lp-covercrypt".to_string());
    }
    if iterations == 0 {
        return Err("--iterations must be greater than zero".to_string());
    }
    if shard_count == 0 || shard_index >= shard_count {
        return Err("shard index must be less than a nonzero shard count".to_string());
    }

    Ok(Config {
        variant,
        iterations,
        warmup,
        output: output.ok_or_else(|| format!("--output is required\n{}", usage()))?,
        shard_index,
        shard_count,
    })
}

fn has_attribute(structure: &AccessStructure, dimension: &str, name: &str) -> bool {
    structure
        .attributes()
        .any(|attribute| attribute.dimension == dimension && attribute.name == name)
}

/// LP-Covercrypt creates `$` structurally.  The baseline does not, so add the
/// same maximum explicitly only when running against the original code.
fn add_baseline_maximum(
    structure: &mut AccessStructure,
    dimension: &str,
    after: Option<&str>,
) -> Result<(), Error> {
    if !has_attribute(structure, dimension, MAXIMUM) {
        structure.add_attribute(
            QualifiedAttribute::new(dimension, MAXIMUM),
            EncryptionHint::Classic,
            after,
        )?;
    }
    Ok(())
}

fn create_evaluation_structure() -> Result<AccessStructure, Error> {
    let mut structure = AccessStructure::new();

    structure.add_hierarchy("SEC".to_string())?;
    structure.add_attribute(
        QualifiedAttribute::new("SEC", "LOW"),
        EncryptionHint::Classic,
        None,
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("SEC", "MED"),
        EncryptionHint::Classic,
        Some("LOW"),
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("SEC", "HIG"),
        EncryptionHint::Hybridized,
        Some("MED"),
    )?;
    add_baseline_maximum(&mut structure, "SEC", Some("HIG"))?;

    structure.add_anarchy("DPT".to_string())?;
    for value in ["DEV", "MKG"] {
        structure.add_attribute(
            QualifiedAttribute::new("DPT", value),
            EncryptionHint::Classic,
            None,
        )?;
    }
    add_baseline_maximum(&mut structure, "DPT", None)?;

    structure.add_anarchy("CTR".to_string())?;
    for value in ["EN", "FR"] {
        structure.add_attribute(
            QualifiedAttribute::new("CTR", value),
            EncryptionHint::Classic,
            None,
        )?;
    }
    add_baseline_maximum(&mut structure, "CTR", None)?;

    Ok(structure)
}

fn setup(cc: &Covercrypt) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
    let (mut msk, _) = cc.setup()?;
    msk.access_structure = create_evaluation_structure()?;
    let mpk = cc.update_msk(&mut msk)?;
    Ok((msk, mpk))
}

fn policies(
    sec_values: &[Option<&str>],
    dpt_values: &[Option<&str>],
    ctr_values: &[Option<&str>],
) -> Vec<String> {
    let mut policies = Vec::new();
    for sec in sec_values {
        for dpt in dpt_values {
            for ctr in ctr_values {
                let mut terms = Vec::new();
                if let Some(value) = sec {
                    terms.push(format!("SEC::{value}"));
                }
                if let Some(value) = dpt {
                    terms.push(format!("DPT::{value}"));
                }
                if let Some(value) = ctr {
                    terms.push(format!("CTR::{value}"));
                }
                if !terms.is_empty() {
                    policies.push(terms.join(" && "));
                }
            }
        }
    }
    policies
}

fn encryption_policies() -> Vec<String> {
    // 3 * 4 * 4 - 1 = 47.  SEC::HIG and SEC::$ are excluded because they
    // select hybridized encryption; the paper evaluates classical ciphertexts.
    policies(
        &[None, Some("LOW"), Some("MED")],
        &[None, Some("DEV"), Some("MKG"), Some(MAXIMUM)],
        &[None, Some("EN"), Some("FR"), Some(MAXIMUM)],
    )
}

fn user_policies() -> Vec<String> {
    // 5 * 4 * 4 - 1 = 79.
    policies(
        &[None, Some("LOW"), Some("MED"), Some("HIG"), Some(MAXIMUM)],
        &[None, Some("DEV"), Some("MKG"), Some(MAXIMUM)],
        &[None, Some("EN"), Some("FR"), Some(MAXIMUM)],
    )
}

fn is_complete_user_policy(policy: &str) -> bool {
    ["SEC::", "DPT::", "CTR::"]
        .iter()
        .all(|dimension| policy.contains(dimension))
}

/// The released baseline predates the structural maximum attribute and treats
/// `$` in an anarchic dimension as an ordinary incomparable value.  Expand an
/// explicit anarchic maximum into all of that dimension's values so the
/// baseline receives the maximum semantics defined by the paper.  Missing
/// dimensions are deliberately left untouched: the original implementation
/// itself expands those, which is the Rule 2 behavior under test.
fn baseline_user_policy(policy: &str) -> String {
    policy
        .replace("DPT::$", "(DPT::DEV || DPT::MKG || DPT::$)")
        .replace("CTR::$", "(CTR::EN || CTR::FR || CTR::$)")
}

fn csv_field(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn run(config: Config) -> Result<(), Box<dyn std::error::Error>> {
    let enc_policies = encryption_policies();
    let usk_policies = user_policies();
    assert_eq!(enc_policies.len(), 47);
    assert_eq!(usk_policies.len(), 79);

    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup(&cc)?;
    let output = File::create(&config.output)?;
    let mut output = BufWriter::new(output);
    writeln!(
        output,
        "variant,baseline_ref,enc_ap,user_ap,y_relation,user_rights,user_key_bytes,ciphertext_bytes,decryption_result,iterations,total_ns,mean_ns"
    )?;

    let selected_enc_policies = enc_policies
        .iter()
        .enumerate()
        .filter(|(index, _)| index % config.shard_count == config.shard_index)
        .map(|(_, policy)| policy)
        .collect::<Vec<_>>();
    let total_pairs = selected_enc_policies.len() * usk_policies.len();
    let mut pair_index = 0usize;
    eprintln!(
        "{} shard {}/{}: {} ciphertext policies x {} user policies = {} pairs; {} iterations/pair",
        config.variant,
        config.shard_index + 1,
        config.shard_count,
        selected_enc_policies.len(),
        usk_policies.len(),
        total_pairs,
        config.iterations
    );

    for enc_policy in selected_enc_policies {
        let eap = AccessPolicy::parse(enc_policy)?;
        let ciphertext =
            PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(&cc, &mpk, &eap, PLAINTEXT)?;
        let ciphertext_bytes = {
            let mut serializer = Serializer::new();
            serializer.write(&ciphertext.0)?;
            serializer.write_vec(&ciphertext.1)?;
            serializer.finalize().len()
        };

        for user_policy in &usk_policies {
            pair_index += 1;
            let implementation_policy = if config.variant == "covercrypt" {
                baseline_user_policy(user_policy)
            } else {
                user_policy.clone()
            };
            let uap = AccessPolicy::parse(&implementation_policy)?;
            let user_rights = msk.access_structure.ap_to_usk_rights(&uap)?.len();
            let usk = cc.generate_user_secret_key(&mut msk, &uap)?;
            let user_key_bytes = usk.serialize()?.len();

            let first =
                PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(&cc, &usk, &ciphertext)?;
            let outcome = if first.is_some() {
                "success"
            } else {
                "failure"
            };
            black_box(first);

            for _ in 0..config.warmup {
                black_box(PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc,
                    &usk,
                    &ciphertext,
                )?);
            }

            let start = Instant::now();
            for _ in 0..config.iterations {
                black_box(PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc,
                    &usk,
                    &ciphertext,
                )?);
            }
            let total_ns = start.elapsed().as_nanos();
            let mean_ns = total_ns as f64 / f64::from(config.iterations);
            let y_relation = if is_complete_user_policy(user_policy) {
                "same"
            } else {
                "different"
            };

            writeln!(
                output,
                "{},{},{},{},{},{},{},{},{},{},{},{:.3}",
                config.variant,
                BASELINE_REF,
                csv_field(enc_policy),
                csv_field(user_policy),
                y_relation,
                user_rights,
                user_key_bytes,
                ciphertext_bytes,
                outcome,
                config.iterations,
                total_ns,
                mean_ns
            )?;
        }
        output.flush()?;
        eprintln!("{}: {pair_index}/{total_pairs} pairs", config.variant);
    }

    Ok(())
}

fn main() {
    let result = parse_args().map_err(|error| error.into()).and_then(run);
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
