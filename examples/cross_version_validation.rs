//! Cross-build policy and wire-compatibility validation for the paper artifact.
//!
//! The source intentionally uses only the public API shared by Covercrypt v15
//! and LP-Covercrypt. `benches/run_cross_version_validation.sh` copies it into
//! a clean v15 checkout and executes every producer/consumer combination.

use cosmian_cover_crypt::{
    api::Covercrypt, traits::PkeAc, AccessPolicy, AccessStructure, EncryptionHint, MasterPublicKey,
    MasterSecretKey, QualifiedAttribute, UserSecretKey, XEnc,
};
use cosmian_crypto_core::{
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    Aes256Gcm,
};
use serde_json::{json, Value};
use std::{
    env,
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
};

const MAXIMUM: &str = "$";

#[derive(Clone, Copy)]
enum Scenario {
    Classic,
    Hybridized,
}

impl Scenario {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "classic" => Ok(Self::Classic),
            "hybridized" => Ok(Self::Hybridized),
            _ => Err("scenario must be classic or hybridized".to_string()),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Classic => "classic",
            Self::Hybridized => "hybridized",
        }
    }

    fn hint(self) -> EncryptionHint {
        match self {
            Self::Classic => EncryptionHint::Classic,
            Self::Hybridized => EncryptionHint::Hybridized,
        }
    }
}

fn has_attribute(structure: &AccessStructure, dimension: &str, name: &str) -> bool {
    structure
        .attributes()
        .any(|attribute| attribute.dimension == dimension && attribute.name == name)
}

fn add_baseline_maximum(
    structure: &mut AccessStructure,
    dimension: &str,
    hint: EncryptionHint,
) -> Result<(), Box<dyn std::error::Error>> {
    if !has_attribute(structure, dimension, MAXIMUM) {
        structure.add_attribute(QualifiedAttribute::new(dimension, MAXIMUM), hint, None)?;
    }
    Ok(())
}

fn create_structure(scenario: Scenario) -> Result<AccessStructure, Box<dyn std::error::Error>> {
    let mut structure = AccessStructure::new();
    let hint = scenario.hint();

    structure.add_hierarchy("SEC".to_string())?;
    add_baseline_maximum(&mut structure, "SEC", hint)?;
    structure.add_attribute(QualifiedAttribute::new("SEC", "LOW"), hint, None)?;
    structure.add_attribute(QualifiedAttribute::new("SEC", "MED"), hint, Some("LOW"))?;
    structure.add_attribute(QualifiedAttribute::new("SEC", "HIG"), hint, Some("MED"))?;

    structure.add_anarchy("DPT".to_string())?;
    add_baseline_maximum(&mut structure, "DPT", hint)?;
    structure.add_attribute(QualifiedAttribute::new("DPT", "DEV"), hint, None)?;
    structure.add_attribute(QualifiedAttribute::new("DPT", "MKG"), hint, None)?;

    structure.add_anarchy("CTR".to_string())?;
    add_baseline_maximum(&mut structure, "CTR", hint)?;
    structure.add_attribute(QualifiedAttribute::new("CTR", "EN"), hint, None)?;
    structure.add_attribute(QualifiedAttribute::new("CTR", "FR"), hint, None)?;

    Ok(structure)
}

fn baseline_key_policy(policy: &str) -> String {
    policy
        .replace("DPT::$", "(DPT::DEV || DPT::MKG || DPT::$)")
        .replace("CTR::$", "(CTR::EN || CTR::FR || CTR::$)")
}

fn implementation_key_policy(variant: &str, policy: &str) -> String {
    if variant == "covercrypt" {
        baseline_key_policy(policy)
    } else {
        policy.to_string()
    }
}

fn bytes_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_json(path: &Path, value: &Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn complete_key_policies() -> Vec<String> {
    let mut policies = Vec::new();
    for sec in ["LOW", "MED", "HIG", MAXIMUM] {
        for dpt in ["DEV", "MKG", MAXIMUM] {
            for ctr in ["EN", "FR", MAXIMUM] {
                policies.push(format!("SEC::{sec} && DPT::{dpt} && CTR::{ctr}"));
            }
        }
    }
    policies
}

fn run_boolean(variant: &str, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let structure = create_structure(Scenario::Classic)?;
    let key_policies = complete_key_policies();
    let mut key_rights = Vec::new();
    for source in &key_policies {
        let implementation = implementation_key_policy(variant, source);
        let policy = AccessPolicy::parse(&implementation)?;
        key_rights.push(structure.ap_to_usk_rights(&policy)?);
    }

    let cases = [
        ("atomic", "DPT::DEV", "preservation"),
        ("duplicate_clause", "DPT::DEV || DPT::DEV", "preservation"),
        (
            "hierarchical_subsumption",
            "SEC::LOW || SEC::HIG",
            "preservation",
        ),
        (
            "cross_dimension_subsumption",
            "DPT::DEV || (DPT::DEV && SEC::HIG)",
            "preservation",
        ),
        (
            "dnf_overlap",
            "(SEC::LOW || SEC::HIG) && (DPT::DEV || DPT::MKG)",
            "preservation",
        ),
        (
            "redundant_hierarchical_disjunct",
            "(DPT::DEV && SEC::LOW) || (DPT::DEV && SEC::HIG)",
            "preservation",
        ),
        ("right_broadcast_or", "SEC::LOW || *", "preservation"),
        ("right_broadcast_and", "SEC::LOW && *", "preservation"),
        ("hierarchical_maximum", "SEC::$", "preservation"),
        ("anarchic_maximum", "DPT::$", "preservation"),
        (
            "repeated_hierarchy_conjunction",
            "SEC::LOW && SEC::HIG",
            "intentional_language_change",
        ),
        (
            "incomparable_anarchy_conjunction",
            "DPT::DEV && DPT::MKG",
            "intentional_language_change",
        ),
        ("unknown_attribute", "DPT::UNKNOWN", "rejected_input"),
        ("unknown_dimension", "UNKNOWN::VALUE", "rejected_input"),
    ];

    let mut results = Vec::new();
    for (name, source, class) in cases {
        let compiled = AccessPolicy::parse(source)
            .map_err(|error| error.to_string())
            .and_then(|policy| {
                structure
                    .ap_to_enc_rights(&policy)
                    .map_err(|error| error.to_string())
            });
        match compiled {
            Ok(rights) => {
                let mut canonical_rights = rights
                    .iter()
                    .map(|right| bytes_hex(right))
                    .collect::<Vec<_>>();
                canonical_rights.sort_unstable();
                let decisions = key_rights
                    .iter()
                    .map(|key| !rights.is_disjoint(key))
                    .collect::<Vec<_>>();
                results.push(json!({
                    "name": name,
                    "source": source,
                    "class": class,
                    "accepted": true,
                    "canonical_rights": canonical_rights,
                    "complete_key_decisions": decisions,
                }));
            }
            Err(error) => results.push(json!({
                "name": name,
                "source": source,
                "class": class,
                "accepted": false,
                "error": error,
            })),
        }
    }

    write_json(
        output,
        &json!({
            "variant": variant,
            "complete_key_policies": key_policies,
            "cases": results,
        }),
    )
}

fn serialize_pke(
    path: &Path,
    ciphertext: &(XEnc, Vec<u8>),
) -> Result<(), Box<dyn std::error::Error>> {
    let mut serializer = Serializer::new();
    serializer.write(&ciphertext.0)?;
    serializer.write_vec(&ciphertext.1)?;
    fs::write(path, serializer.finalize())?;
    Ok(())
}

fn deserialize_pke(bytes: &[u8]) -> Result<(XEnc, Vec<u8>), Box<dyn std::error::Error>> {
    let mut deserializer = Deserializer::new(bytes);
    let encapsulation = deserializer.read::<XEnc>()?;
    let payload = deserializer.read_vec()?;
    Ok((encapsulation, payload))
}

fn run_produce(
    variant: &str,
    scenario: Scenario,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(directory)?;
    let cc = Covercrypt::default();
    let (mut msk, _) = cc.setup()?;
    msk.access_structure = create_structure(scenario)?;
    let mpk = cc.update_msk(&mut msk)?;

    fs::write(
        directory.join("access-structure.bin"),
        msk.access_structure.serialize()?,
    )?;
    fs::write(directory.join("msk.bin"), msk.serialize()?)?;
    fs::write(directory.join("mpk.bin"), mpk.serialize()?)?;

    let key_sources = [
        ("maximum", "SEC::$ && DPT::$ && CTR::$"),
        ("concrete", "SEC::HIG && DPT::DEV && CTR::EN"),
        ("omitted", "SEC::MED"),
    ];
    for (name, source) in key_sources {
        let implementation = implementation_key_policy(variant, source);
        let policy = AccessPolicy::parse(&implementation)?;
        let usk = cc.generate_user_secret_key(&mut msk, &policy)?;
        fs::write(directory.join(format!("usk-{name}.bin")), usk.serialize()?)?;
    }

    let ciphertext_sources = [
        ("broadcast", "*"),
        ("hierarchy", "SEC::LOW"),
        ("maximum", "DPT::$"),
        ("boolean_subsumption", "DPT::DEV || (DPT::DEV && SEC::HIG)"),
        ("omitted_witness", "DPT::DEV"),
    ];
    for (name, source) in ciphertext_sources {
        let policy = AccessPolicy::parse(source)?;
        let plaintext = format!("cross-version:{name}");
        let ciphertext = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
            &cc,
            &mpk,
            &policy,
            plaintext.as_bytes(),
        )?;
        serialize_pke(&directory.join(format!("pke-{name}.bin")), &ciphertext)?;
    }

    write_json(
        &directory.join("manifest.json"),
        &json!({"producer": variant, "scenario": scenario.name()}),
    )
}

fn deserialize_status<T: Serializable>(bytes: &[u8]) -> bool {
    T::deserialize(bytes).is_ok()
}

fn decrypt_case(
    cc: &Covercrypt,
    directory: &Path,
    key: &UserSecretKey,
    name: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    let bytes = fs::read(directory.join(format!("pke-{name}.bin")))?;
    let ciphertext = deserialize_pke(&bytes)?;
    let plaintext = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(cc, key, &ciphertext)?;
    let expected = format!("cross-version:{name}");
    Ok(plaintext.as_deref().map(|value| value.as_slice()) == Some(expected.as_bytes()))
}

fn run_consume(
    consumer: &str,
    producer: &str,
    scenario: Scenario,
    directory: &Path,
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let same_version = consumer == producer;
    let structure_ok =
        deserialize_status::<AccessStructure>(&fs::read(directory.join("access-structure.bin"))?);
    let msk_ok = deserialize_status::<MasterSecretKey>(&fs::read(directory.join("msk.bin"))?);
    let mpk_ok = deserialize_status::<MasterPublicKey>(&fs::read(directory.join("mpk.bin"))?);

    if structure_ok != same_version || msk_ok != same_version || mpk_ok != same_version {
        return Err(format!(
            "unexpected stateful-object compatibility: structure={structure_ok}, msk={msk_ok}, mpk={mpk_ok}, same_version={same_version}"
        )
        .into());
    }

    let maximum = UserSecretKey::deserialize(&fs::read(directory.join("usk-maximum.bin"))?)?;
    let concrete = UserSecretKey::deserialize(&fs::read(directory.join("usk-concrete.bin"))?)?;
    let omitted = UserSecretKey::deserialize(&fs::read(directory.join("usk-omitted.bin"))?)?;
    let cc = Covercrypt::default();

    let cases = [
        (
            "maximum_key_broadcast",
            decrypt_case(&cc, directory, &maximum, "broadcast")?,
            true,
        ),
        (
            "maximum_key_hierarchy",
            decrypt_case(&cc, directory, &maximum, "hierarchy")?,
            true,
        ),
        (
            "maximum_key_maximum",
            decrypt_case(&cc, directory, &maximum, "maximum")?,
            true,
        ),
        (
            "concrete_key_maximum",
            decrypt_case(&cc, directory, &concrete, "maximum")?,
            false,
        ),
        (
            "concrete_key_boolean_subsumption",
            decrypt_case(&cc, directory, &concrete, "boolean_subsumption")?,
            true,
        ),
        (
            "omitted_key_concrete_dimension",
            decrypt_case(&cc, directory, &omitted, "omitted_witness")?,
            producer == "covercrypt",
        ),
    ];
    for (name, actual, expected) in cases {
        if actual != expected {
            return Err(format!("{name}: expected {expected}, got {actual}").into());
        }
    }

    write_json(
        output,
        &json!({
            "producer": producer,
            "consumer": consumer,
            "scenario": scenario.name(),
            "stateful_objects": {
                "access_structure_deserialized": structure_ok,
                "msk_deserialized": msk_ok,
                "mpk_deserialized": mpk_ok,
                "expected": if same_version { "accepted" } else { "rejected_version_boundary" },
            },
            "stateless_wire_objects": {
                "usk_deserialized": true,
                "pke_ciphertexts_deserialized": true,
                "decisions": cases.iter().map(|(name, actual, expected)| json!({
                    "case": name,
                    "actual": actual,
                    "expected": expected,
                })).collect::<Vec<_>>(),
            },
        }),
    )
}

fn require_arg(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing {name}"))
}

fn main() {
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let mut args = env::args().skip(1);
        let mode = require_arg(&mut args, "mode")?;
        match mode.as_str() {
            "boolean" => {
                let variant = require_arg(&mut args, "variant")?;
                let output = PathBuf::from(require_arg(&mut args, "output")?);
                run_boolean(&variant, &output)
            }
            "produce" => {
                let variant = require_arg(&mut args, "variant")?;
                let scenario = Scenario::parse(&require_arg(&mut args, "scenario")?)?;
                let directory = PathBuf::from(require_arg(&mut args, "directory")?);
                run_produce(&variant, scenario, &directory)
            }
            "consume" => {
                let consumer = require_arg(&mut args, "consumer")?;
                let producer = require_arg(&mut args, "producer")?;
                let scenario = Scenario::parse(&require_arg(&mut args, "scenario")?)?;
                let directory = PathBuf::from(require_arg(&mut args, "directory")?);
                let output = PathBuf::from(require_arg(&mut args, "output")?);
                run_consume(&consumer, &producer, scenario, &directory, &output)
            }
            _ => Err(format!("unknown mode: {mode}").into()),
        }
    })();

    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(2);
    }
}
