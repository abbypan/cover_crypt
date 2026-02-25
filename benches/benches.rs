use cosmian_cover_crypt::{
    api::Covercrypt,
    traits::{KemAc, PkeAc},
    AccessPolicy,
    AccessStructure,
    QualifiedAttribute,
    EncryptionHint,
    MasterPublicKey,
    MasterSecretKey,
    Error,
}; 
use cosmian_crypto_core::Aes256Gcm;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use std::fs::File;
use std::io::Write;

// Create a custom access structure matching star.rs
fn create_custom_structure() -> Result<AccessStructure, Error> {
    let mut structure = AccessStructure::new();

    // Create a hierarchical dimension for Security Level
    structure.add_hierarchy("Security".to_string())?;

    // Add security levels (hierarchical - ordered)
    structure.add_attribute(
        QualifiedAttribute::new("Security", "LOW"),
        EncryptionHint::Classic,
        None, // Lowest level
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Security", "MED"),
        EncryptionHint::Classic,
        Some("LOW"), // After LOW
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Security", "HIGH"),
        EncryptionHint::Hybridized,
        Some("MED"), // After MED
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Security", "*"),
        EncryptionHint::Hybridized,
        Some("HIGH"), // After HIGH
    )?;

    // Create an anarchic dimension for Department
    structure.add_anarchy("Department".to_string())?;

    // Add departments (anarchic - unordered)
    structure.add_attribute(
        QualifiedAttribute::new("Department", "DEV"),
        EncryptionHint::Classic,
        None,
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Department", "MKG"),
        EncryptionHint::Classic,
        None,
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Department", "*"),
        EncryptionHint::Classic,
        None,
    )?;

    // Create another anarchic dimension for Region
    structure.add_anarchy("Region".to_string())?;

    structure.add_attribute(
        QualifiedAttribute::new("Region", "EN"),
        EncryptionHint::Classic,
        None,
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Region", "FR"),
        EncryptionHint::Classic,
        None,
    )?;
    structure.add_attribute(
        QualifiedAttribute::new("Region", "*"),
        EncryptionHint::Classic,
        None,
    )?;

    Ok(structure)
}

// Setup function that creates keys with custom structure
fn setup_with_custom_structure(
    cc: &Covercrypt,
) -> Result<(MasterSecretKey, MasterPublicKey), Error> {
    let (mut msk, _) = cc.setup()?;
    msk.access_structure = create_custom_structure()?;
    let mpk = cc.update_msk(&mut msk)?;
    Ok((msk, mpk))
}

// 合并的 encryption policies - 所有3个dimension的排列组合 (删除重复项)
// Security: null/LOW/MED/HIGH/* × Department: null/DEV/MKG/* × Region: null/EN/FR/*
// 总共: 5 × 4 × 4 = 80种组合 (Security=null只保留一份，不重复)
const ENC_APS: [(&str, usize); 79] = [
    // Security = null (只保留一份，不重复)
   // ("", 1),
    ("Department::DEV", 1),
    ("Department::MKG", 1),
    ("Department::*", 1),
    ("Region::EN", 1),
    ("Region::FR", 1),
    ("Region::*", 1),
    ("Department::DEV && Region::EN", 1),
    ("Department::DEV && Region::FR", 1),
    ("Department::DEV && Region::*", 1),
    ("Department::MKG && Region::EN", 1),
    ("Department::MKG && Region::FR", 1),
    ("Department::MKG && Region::*", 1),
    ("Department::* && Region::EN", 1),
    ("Department::* && Region::FR", 1),
    ("Department::* && Region::*", 1),
    // Security = LOW (Classical)
    ("Security::LOW", 1),
    ("Security::LOW && Department::DEV", 1),
    ("Security::LOW && Department::MKG", 1),
    ("Security::LOW && Department::*", 1),
    ("Security::LOW && Region::EN", 1),
    ("Security::LOW && Region::FR", 1),
    ("Security::LOW && Region::*", 1),
    ("Security::LOW && Department::DEV && Region::EN", 1),
    ("Security::LOW && Department::DEV && Region::FR", 1),
    ("Security::LOW && Department::DEV && Region::*", 1),
    ("Security::LOW && Department::MKG && Region::EN", 1),
    ("Security::LOW && Department::MKG && Region::FR", 1),
    ("Security::LOW && Department::MKG && Region::*", 1),
    ("Security::LOW && Department::* && Region::EN", 1),
    ("Security::LOW && Department::* && Region::FR", 1),
    ("Security::LOW && Department::* && Region::*", 1),
    // Security = MED (Classical)
    ("Security::MED", 1),
    ("Security::MED && Department::DEV", 1),
    ("Security::MED && Department::MKG", 1),
    ("Security::MED && Department::*", 1),
    ("Security::MED && Region::EN", 1),
    ("Security::MED && Region::FR", 1),
    ("Security::MED && Region::*", 1),
    ("Security::MED && Department::DEV && Region::EN", 1),
    ("Security::MED && Department::DEV && Region::FR", 1),
    ("Security::MED && Department::DEV && Region::*", 1),
    ("Security::MED && Department::MKG && Region::EN", 1),
    ("Security::MED && Department::MKG && Region::FR", 1),
    ("Security::MED && Department::MKG && Region::*", 1),
    ("Security::MED && Department::* && Region::EN", 1),
    ("Security::MED && Department::* && Region::FR", 1),
    ("Security::MED && Department::* && Region::*", 1),
    // Security = HIGH (Hybridized)
    ("Security::HIGH", 1),
    ("Security::HIGH && Department::DEV", 1),
    ("Security::HIGH && Department::MKG", 1),
    ("Security::HIGH && Department::*", 1),
    ("Security::HIGH && Region::EN", 1),
    ("Security::HIGH && Region::FR", 1),
    ("Security::HIGH && Region::*", 1),
    ("Security::HIGH && Department::DEV && Region::EN", 1),
    ("Security::HIGH && Department::DEV && Region::FR", 1),
    ("Security::HIGH && Department::DEV && Region::*", 1),
    ("Security::HIGH && Department::MKG && Region::EN", 1),
    ("Security::HIGH && Department::MKG && Region::FR", 1),
    ("Security::HIGH && Department::MKG && Region::*", 1),
    ("Security::HIGH && Department::* && Region::EN", 1),
    ("Security::HIGH && Department::* && Region::FR", 1),
    ("Security::HIGH && Department::* && Region::*", 1),
    // Security = *
    ("Security::*", 1),
    ("Security::* && Department::DEV", 1),
    ("Security::* && Department::MKG", 1),
    ("Security::* && Department::*", 1),
    ("Security::* && Region::EN", 1),
    ("Security::* && Region::FR", 1),
    ("Security::* && Region::*", 1),
    ("Security::* && Department::DEV && Region::EN", 1),
    ("Security::* && Department::DEV && Region::FR", 1),
    ("Security::* && Department::DEV && Region::*", 1),
    ("Security::* && Department::MKG && Region::EN", 1),
    ("Security::* && Department::MKG && Region::FR", 1),
    ("Security::* && Department::MKG && Region::*", 1),
    ("Security::* && Department::* && Region::EN", 1),
    ("Security::* && Department::* && Region::FR", 1),
    ("Security::* && Department::* && Region::*", 1),
];

// 合并的 USK policies - 所有3个dimension的排列组合 (删除重复项)
// Security: null/LOW/MED/HIGH/* × Department: null/DEV/MKG/* × Region: null/EN/FR/*
// 总共: 5 × 4 × 4 = 80种组合 (Security=null只保留一份，不重复)
const USK_APS: [(&str, usize); 79] = [
    // Security = null (只保留一份，不重复)
   // ("", 8),
    ("Department::DEV", 8),
    ("Department::MKG", 8),
    ("Department::*", 8),
    ("Region::EN", 8),
    ("Region::FR", 8),
    ("Region::*", 8),
    ("Department::DEV && Region::EN", 8),
    ("Department::DEV && Region::FR", 8),
    ("Department::DEV && Region::*", 8),
    ("Department::MKG && Region::EN", 8),
    ("Department::MKG && Region::FR", 8),
    ("Department::MKG && Region::*", 8),
    ("Department::* && Region::EN", 8),
    ("Department::* && Region::FR", 8),
    ("Department::* && Region::*", 8),
    // Security = LOW (Classical)
    ("Security::LOW", 8),
    ("Security::LOW && Department::DEV", 8),
    ("Security::LOW && Department::MKG", 8),
    ("Security::LOW && Department::*", 8),
    ("Security::LOW && Region::EN", 8),
    ("Security::LOW && Region::FR", 8),
    ("Security::LOW && Region::*", 8),
    ("Security::LOW && Department::DEV && Region::EN", 8),
    ("Security::LOW && Department::DEV && Region::FR", 8),
    ("Security::LOW && Department::DEV && Region::*", 8),
    ("Security::LOW && Department::MKG && Region::EN", 8),
    ("Security::LOW && Department::MKG && Region::FR", 8),
    ("Security::LOW && Department::MKG && Region::*", 8),
    ("Security::LOW && Department::* && Region::EN", 8),
    ("Security::LOW && Department::* && Region::FR", 8),
    ("Security::LOW && Department::* && Region::*", 8),
    // Security = MED (Classical)
    ("Security::MED", 20),
    ("Security::MED && Department::DEV", 20),
    ("Security::MED && Department::MKG", 20),
    ("Security::MED && Department::*", 20),
    ("Security::MED && Region::EN", 20),
    ("Security::MED && Region::FR", 20),
    ("Security::MED && Region::*", 20),
    ("Security::MED && Department::DEV && Region::EN", 20),
    ("Security::MED && Department::DEV && Region::FR", 20),
    ("Security::MED && Department::DEV && Region::*", 20),
    ("Security::MED && Department::MKG && Region::EN", 20),
    ("Security::MED && Department::MKG && Region::FR", 20),
    ("Security::MED && Department::MKG && Region::*", 20),
    ("Security::MED && Department::* && Region::EN", 20),
    ("Security::MED && Department::* && Region::FR", 20),
    ("Security::MED && Department::* && Region::*", 20),
    // Security = HIGH (Hybridized)
    ("Security::HIGH", 12),
    ("Security::HIGH && Department::DEV", 12),
    ("Security::HIGH && Department::MKG", 12),
    ("Security::HIGH && Department::*", 12),
    ("Security::HIGH && Region::EN", 12),
    ("Security::HIGH && Region::FR", 12),
    ("Security::HIGH && Region::*", 12),
    ("Security::HIGH && Department::DEV && Region::EN", 12),
    ("Security::HIGH && Department::DEV && Region::FR", 12),
    ("Security::HIGH && Department::DEV && Region::*", 12),
    ("Security::HIGH && Department::MKG && Region::EN", 12),
    ("Security::HIGH && Department::MKG && Region::FR", 12),
    ("Security::HIGH && Department::MKG && Region::*", 12),
    ("Security::HIGH && Department::* && Region::EN", 12),
    ("Security::HIGH && Department::* && Region::FR", 12),
    ("Security::HIGH && Department::* && Region::*", 12),
    // Security = * (Hybridized)
    ("Security::*", 30),
    ("Security::* && Department::DEV", 30),
    ("Security::* && Department::MKG", 30),
    ("Security::* && Department::*", 30),
    ("Security::* && Region::EN", 30),
    ("Security::* && Region::FR", 30),
    ("Security::* && Region::*", 30),
    ("Security::* && Department::DEV && Region::EN", 30),
    ("Security::* && Department::DEV && Region::FR", 30),
    ("Security::* && Department::DEV && Region::*", 30),
    ("Security::* && Department::MKG && Region::EN", 30),
    ("Security::* && Department::MKG && Region::FR", 30),
    ("Security::* && Department::MKG && Region::*", 30),
    ("Security::* && Department::* && Region::EN", 30),
    ("Security::* && Department::* && Region::FR", 30),
    ("Security::* && Department::* && Region::*", 30),
];

const PLAINTEXT: &[u8] = b"testing encryption/decryption benchmark";

/// enc_ap uses hybridized attributes (Security::HIGH or Security::*) => hybridized, else classical.
fn is_hybridized_enc_ap(enc_ap: &str) -> bool {
    enc_ap.contains("Security::HIGH") || enc_ap.contains("Security::*")
}

macro_rules! gen_enc {
    ($cc:ident, $mpk:ident, $ap:ident, $cnt:ident) => {{
        let (k, enc) = $cc
            .encaps(&$mpk, &AccessPolicy::parse($ap).unwrap())
            .unwrap();
       // assert_eq!(enc.count(), $cnt);
        (k, enc)
    }};
}

macro_rules! gen_usk {
    ($cc:ident, $msk:ident, $ap:ident, $cnt:ident) => {{
        let usk = $cc
            .generate_user_secret_key(&mut $msk, &AccessPolicy::parse($ap).unwrap())
            .unwrap();
     //   assert_eq!(usk.count(), $cnt);
        usk
    }};
}

// ... existing code up to line 301 ...

fn bench_classical_encapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Classic encapsulation");
        for (enc_ap, _cnt_enc) in ENC_APS {
            let _ = gen_enc!(cc, mpk, enc_ap, _cnt_enc);
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            // 使用enc_ap作为benchmark名称的一部分以确保唯一性
            let bench_name = if enc_ap.is_empty() {
                "empty".to_string()
            } else {
                enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            group.bench_function(format!("{}", bench_name), |b| {
                b.iter(|| cc.encaps(&mpk, &eap).unwrap())
            });
        }
    }
}

fn bench_classical_decapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Decapsulation");
        for (enc_ap, _cnt_enc) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, _cnt_secret) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let _usk = gen_usk!(cc, msk, usk_ap, _cnt_secret);

                let (_k, _enc) = gen_enc!(cc, mpk, enc_ap, _cnt_enc);
                //  assert_eq!(Some(k), cc.decaps(&usk, &enc).unwrap());

                // 使用enc_ap和usk_ap作为benchmark名称以确保唯一性
                let enc_name = if enc_ap.is_empty() {
                    "empty".to_string()
                } else {
                    enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
                };
                let usk_name = if usk_ap.is_empty() {
                    "empty".to_string()
                } else {
                    usk_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
                };
                group.bench_function(
                    format!("enc_{}_usk_{}", enc_name, usk_name),
                    |b| {
                        b.iter_batched(
                            || {
                                (
                                    cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                    cc.encaps(&mpk, &eap).unwrap(),
                                )
                            },
                            |(usk, (_, enc))| cc.decaps(&usk, &enc).unwrap(),
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
}

fn bench_hybridized_encapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized encapsulation");
        for (enc_ap, _cnt_enc) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            let _ = gen_enc!(cc, mpk, enc_ap, _cnt_enc);
            let bench_name = if enc_ap.is_empty() {
                "empty".to_string()
            } else {
                enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            group.bench_function(format!("{}", bench_name), |b| {
                b.iter(|| cc.encaps(&mpk, &eap).unwrap())
            });
        }
    }
}

fn bench_hybridized_decapsulation(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized Decapsulation");
        for (enc_ap, _enc_cnt) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, _usk_cnt) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();
                let usk = gen_usk!(cc, msk, usk_ap, _usk_cnt);
                let (k, enc) = gen_enc!(cc, mpk, enc_ap, _enc_cnt);
                // Skip when user key cannot decrypt this enc_ap (policy not satisfied)
                if cc.decaps(&usk, &enc).unwrap().is_none() {
                    continue;
                }

                let enc_name = if enc_ap.is_empty() {
                    "empty".to_string()
                } else {
                    enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
                };
                let usk_name = if usk_ap.is_empty() {
                    "empty".to_string()
                } else {
                    usk_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
                };
                group.bench_function(
                    format!("enc_{}_usk_{}", enc_name, usk_name),
                    |b| {
                        b.iter_batched(
                            || {
                                (
                                    cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                    cc.encaps(&mpk, &eap).unwrap(),
                                )
                            },
                            |(usk, (_, enc))| cc.decaps(&usk, &enc).unwrap(),
                            BatchSize::SmallInput,
                        )
                    },
                );
            }
        }
    }
}

/// Classical encryption benchmark: enc_ap that use only classic attributes.
fn bench_classical_encryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    let mut group = c.benchmark_group("Classical encryption");
    for (enc_ap, _cnt_enc) in ENC_APS.iter().filter(|(ap, _)| !is_hybridized_enc_ap(ap)) {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
            &cc,
            &mpk,
            &eap,
            PLAINTEXT,
        )
        .unwrap();
        let bench_name = if enc_ap.is_empty() {
            "empty".to_string()
        } else {
            enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
        };
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                    &cc,
                    &mpk,
                    &eap,
                    PLAINTEXT,
                )
                .unwrap()
            })
        });
    }
}

/// Hybridized encryption benchmark: enc_ap that use Security::HIGH or Security::*.
fn bench_hybridized_encryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    let mut group = c.benchmark_group("Hybridized encryption");
    for (enc_ap, _cnt_enc) in ENC_APS.iter().filter(|(ap, _)| is_hybridized_enc_ap(ap)) {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
            &cc,
            &mpk,
            &eap,
            PLAINTEXT,
        )
        .unwrap();
        let bench_name = if enc_ap.is_empty() {
            "empty".to_string()
        } else {
            enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
        };
        group.bench_function(bench_name, |b| {
            b.iter(|| {
                PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                    &cc,
                    &mpk,
                    &eap,
                    PLAINTEXT,
                )
                .unwrap()
            })
        });
    }
}

/// Classical decryption benchmark: enc_ap that use only classic attributes.
fn bench_classical_decryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    let mut group = c.benchmark_group("Classical decryption");
    for (enc_ap, _cnt_enc) in ENC_APS.iter().filter(|(ap, _)| !is_hybridized_enc_ap(ap)) {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _cnt_secret) in USK_APS.iter() {
            let uap = AccessPolicy::parse(usk_ap).unwrap();

            let usk = gen_usk!(cc, msk, usk_ap, _cnt_secret);
            let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            )
            .unwrap();
            // Skip when user key cannot decrypt this enc_ap (policy not satisfied)
            if PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                &cc, &usk, &ctx,
            )
            .unwrap()
            .is_none()
            {
                continue;
            }

            let enc_name = if enc_ap.is_empty() {
                "empty".to_string()
            } else {
                enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            let usk_name = if usk_ap.is_empty() {
                "empty".to_string()
            } else {
                usk_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            group.bench_function(
                format!("enc_{}_usk_{}", enc_name, usk_name),
                |b| {
                    b.iter_batched(
                        || {
                            (
                                cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                                    &cc,
                                    &mpk,
                                    &eap,
                                    PLAINTEXT,
                                )
                                .unwrap(),
                            )
                        },
                        |(usk, ctx)| {
                            PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                                &cc, &usk, &ctx,
                            )
                            .unwrap()
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }
}

/// Hybridized decryption benchmark: enc_ap that use Security::HIGH or Security::*.
fn bench_hybridized_decryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    let mut group = c.benchmark_group("Hybridized decryption");
    for (enc_ap, _cnt_enc) in ENC_APS.iter().filter(|(ap, _)| is_hybridized_enc_ap(ap)) {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _cnt_secret) in USK_APS.iter() {
            let uap = AccessPolicy::parse(usk_ap).unwrap();

            let usk = gen_usk!(cc, msk, usk_ap, _cnt_secret);
            let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            )
            .unwrap();
            // Skip when user key cannot decrypt this enc_ap (policy not satisfied)
            if PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                &cc, &usk, &ctx,
            )
            .unwrap()
            .is_none()
            {
                continue;
            }

            let enc_name = if enc_ap.is_empty() {
                "empty".to_string()
            } else {
                enc_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            let usk_name = if usk_ap.is_empty() {
                "empty".to_string()
            } else {
                usk_ap.replace("::", "_").replace(" && ", "_").replace(" ", "")
            };
            group.bench_function(
                format!("enc_{}_usk_{}", enc_name, usk_name),
                |b| {
                    b.iter_batched(
                        || {
                            (
                                cc.generate_user_secret_key(&mut msk, &uap).unwrap(),
                                PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                                    &cc,
                                    &mpk,
                                    &eap,
                                    PLAINTEXT,
                                )
                                .unwrap(),
                            )
                        },
                        |(usk, ctx)| {
                            PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                                &cc, &usk, &ctx,
                            )
                            .unwrap()
                        },
                        BatchSize::SmallInput,
                    )
                },
            );
        }
    }
}

// ... rest of the file remains the same ...
// ... existing code up to line 572 ...

const CSV_ITERATIONS: u32 = 1000;

/// One row per (enc_ap, user_ap). Columns: enc_ap, user_ap, type (classical|hybridized), encryption, decryption, decryption_result (success|fail).
/// Progress is printed to stderr.
fn collect_benchmark_results_to_csv() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::{stderr, Write as _};

    let total_enc = ENC_APS.len();
    let total_usk = USK_APS.len();
    let total_rows = total_enc * total_usk;

    eprintln!("Writing benchmark results to benchmark_results.csv");
    eprintln!("  Total: {} enc_ap × {} user_ap = {} rows", total_enc, total_usk, total_rows);

    let mut file = File::create("benchmark_results.csv")?;
    let header = "enc_ap,user_ap,type,encryption,decryption,decryption_result";
    writeln!(file, "{}", header)?;
    println!("{}", header);

    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc)?;

    // Encryption time per enc_ap (same for all user_ap in that row)
    eprintln!("  Phase 1/2: measuring encryption times ({} enc_ap)...", total_enc);
    let mut enc_times_ns = Vec::with_capacity(total_enc);
    for (i, (enc_ap, _)) in ENC_APS.iter().enumerate() {
        let eap = AccessPolicy::parse(*enc_ap).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..CSV_ITERATIONS {
            let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc, &mpk, &eap, PLAINTEXT,
            )
            .unwrap();
        }
        enc_times_ns.push((start.elapsed().as_nanos() / CSV_ITERATIONS as u128) as u64);
        eprintln!("    encryption {} / {}", i + 1, total_enc);
        let _ = stderr().flush();
    }

    // Decryption times and CSV rows
    eprintln!("  Phase 2/2: measuring decryption & writing CSV ({} rows)...", total_rows);
    let mut rows_written = 0usize;
    for (enc_idx, (enc_ap, _cnt_enc)) in ENC_APS.iter().enumerate() {
        let eap = AccessPolicy::parse(*enc_ap).unwrap();
        let encryption_ns = enc_times_ns[enc_idx];
        let row_type = if is_hybridized_enc_ap(enc_ap) {
            "hybridized"
        } else {
            "classical"
        };

        for (usk_ap, _cnt_secret) in USK_APS.iter() {
            let uap = AccessPolicy::parse(*usk_ap).unwrap();
            let usk = cc.generate_user_secret_key(&mut msk, &uap).unwrap();
            let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            )
            .unwrap();

            let decryption_result = if PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                &cc, &usk, &ctx,
            )
            .unwrap()
            .is_some()
            {
                "success"
            } else {
                "fail"
            };

            let start = std::time::Instant::now();
            for _ in 0..CSV_ITERATIONS {
                let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc, &usk, &ctx,
                )
                .unwrap();
            }
            let decryption_ns =
                (start.elapsed().as_nanos() / CSV_ITERATIONS as u128) as u64;

            let line = format!(
                "\"{}\",\"{}\",{},{},{},{}",
                enc_ap.replace('"', "\"\""),
                usk_ap.replace('"', "\"\""),
                row_type,
                encryption_ns,
                decryption_ns,
                decryption_result
            );
            writeln!(file, "{}", line)?;
            println!("{}", line);
            rows_written += 1;
        }
        eprintln!("    enc_ap {} / {} (rows {})", enc_idx + 1, total_enc, rows_written);
        let _ = stderr().flush();
    }

    eprintln!("Done. {} rows written to benchmark_results.csv", rows_written);
    Ok(())
}

fn bench_collect_results(_c: &mut Criterion) {
    if let Err(e) = collect_benchmark_results_to_csv() {
        eprintln!("Error collecting benchmark results: {}", e);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(2000);
    targets =
    bench_classical_encapsulation,
    bench_classical_decapsulation,
    bench_hybridized_encapsulation,
    bench_hybridized_decapsulation,
    bench_classical_encryption,
    bench_hybridized_encryption,
    bench_classical_decryption,
    bench_hybridized_decryption,
    bench_collect_results
);

criterion_main!(benches);