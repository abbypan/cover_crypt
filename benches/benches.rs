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
        for (enc_ap, cnt_enc) in ENC_APS {
            let _ = gen_enc!(cc, mpk, enc_ap, cnt_enc);
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
        for (enc_ap, cnt_enc) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, cnt_secret) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let usk = gen_usk!(cc, msk, usk_ap, cnt_secret);

                let (k, enc) = gen_enc!(cc, mpk, enc_ap, cnt_enc);
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
        for (enc_ap, cnt_enc) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            let _ = gen_enc!(cc, mpk, enc_ap, cnt_enc);
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
        for (enc_ap, enc_cnt) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, usk_cnt) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();
                let usk = gen_usk!(cc, msk, usk_ap, usk_cnt);
                let (k, enc) = gen_enc!(cc, mpk, enc_ap, enc_cnt);
                assert_eq!(Some(k), cc.decaps(&usk, &enc).unwrap());

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

fn bench_classical_encryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Classic encryption");
        for (enc_ap, cnt_enc) in ENC_APS {
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
            group.bench_function(format!("{}", bench_name), |b| {
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
}

fn bench_classical_decryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Classic decryption");
        for (enc_ap, cnt_enc) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, cnt_secret) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();

                let usk = gen_usk!(cc, msk, usk_ap, cnt_secret);
                let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                    &cc,
                    &mpk,
                    &eap,
                    PLAINTEXT,
                )
                .unwrap();
                assert!(PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc, &usk, &ctx
                )
                .unwrap()
                .is_some());

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
}

fn bench_hybridized_encryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (_, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized encryption");
        for (enc_ap, cnt_enc) in ENC_APS {
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
            group.bench_function(format!("{}", bench_name), |b| {
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
}

fn bench_hybridized_decryption(c: &mut Criterion) {
    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc).unwrap();

    {
        let mut group = c.benchmark_group("Hybridized decryption");
        for (enc_ap, enc_cnt) in ENC_APS {
            let eap = AccessPolicy::parse(enc_ap).unwrap();
            for (usk_ap, usk_cnt) in USK_APS {
                let uap = AccessPolicy::parse(usk_ap).unwrap();
                let usk = gen_usk!(cc, msk, usk_ap, usk_cnt);
                let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                    &cc,
                    &mpk,
                    &eap,
                    PLAINTEXT,
                )
                .unwrap();
                assert!(PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc, &usk, &ctx
                )
                .unwrap()
                .is_some());

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
}

// ... rest of the file remains the same ...
// ... existing code up to line 572 ...

// 收集所有benchmark结果并写入CSV文件
fn collect_benchmark_results_to_csv() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::create("benchmark_results.csv")?;
    writeln!(file, "benchmark_type,enc_ap,uap,time_ns")?;

    let cc = Covercrypt::default();
    let (mut msk, mpk) = setup_with_custom_structure(&cc)?;

    // Classical Encapsulation
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = cc.encaps(&mpk, &eap).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / 1000;
        writeln!(file, "Classical Encapsulation,\"{}\",\"\",{}", enc_ap, avg_ns)?;
    }

    // Classical Decapsulation
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _cnt_secret) in USK_APS {
            let uap = AccessPolicy::parse(usk_ap).unwrap();
            let usk = cc.generate_user_secret_key(&mut msk, &uap).unwrap();
            let (_, enc) = cc.encaps(&mpk, &eap).unwrap();
            
            let start = std::time::Instant::now();
            for _ in 0..1000 {
                let _ = cc.decaps(&usk, &enc).unwrap();
            }
            let elapsed = start.elapsed();
            let avg_ns = elapsed.as_nanos() / 1000;
            writeln!(file, "Classical Decapsulation,\"{}\",\"{}\",{}", enc_ap, usk_ap, avg_ns)?;
        }
    }

    // Hybridized Encapsulation
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = cc.encaps(&mpk, &eap).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / 1000;
        writeln!(file, "Hybridized Encapsulation,\"{}\",\"\",{}", enc_ap, avg_ns)?;
    }

    // Hybridized Decapsulation
    for (enc_ap, _enc_cnt) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _usk_cnt) in USK_APS {
            let uap = AccessPolicy::parse(usk_ap).unwrap();
            let usk = cc.generate_user_secret_key(&mut msk, &uap).unwrap();
            let (_, enc) = cc.encaps(&mpk, &eap).unwrap();
            
            let start = std::time::Instant::now();
            for _ in 0..1000 {
                let _ = cc.decaps(&usk, &enc).unwrap();
            }
            let elapsed = start.elapsed();
            let avg_ns = elapsed.as_nanos() / 1000;
            writeln!(file, "Hybridized Decapsulation,\"{}\",\"{}\",{}", enc_ap, usk_ap, avg_ns)?;
        }
    }

    // Classical Encryption
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            ).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / 1000;
        writeln!(file, "Classical Encryption,\"{}\",\"\",{}", enc_ap, avg_ns)?;
    }

    // Classical Decryption
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _cnt_secret) in USK_APS {
            let uap = AccessPolicy::parse(usk_ap).unwrap();
            let usk = cc.generate_user_secret_key(&mut msk, &uap).unwrap();
            let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            ).unwrap();
            
            let start = std::time::Instant::now();
            for _ in 0..1000 {
                let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc, &usk, &ctx
                ).unwrap();
            }
            let elapsed = start.elapsed();
            let avg_ns = elapsed.as_nanos() / 1000;
            writeln!(file, "Classical Decryption,\"{}\",\"{}\",{}", enc_ap, usk_ap, avg_ns)?;
        }
    }

    // Hybridized Encryption
    for (enc_ap, _cnt_enc) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            ).unwrap();
        }
        let elapsed = start.elapsed();
        let avg_ns = elapsed.as_nanos() / 1000;
        writeln!(file, "Hybridized Encryption,\"{}\",\"\",{}", enc_ap, avg_ns)?;
    }

    // Hybridized Decryption
    for (enc_ap, _enc_cnt) in ENC_APS {
        let eap = AccessPolicy::parse(enc_ap).unwrap();
        for (usk_ap, _usk_cnt) in USK_APS {
            let uap = AccessPolicy::parse(usk_ap).unwrap();
            let usk = cc.generate_user_secret_key(&mut msk, &uap).unwrap();
            let ctx = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::encrypt(
                &cc,
                &mpk,
                &eap,
                PLAINTEXT,
            ).unwrap();
            
            let start = std::time::Instant::now();
            for _ in 0..1000 {
                let _ = PkeAc::<{ Aes256Gcm::KEY_LENGTH }, Aes256Gcm>::decrypt(
                    &cc, &usk, &ctx
                ).unwrap();
            }
            let elapsed = start.elapsed();
            let avg_ns = elapsed.as_nanos() / 1000;
            writeln!(file, "Hybridized Decryption,\"{}\",\"{}\",{}", enc_ap, usk_ap, avg_ns)?;
        }
    }

    Ok(())
}

fn bench_collect_results(c: &mut Criterion) {
    if let Err(e) = collect_benchmark_results_to_csv() {
        eprintln!("Error collecting benchmark results: {}", e);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(20);
    targets =
    bench_classical_encapsulation,
    bench_classical_decapsulation,
    bench_hybridized_encapsulation,
    bench_hybridized_decapsulation,
    bench_classical_encryption,
    bench_classical_decryption,
    bench_hybridized_encryption,
    bench_hybridized_decryption,
    bench_collect_results
);

criterion_main!(benches);