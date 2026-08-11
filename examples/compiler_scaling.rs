//! Measure the compiler-side Cartesian-product growth reported in the paper.

use cosmian_cover_crypt::{
    AccessPolicy, AccessStructure, EncryptionHint, Error, QualifiedAttribute,
};
use std::{hint::black_box, time::Instant};

const WARMUP: usize = 50;
const SAMPLES: usize = 500;

fn median_ns(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn compile_samples(
    structure: &AccessStructure,
    policy: &AccessPolicy,
) -> Result<(usize, u128), Error> {
    for _ in 0..WARMUP {
        black_box(structure.ap_to_usk_rights(black_box(policy))?);
    }

    let mut samples = Vec::with_capacity(SAMPLES);
    let mut rights = 0usize;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        let compiled = structure.ap_to_usk_rights(black_box(policy))?;
        samples.push(start.elapsed().as_nanos());
        rights = compiled.len();
        black_box(compiled);
    }
    Ok((rights, median_ns(&mut samples)))
}

fn main() -> Result<(), Error> {
    println!("dimensions,lp_rights,unrestricted_rights,lp_median_ns,unrestricted_median_ns");
    for dimension_count in 2u32..=5 {
        let mut structure = AccessStructure::new();
        for dimension_index in 0..dimension_count {
            let dimension = format!("D{dimension_index}");
            structure.add_anarchy(dimension.clone())?;
            for attribute_index in 0..3 {
                let attribute = format!("V{attribute_index}");
                structure.add_attribute(
                    QualifiedAttribute::new(&dimension, &attribute),
                    EncryptionHint::Classic,
                    None,
                )?;
            }
        }

        let lp = AccessPolicy::parse("D0::V0")?;
        let unrestricted_source = std::iter::once("D0::V0".to_string())
            .chain((1..dimension_count).map(|index| format!("D{index}::$")))
            .collect::<Vec<_>>()
            .join(" && ");
        let unrestricted = AccessPolicy::parse(&unrestricted_source)?;
        let (lp_rights, lp_ns) = compile_samples(&structure, &lp)?;
        let (unrestricted_rights, unrestricted_ns) = compile_samples(&structure, &unrestricted)?;

        println!("{dimension_count},{lp_rights},{unrestricted_rights},{lp_ns},{unrestricted_ns}");
    }
    Ok(())
}
