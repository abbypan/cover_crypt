//! Example demonstrating complementary rights (comp_rights) generation
//! for different access policies.

use cosmian_cover_crypt::{AccessPolicy, AccessStructure, QualifiedAttribute, EncryptionHint, Error};
use cosmian_crypto_core::bytes_ser_de::Deserializer;
use std::collections::{HashMap, HashSet};

// Build a map from attribute ID to attribute name
// We use the fact that generating associated rights for a single attribute
// gives us a right containing just that attribute's ID
fn build_id_to_attr_map(structure: &AccessStructure) -> HashMap<usize, String> {
    let mut id_map = HashMap::new();
    
    // Generate rights for each attribute individually to find their IDs
    for attr in structure.attributes() {
        let ap_str = format!("{}::{}", attr.dimension, attr.name);
        if let Ok(ap) = AccessPolicy::parse(&ap_str) {
            if let Ok(assoc_rights) = structure.ap_to_enc_rights(&ap) {
                // The associated right should contain just one attribute ID
                for right in assoc_rights {
                    // Right implements Deref to [u8], so &*right gives &[u8]
                    if !right.is_empty() {
                        let mut de = Deserializer::new(&*right);
                        if !de.value().is_empty() {
                            if let Ok(id) = de.read_leb128_u64() {
                                id_map.insert(id as usize, ap_str.clone());
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    
    id_map
}

// Helper function to decode a Right back to attribute names
// Right implements Deref<Target = [u8]>, so we can access it as &[u8]
fn decode_right_to_attributes(
    right_bytes: &[u8],
    id_map: &HashMap<usize, String>,
) -> Result<Vec<String>, Error> {
    let mut de = Deserializer::new(right_bytes);
    let mut attr_names = Vec::new();

    // Read all LEB128-encoded IDs until we run out of bytes
    while !de.value().is_empty() {
        let id = de.read_leb128_u64()? as usize;
        if let Some(attr_name) = id_map.get(&id) {
            attr_names.push(attr_name.clone());
        }
    }
    Ok(attr_names)
}

// Function to print rights in a light/minimal style
fn print_rights<R>(rights: &HashSet<R>, id_map: &HashMap<usize, String>) -> Result<(), Error>
where
    R: std::ops::Deref<Target = [u8]> + std::cmp::Ord,
{
    let mut sorted_rights: Vec<_> = rights.iter().collect();
    sorted_rights.sort();
    
    for right in sorted_rights.iter() {
        let attrs = decode_right_to_attributes(&**right, id_map)?;
        if attrs.is_empty() {
            println!("  Empty right");
        } else {
            println!("  {}", attrs.join(" + "));
        }
    }
    Ok(())
}

// Create a custom access structure with custom attributes
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
        Some("HIGH"), // After MED
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

fn main() -> Result<(), Error> {
    let structure = create_custom_structure()?;

    // Build ID to attribute name mapping
    let id_map = build_id_to_attr_map(&structure);

    // Print attribute ID mapping
    println!("\n=== Attribute ID Mapping ===");
    let mut sorted_ids: Vec<_> = id_map.iter().collect();
    sorted_ids.sort_by_key(|(id, _)| **id);
    for (id, name) in sorted_ids {
        println!("  ID {}: {}", id, name);
    }
    println!();

    // Test 1: Complex policy with disjunction and conjunction
    {
        let ap_str = "(Department::DEV || Department::MKG) && Security::HIGH";
        let ap = AccessPolicy::parse(ap_str)?;
             
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 1: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }


    {
        let ap_str = "Department::DEV";
        let ap = AccessPolicy::parse(ap_str)?;
             
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 2: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }


    // Test 2: Simple single attribute policy
    {
        let ap_str = "Region::EN";
        let ap = AccessPolicy::parse(ap_str)?;
            
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 2: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }

    // Test 3: Security level policy (hierarchical)
    {
        let ap_str = "Security::LOW";
        let ap = AccessPolicy::parse(ap_str)?;
            
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 3: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }

    // Test 4: Compare complementary vs associated rights
    {
        let ap_str = "Security::MED && Region::FR";
        let ap = AccessPolicy::parse(ap_str)?;
        
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 4: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }

    // Test 5: Multi-dimensional policy
    {
        let ap_str = "Department::DEV && Security::MED && Region::FR";
        let ap = AccessPolicy::parse(ap_str)?;
          
        let comp_rights = structure.ap_to_usk_rights(&ap)?;
        let assoc_rights = structure.ap_to_enc_rights(&ap)?;

        println!("=== Test 5: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }


    {
        let ap_str = "Security::MED && Region::FR && Department::*";
        let ap = AccessPolicy::parse(ap_str)?;
        
        

        let comp_rights = structure.ap_to_usk_rights(&ap)?;

        let assoc_rights = structure.ap_to_enc_rights(&ap)?;
      
        println!("=== Test 6: Comparison (policy: {}) ===", ap_str);
        println!("Associated rights (what the policy covers): {} right(s)", assoc_rights.len());
        print_rights(&assoc_rights, &id_map)?;
        
        println!("\nComplementary rights (what the policy does NOT cover): {} right(s)", comp_rights.len());
        print_rights(&comp_rights, &id_map)?;
        println!();
    }

    Ok(())
}
