use std::collections::{hash_map::Entry, HashMap, HashSet};

use crate::{
    abe_policy::{
        AccessPolicy, Attribute, AttributeStatus, Dimension, EncryptionHint, QualifiedAttribute,
        Right,
    },
    Error,
};

use super::{
    dimension::{validate_ordinary_name, MAX_ATTRIBUTE_NAME},
    Version,
};

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AccessStructure {
    version: Version,
    // This watermark survives deletion and serialization. Never reconstruct it
    // from live attributes: an issued key may still contain a retired ID.
    // Rollback or concurrent forks of a structure require external coordination.
    next_attribute_id: usize,
    // Use a hash-map to efficiently find dimensions by name.
    dimensions: HashMap<String, Dimension>,
}

impl AccessStructure {
    pub fn new() -> Self {
        Self {
            version: Version::V2,
            next_attribute_id: 0,
            dimensions: HashMap::new(),
        }
    }

    /// Generate the set of USK rights described by the given access policy.
    pub fn ap_to_usk_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_complementary_rights(ap)
    }

    /// Generate the set of ciphertext rights described by the given access policy.
    pub fn ap_to_enc_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        self.generate_associated_rights(ap)
    }

    fn available_attribute_id(&self) -> Result<usize, Error> {
        // Reserve space for the next watermark before mutating the structure.
        // Successful registration commits the increment; failures consume no ID.
        self.next_attribute_id
            .checked_add(1)
            .map(|_| self.next_attribute_id)
            .ok_or_else(|| {
                Error::OperationNotPermitted("attribute identifier space exhausted".to_string())
            })
    }

    fn validate_serialized_invariants(&self) -> Result<(), Error> {
        let mut attribute_ids =
            HashSet::with_capacity(self.dimensions.values().map(Dimension::nb_attributes).sum());
        for (name, dimension) in &self.dimensions {
            validate_ordinary_name(name)
                .map_err(|error| Error::ConversionFailed(error.to_string()))?;
            dimension.validate_maximum().map_err(|error| {
                Error::ConversionFailed(format!("invalid dimension '{name}': {error}"))
            })?;
            for attribute in dimension.attributes() {
                if attribute.get_id() >= self.next_attribute_id {
                    return Err(Error::ConversionFailed(format!(
                        "attribute identifier {} is not below the allocation watermark {}",
                        attribute.get_id(),
                        self.next_attribute_id
                    )));
                }
                if !attribute_ids.insert(attribute.get_id()) {
                    return Err(Error::ConversionFailed(format!(
                        "duplicate attribute identifier {}",
                        attribute.get_id()
                    )));
                }
            }
        }
        Ok(())
    }

    /// Add an anarchic dimension with the given name to the access structure.
    ///
    /// Requires source-policy regeneration for new rights
    /// ====================
    ///
    /// New rights require newly generated user keys with an explicit grant in
    /// the new dimension. Refresh does not add previously absent right IDs.
    pub fn add_anarchy(&mut self, dimension: String) -> Result<(), Error> {
        validate_ordinary_name(&dimension)?;
        let maximum_id = self.available_attribute_id()?;
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::anarchy_with_maximum(maximum_id));
                self.next_attribute_id = maximum_id + 1;
                Ok(())
            }
        }
    }

    /// Add a hierarchic dimension with the given name to the access structure.
    ///
    /// Requires source-policy regeneration for new rights
    /// ====================
    ///
    /// New rights require newly generated user keys with an explicit grant in
    /// the new dimension. Refresh does not add previously absent right IDs.
    pub fn add_hierarchy(&mut self, dimension: String) -> Result<(), Error> {
        validate_ordinary_name(&dimension)?;
        let maximum_id = self.available_attribute_id()?;
        match self.dimensions.entry(dimension) {
            Entry::Occupied(e) => Err(Error::ExistingDimension(e.key().to_string())),
            Entry::Vacant(e) => {
                e.insert(Dimension::hierarchy_with_maximum(maximum_id));
                self.next_attribute_id = maximum_id + 1;
                Ok(())
            }
        }
    }

    /// Removes the given dim from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    ///
    /// Refreshed keys loose the ability to decrypt for an access policy
    /// belonging to the semantic space of the removed dimension.
    pub fn del_dimension(&mut self, dimension: &str) -> Result<(), Error> {
        self.dimensions
            .remove(dimension)
            .map(|_| ())
            .ok_or(Error::DimensionNotFound(dimension.to_string()))
    }

    /// Add the given qualified attribute to the access structure.
    ///
    /// If the dimension if hierarchical, specifying `after` will set the rank
    /// of the new attribute to be in-between the existing attribute which name
    /// is given as `after`, and before the attribute directly higher that
    /// `after`. Gives the new attribute the lowest rank in case no `after`
    /// attribute is specified.
    ///
    /// If `after` does not match any valid attribute, an error is
    /// returned. Specifying `after` when adding a new attribute to an anarchy
    /// has no effect.
    ///
    /// Requires source-policy regeneration for new rights
    /// =================================================
    ///
    /// Even an existing maximum or hierarchical grant needs key regeneration
    /// to acquire the new attribute's rights. Refresh cannot add new right IDs.
    pub fn add_attribute(
        &mut self,
        attribute: QualifiedAttribute,
        encryption_hint: EncryptionHint,
        after: Option<&str>,
    ) -> Result<(), Error> {
        let id = self.available_attribute_id()?;

        self.dimensions
            .get_mut(&attribute.dimension)
            .ok_or_else(|| Error::DimensionNotFound(attribute.dimension.clone()))?
            .add_attribute(attribute.name, encryption_hint, after, id)?;

        self.next_attribute_id = id + 1;
        Ok(())
    }

    /// Remove the given qualified attribute from the access structure.
    ///
    /// Requires USK refresh
    /// ====================
    /// Only refreshed keys loose the ability to decrypt for an access policy belonging to the
    /// semantic space of this attribute.
    pub fn del_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        if let Some(dim) = self.dimensions.get_mut(&attr.dimension) {
            dim.remove_attribute(&attr.name)
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }
}

impl AccessStructure {
    /// Changes the name of an attribute.
    pub fn rename_attribute(
        &mut self,
        attribute: &QualifiedAttribute,
        new_name: String,
    ) -> Result<(), Error> {
        match self.dimensions.get_mut(&attribute.dimension) {
            Some(d) => d.rename_attribute(&attribute.name, new_name),
            None => Err(Error::DimensionNotFound(attribute.dimension.to_string())),
        }
    }

    pub fn dimensions(&self) -> impl Iterator<Item = &str> {
        self.dimensions.keys().map(|d| d.as_str())
    }

    pub fn attributes(&'_ self) -> impl '_ + Iterator<Item = QualifiedAttribute> {
        self.dimensions.iter().flat_map(|(dimension, d)| {
            d.get_attributes_name()
                .map(move |name| QualifiedAttribute::new(dimension, name.as_str()))
        })
    }

    /// Marks an attribute as read only.
    /// The corresponding attribute key will be removed from the public key.
    /// But the decryption key will be kept to allow reading old ciphertext.
    pub fn disable_attribute(&mut self, attr: &QualifiedAttribute) -> Result<(), Error> {
        match self.dimensions.get_mut(&attr.dimension) {
            Some(d) => d.disable_attribute(&attr.name),
            None => Err(Error::DimensionNotFound(attr.dimension.to_string())),
        }
    }

    /// Generates all rights defined by this access structure and return their
    /// hybridization and activation status.
    pub(crate) fn omega(&self) -> Result<HashMap<Right, (EncryptionHint, AttributeStatus)>, Error> {
        let universe = self.dimensions.iter().collect::<Vec<_>>();
        combine(universe.as_slice())
            .into_iter()
            .map(|(ids, is_hybridized, is_readonly)| {
                Right::from_point(ids).map(|r| (r, (is_hybridized, is_readonly)))
            })
            .collect()
    }
}

impl AccessStructure {
    /// Returns the given attribute from the access structure.
    /// Fails if there is no such attribute.
    fn get_attribute(&self, attr: &QualifiedAttribute) -> Result<&Attribute, Error> {
        if let Some(dim) = self.dimensions.get(&attr.dimension) {
            dim.get_attribute(&attr.name)
                .ok_or(Error::AttributeNotFound(attr.to_string()))
        } else {
            Err(Error::DimensionNotFound(attr.dimension.to_string()))
        }
    }

    /// Validates a DNF clause and reduces repeated attributes from the same
    /// dimension to their strongest conjunction.
    fn normalize_clause(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<QualifiedAttribute>, Error> {
        let mut normalized = HashMap::<String, String>::with_capacity(clause.len());
        let mut anarchic_concrete_values = HashMap::<&str, &str>::new();

        for attribute in clause {
            let dimension = self
                .dimensions
                .get(&attribute.dimension)
                .ok_or_else(|| Error::DimensionNotFound(attribute.dimension.clone()))?;
            dimension
                .get_attribute(&attribute.name)
                .ok_or_else(|| Error::AttributeNotFound(attribute.to_string()))?;

            // Keep original concrete values separate from the reduced value:
            // a maximum must not mask a conflict later in the same clause.
            if !dimension.is_ordered() && attribute.name != MAX_ATTRIBUTE_NAME {
                let previous = anarchic_concrete_values
                    .entry(attribute.dimension.as_str())
                    .or_insert(attribute.name.as_str());
                if *previous != attribute.name.as_str() {
                    return Err(Error::InvalidBooleanExpression(format!(
                        "invalid conjunction in dimension '{}': mutually exclusive attributes '{}' and '{}' cannot be conjoined",
                        attribute.dimension, previous, attribute.name
                    )));
                }
            }

            match normalized.entry(attribute.dimension.clone()) {
                Entry::Vacant(entry) => {
                    entry.insert(attribute.name.clone());
                }
                Entry::Occupied(mut entry) => {
                    let conjunction =
                        dimension
                            .conjunct(entry.get(), &attribute.name)
                            .map_err(|error| {
                                Error::InvalidBooleanExpression(format!(
                                    "invalid conjunction in dimension '{}': {error}",
                                    attribute.dimension
                                ))
                            })?;
                    entry.insert(conjunction);
                }
            }
        }

        let mut normalized = normalized
            .into_iter()
            .map(|(dimension, name)| QualifiedAttribute { dimension, name })
            .collect::<Vec<_>>();
        normalized.sort_unstable();
        Ok(normalized)
    }

    /// Returns whether the right represented by `lhs` dominates the right
    /// represented by `rhs`, treating omitted dimensions as empty attributes.
    fn clause_dominates(
        &self,
        lhs: &[QualifiedAttribute],
        rhs: &[QualifiedAttribute],
    ) -> Result<bool, Error> {
        for (dimension_name, dimension) in &self.dimensions {
            let lhs_value = lhs
                .iter()
                .find(|attribute| &attribute.dimension == dimension_name)
                .map(|attribute| attribute.name.as_str());
            let rhs_value = rhs
                .iter()
                .find(|attribute| &attribute.dimension == dimension_name)
                .map(|attribute| attribute.name.as_str());

            if !dimension.dominates(lhs_value, rhs_value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Retrieves the ID of an attribute.
    #[cfg(test)]
    fn get_attribute_id(&self, attribute: &QualifiedAttribute) -> Result<usize, Error> {
        self.get_attribute(attribute).map(Attribute::get_id)
    }

    /// Generates the restriction of the semantic space of the given clause to
    /// the rights of lower rank than its associated right.
    ///
    /// The semantic space is define as the smallest subspace of the universe in
    /// which the given clause can be expressed.
    ///
    /// # Error
    ///
    /// Returns an error if the clause is invalid.
    fn generate_semantic_space(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<HashMap<String, Dimension>, Error> {
        self.normalize_clause(clause)?
            .into_iter()
            .map(|qa| {
                self.dimensions
                    .get(&qa.dimension)
                    .ok_or_else(|| Error::DimensionNotFound(qa.dimension.clone()))
                    .and_then(|d| d.restrict(qa.name.clone()))
                    .map(|d| (qa.dimension.clone(), d))
            })
            .collect()
    }

    /// Returns the points in the complementary space of the given clause.
    ///
    /// The complementary space of a clause is generated by extending each of
    /// its semantic projections and hierarchical extensions with the
    /// complementary in Omega of its semantic space.
    fn generate_complementary_points(
        &self,
        clause: &[QualifiedAttribute],
    ) -> Result<Vec<Vec<usize>>, Error> {
        // The goal is to compute Ω_r = Ω - sem_Ω(r) + {P: P <= P_r}.

        // Compute sem_Ω(r), the semantic space of the right in Omega.
        let semantic_space = self.generate_semantic_space(clause)?;

        let semantic_points = combine(semantic_space.iter().collect::<Vec<_>>().as_slice())
            .into_iter()
            .map(|(ids, _, _)| ids)
            .collect::<Vec<_>>();

        Ok(semantic_points)
    }

    /// Returns the rights in the complementary space of the given access policy.
    fn generate_complementary_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        // The complementary space of an access policy is the union of the
        // complementary spaces generated by each clause of the DNF of this
        // access policy.
        let points = ap
            .to_dnf()
            .iter()
            .map(|qas| self.generate_complementary_points(qas))
            .try_fold(HashSet::new(), |mut acc, ids| {
                ids?.into_iter().for_each(|ids| {
                    acc.insert(ids);
                });
                Ok::<HashSet<Vec<usize>>, Error>(acc)
            })?;

        points.into_iter().map(Right::from_point).collect()
    }

    fn generate_associated_rights(&self, ap: &AccessPolicy) -> Result<HashSet<Right>, Error> {
        let clauses = ap
            .to_dnf()
            .iter()
            .map(|clause| self.normalize_clause(clause))
            .collect::<Result<HashSet<_>, _>>()?
            .into_iter()
            .collect::<Vec<_>>();

        // A stronger clause is redundant when a weaker clause already grants
        // every user satisfying it access to the ciphertext. Keep only the
        // minimal, non-subsumed requirements while preserving policy semantics.
        let mut retained = Vec::with_capacity(clauses.len());
        for (index, clause) in clauses.iter().enumerate() {
            let mut is_redundant = false;
            for (other_index, other) in clauses.iter().enumerate() {
                if index != other_index && self.clause_dominates(clause, other)? {
                    is_redundant = true;
                    break;
                }
            }
            if !is_redundant {
                retained.push(clause);
            }
        }

        retained
            .into_iter()
            .map(|conjunction| {
                Right::from_point(
                    conjunction
                        .iter()
                        .map(|attr| self.get_attribute(attr).map(Attribute::get_id))
                        .collect::<Result<_, _>>()?,
                )
            })
            .collect()
    }
}

/// Combines all attributes IDs from the given dimensions using at most one attribute for each
/// dimensions. Returns the disjunction of the associated hybridization and activation status.
///
/// As an example, if dimensions D1::A1 and D2::(A2,B2) are given, the following combinations will be created:
/// - D1::A1
/// - D1::A1 && D2::A2
/// - D1::A1 && D2::B2
/// - D2::A2
/// - D2::B2
fn combine(
    dimensions: &[(&String, &Dimension)],
) -> Vec<(Vec<usize>, EncryptionHint, AttributeStatus)> {
    if dimensions.is_empty() {
        vec![(
            vec![],
            EncryptionHint::Classic,
            AttributeStatus::EncryptDecrypt,
        )]
    } else {
        let (_, current_dimension) = &dimensions[0];
        let partial_combinations = combine(&dimensions[1..]);
        let mut res = vec![];
        for component in current_dimension.attributes() {
            for (ids, is_hybridized, is_activated) in &partial_combinations {
                res.push((
                    [vec![component.get_id()], ids.clone()].concat(),
                    *is_hybridized | component.get_encryption_hint(),
                    *is_activated | component.get_status(),
                ));
            }
        }
        [partial_combinations.clone(), res].concat()
    }
}

impl Default for AccessStructure {
    fn default() -> Self {
        Self::new()
    }
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{
        to_leb128_len, Deserializer, Serializable, Serializer,
    };

    impl Serializable for AccessStructure {
        type Error = Error;

        fn length(&self) -> usize {
            1 + to_leb128_len(self.next_attribute_id)
                + to_leb128_len(self.dimensions.len())
                + self
                    .dimensions
                    .iter()
                    .map(|(name, dimension)| {
                        let l = name.len();
                        to_leb128_len(l) + l + dimension.length()
                    })
                    .sum::<usize>()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_leb128_u64(self.version as u64)?;
            n += ser.write_leb128_u64(u64::try_from(self.next_attribute_id)?)?;
            n += ser.write_leb128_u64(self.dimensions.len() as u64)?;
            self.dimensions.iter().try_for_each(|(name, dimension)| {
                n += ser.write_vec(name.as_bytes())?;
                n += ser.write(dimension)?;
                Ok::<_, Self::Error>(())
            })?;
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let version = de.read_leb128_u64()?;
            if version != Version::V2 as u64 {
                return Err(Error::ConversionFailed(format!(
                    "unsupported access-structure format tag {version}; LP V2 requires protected maxima and a trusted allocation watermark"
                )));
            }
            let next_attribute_id = usize::try_from(de.read_leb128_u64()?)?;
            let dimensions = (0..de.read_leb128_u64()?)
                .map(|_| {
                    let name = String::from_utf8(de.read_vec()?)
                        .map_err(|e| Error::ConversionFailed(e.to_string()))?;
                    let dimension = de.read::<Dimension>()?;
                    Ok((name, dimension))
                })
                .collect::<Result<HashMap<_, _>, Error>>()?;
            let structure = Self {
                version: Version::V2,
                next_attribute_id,
                dimensions,
            };
            structure.validate_serialized_invariants()?;
            Ok(structure)
        }
    }

    #[test]
    fn test_access_structure_serialization() {
        use crate::abe_policy::gen_structure;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();
        test_serialization(&structure).unwrap();
    }

    #[test]
    fn test_legacy_access_structure_version_is_rejected() {
        use crate::abe_policy::gen_structure;
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();
        let mut bytes = structure.serialize().unwrap();
        assert_eq!(bytes[0], Version::V2 as u8);
        for unsupported_tag in [0, 1] {
            bytes[0] = unsupported_tag;
            assert!(AccessStructure::deserialize(&bytes).is_err());
        }
    }

    #[test]
    fn test_retired_ids_survive_serialization() -> Result<(), Error> {
        for ordered in [false, true] {
            let mut structure = AccessStructure::new();
            if ordered {
                structure.add_hierarchy("D".to_string())?;
            } else {
                structure.add_anarchy("D".to_string())?;
            }
            let old = QualifiedAttribute::new("D", "OLD");
            structure.add_attribute(old.clone(), EncryptionHint::Classic, None)?;
            let old_id = structure.get_attribute(&old)?.get_id();
            structure.del_attribute(&old)?;
            let mut restored = AccessStructure::deserialize(&structure.serialize()?)?;
            let new = QualifiedAttribute::new("D", "NEW");
            restored.add_attribute(new.clone(), EncryptionHint::Classic, None)?;
            assert!(restored.get_attribute(&new)?.get_id() > old_id);

            let watermark = restored.next_attribute_id;
            restored.del_dimension("D")?;
            let mut empty = AccessStructure::deserialize(&restored.serialize()?)?;
            assert!(empty.dimensions.is_empty());
            assert_eq!(empty.next_attribute_id, watermark);
            empty.add_anarchy("OTHER".to_string())?;
            assert_eq!(
                empty
                    .get_attribute(&QualifiedAttribute::new("OTHER", MAX_ATTRIBUTE_NAME))?
                    .get_id(),
                watermark
            );
        }
        Ok(())
    }

    #[test]
    fn test_invalid_allocation_watermark_is_rejected() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_anarchy("D".to_string())?;
        structure.add_attribute(
            QualifiedAttribute::new("D", "A"),
            EncryptionHint::Classic,
            None,
        )?;
        for invalid_watermark in [0, 1] {
            let mut invalid = structure.clone();
            invalid.next_attribute_id = invalid_watermark;
            assert!(AccessStructure::deserialize(&invalid.serialize()?).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_identifier_exhaustion_is_atomic() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_anarchy("D".to_string())?;
        structure.next_attribute_id = usize::MAX - 1;
        structure.add_attribute(
            QualifiedAttribute::new("D", "LAST"),
            EncryptionHint::Classic,
            None,
        )?;
        let mut exhausted = AccessStructure::deserialize(&structure.serialize()?)?;
        let before = exhausted.clone();
        assert!(exhausted.add_anarchy("A".to_string()).is_err());
        assert!(exhausted.add_hierarchy("H".to_string()).is_err());
        assert!(exhausted
            .add_attribute(
                QualifiedAttribute::new("D", "NEW"),
                EncryptionHint::Classic,
                None
            )
            .is_err());
        assert_eq!(exhausted, before);
        exhausted.del_dimension("D")?;
        assert!(exhausted.add_anarchy("REPLACEMENT".to_string()).is_err());
        Ok(())
    }

    #[test]
    fn test_failed_registration_does_not_consume_identifiers() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_hierarchy("D".to_string())?;
        let existing = QualifiedAttribute::new("D", "A");
        structure.add_attribute(existing.clone(), EncryptionHint::Classic, None)?;
        let before = structure.clone();
        assert!(structure.add_hierarchy("D".to_string()).is_err());
        assert!(structure.add_anarchy("D".to_string()).is_err());
        assert!(structure.add_anarchy("BAD::NAME".to_string()).is_err());
        assert!(structure
            .add_attribute(existing, EncryptionHint::Classic, None)
            .is_err());
        for (attribute, after) in [
            (QualifiedAttribute::new("UNKNOWN", "A"), None),
            (QualifiedAttribute::new("D", MAX_ATTRIBUTE_NAME), None),
            (QualifiedAttribute::new("D", "NEW"), Some("UNKNOWN")),
        ] {
            assert!(structure
                .add_attribute(attribute, EncryptionHint::Classic, after)
                .is_err());
        }
        assert_eq!(structure, before);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::abe_policy::gen_structure;

    #[test]
    fn test_combine() {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|d| d.attributes().count() + 1)
                .product::<usize>()
        );

        structure.add_anarchy("Country".to_string()).unwrap();
        [
            ("France", EncryptionHint::Classic),
            ("Germany", EncryptionHint::Classic),
            ("Spain", EncryptionHint::Classic),
        ]
        .into_iter()
        .try_for_each(|(attribute, hint)| {
            structure.add_attribute(QualifiedAttribute::new("Country", attribute), hint, None)
        })
        .unwrap();

        // There should be `Prod_dim(|dim| + 1)` rights.
        assert_eq!(
            combine(&structure.dimensions.iter().collect::<Vec<_>>()).len(),
            structure
                .dimensions
                .values()
                .map(|dim| dim.attributes().count() + 1)
                .product::<usize>()
        );
    }

    #[test]
    fn test_generate_complementary_rights() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false).unwrap();

        {
            let ap = "(DPT::HR || DPT::FIN) && SEC::TOP";
            let comp_points = structure.generate_complementary_rights(&AccessPolicy::parse(ap)?)?;

            // Check the rights are the same as the ones manually generated, i.e.:
            // - rights()
            // - rights(HR, TOP)
            // - rights(HR, LOW)
            // - rights(FIN, TOP)
            // - rights(FIN, LOW)
            let mut rights = HashSet::new();

            rights.insert(Right::from_point(vec![])?);

            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                },
            )?])?);
            rights.insert(Right::from_point(vec![structure.get_attribute_id(
                &QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                },
            )?])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                })?,
            ])?);
            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "LOW".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "HR".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                })?,
            ])?);

            rights.insert(Right::from_point(vec![
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "DPT".to_string(),
                    name: "FIN".to_string(),
                })?,
                structure.get_attribute_id(&QualifiedAttribute {
                    dimension: "SEC".to_string(),
                    name: "TOP".to_string(),
                })?,
            ])?);

            assert_eq!(comp_points, rights);
        }

        // Check the number of rights generated by some other access policies.
        {
            let ap = "DPT::HR";
            assert_eq!(
                structure
                    .generate_complementary_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // LP-Covercrypt does not expand the missing SEC dimension.
                // DPT::HR yields only the empty right and DPT::HR.
                2
            );

            let ap = "SEC::LOW";
            assert_eq!(
                structure
                    .generate_complementary_rights(&AccessPolicy::parse(ap)?)?
                    .len(),
                // LP-Covercrypt does not expand the missing DPT dimension.
                // SEC::LOW yields only the empty right and SEC::LOW.
                2
            );
        }
        Ok(())
    }

    #[test]
    fn test_maximum_attribute_is_structural_and_protected() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_hierarchy("SEC".to_string())?;
        structure.add_attribute(
            QualifiedAttribute::new("SEC", "LOW"),
            EncryptionHint::Classic,
            None,
        )?;
        structure.add_attribute(
            QualifiedAttribute::new("SEC", "HIGH"),
            EncryptionHint::Hybridized,
            Some("LOW"),
        )?;

        let attributes = structure
            .attributes()
            .filter(|attribute| attribute.dimension == "SEC")
            .map(|attribute| attribute.name)
            .collect::<Vec<_>>();
        assert_eq!(attributes, ["LOW", "HIGH", MAX_ATTRIBUTE_NAME]);

        let maximum = QualifiedAttribute::new("SEC", MAX_ATTRIBUTE_NAME);
        assert!(structure
            .add_attribute(maximum.clone(), EncryptionHint::Classic, None)
            .is_err());
        assert!(structure.del_attribute(&maximum).is_err());
        assert!(structure.disable_attribute(&maximum).is_err());
        assert!(structure
            .rename_attribute(&maximum, "RENAMED".to_string())
            .is_err());
        assert!(structure
            .rename_attribute(
                &QualifiedAttribute::new("SEC", "LOW"),
                MAX_ATTRIBUTE_NAME.to_string(),
            )
            .is_err());
        assert!(structure
            .add_attribute(
                QualifiedAttribute::new("SEC", "ABOVE_MAX"),
                EncryptionHint::Classic,
                Some(MAX_ATTRIBUTE_NAME),
            )
            .is_err());

        Ok(())
    }

    #[test]
    fn test_lp_missing_dimension_and_explicit_maximum() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;

        let restricted = structure.ap_to_usk_rights(&AccessPolicy::parse("DPT::HR")?)?;
        assert_eq!(restricted.len(), 2);

        let unrestricted = structure.ap_to_usk_rights(&AccessPolicy::parse("DPT::$")?)?;
        // Empty + five concrete department attributes + the maximum attribute.
        assert_eq!(unrestricted.len(), 7);

        Ok(())
    }

    #[test]
    fn test_maximum_has_explicit_key_and_ciphertext_polarity() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;

        let x_maximum = structure.ap_to_enc_rights(&AccessPolicy::parse("DPT::$")?)?;
        let x_concrete = structure.ap_to_enc_rights(&AccessPolicy::parse("DPT::HR")?)?;
        let x_omitted = structure.ap_to_enc_rights(&AccessPolicy::parse("*")?)?;
        let y_concrete = structure.ap_to_usk_rights(&AccessPolicy::parse("DPT::HR")?)?;
        let y_maximum = structure.ap_to_usk_rights(&AccessPolicy::parse("DPT::$")?)?;

        // A ciphertext maximum requires the maximum coordinate; it is not a
        // wildcard satisfied by an ordinary concrete key value.
        assert!(x_maximum.is_disjoint(&y_concrete));
        assert!(!x_maximum.is_disjoint(&y_maximum));

        // A maximum-bearing key has the full lower set and therefore satisfies
        // concrete and omitted ciphertext requirements in the dimension.
        assert!(!x_concrete.is_disjoint(&y_maximum));
        assert!(!x_omitted.is_disjoint(&y_concrete));

        Ok(())
    }

    #[test]
    fn test_mixed_broadcast_is_compiled_per_policy_path() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;

        let term = AccessPolicy::parse("SEC::LOW")?;
        let with_broadcast = AccessPolicy::parse("SEC::LOW || *")?;

        assert_eq!(
            structure.ap_to_enc_rights(&with_broadcast)?,
            structure.ap_to_enc_rights(&AccessPolicy::parse("*")?)?
        );
        assert_eq!(
            structure.ap_to_usk_rights(&with_broadcast)?,
            structure.ap_to_usk_rights(&term)?
        );
        Ok(())
    }

    #[test]
    fn test_reserved_tokens_are_rejected_in_ordinary_names() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        for invalid_dimension in [
            "$", "*", "D$", "D*", "D(", "D)", "D&&X", "D||X", "D::X", " D", "D ",
        ] {
            assert!(
                structure
                    .add_anarchy(invalid_dimension.to_string())
                    .is_err(),
                "{invalid_dimension}"
            );
        }
        structure.add_anarchy("D".to_string())?;
        for invalid_attribute in [
            "$", "*", "A$B", "A*B", "A(B", "A)B", "A&&B", "A||B", "A::B", " A", "A ",
        ] {
            assert!(
                structure
                    .add_attribute(
                        QualifiedAttribute::new("D", invalid_attribute),
                        EncryptionHint::Classic,
                        None,
                    )
                    .is_err(),
                "{invalid_attribute}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_invalid_anarchic_conjunction_is_rejected() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;
        let invalid = AccessPolicy::parse("DPT::HR && DPT::FIN")?;

        assert!(structure.ap_to_usk_rights(&invalid).is_err());
        assert!(structure.ap_to_enc_rights(&invalid).is_err());
        Ok(())
    }

    #[test]
    fn test_validation_regression_anarchic_conflicts_ignore_term_order() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_anarchy("DPT".to_string())?;
        for name in ["DEV", "MKG"] {
            structure.add_attribute(
                QualifiedAttribute::new("DPT", name),
                EncryptionHint::Classic,
                None,
            )?;
        }

        // An explicit maximum must not hide incompatible concrete attributes.
        for terms in [
            ["DPT::DEV", "DPT::MKG", "DPT::$"],
            ["DPT::DEV", "DPT::$", "DPT::MKG"],
            ["DPT::MKG", "DPT::DEV", "DPT::$"],
            ["DPT::MKG", "DPT::$", "DPT::DEV"],
            ["DPT::$", "DPT::DEV", "DPT::MKG"],
            ["DPT::$", "DPT::MKG", "DPT::DEV"],
        ] {
            let clause = terms.join(" && ");
            for source in [
                clause.clone(),
                format!("({clause}) || *"),
                format!("* || ({clause})"),
                format!("({} || *) && {} && {}", terms[0], terms[1], terms[2]),
            ] {
                let policy = AccessPolicy::parse(&source)?;
                assert!(
                    matches!(
                        structure.ap_to_enc_rights(&policy),
                        Err(Error::InvalidBooleanExpression(_))
                    ),
                    "ciphertext accepted {source}"
                );
                assert!(
                    matches!(
                        structure.ap_to_usk_rights(&policy),
                        Err(Error::InvalidBooleanExpression(_))
                    ),
                    "key accepted {source}"
                );
            }
        }

        // One concrete value (possibly repeated) can still accompany a maximum.
        let maximum = AccessPolicy::parse("DPT::$")?;
        for source in [
            "DPT::$ && DPT::DEV && DPT::DEV",
            "DPT::DEV && DPT::$ && DPT::DEV",
            "DPT::DEV && DPT::DEV && DPT::$",
        ] {
            let policy = AccessPolicy::parse(source)?;
            assert_eq!(
                structure.ap_to_enc_rights(&policy)?,
                structure.ap_to_enc_rights(&maximum)?,
                "{source}"
            );
            assert_eq!(
                structure.ap_to_usk_rights(&policy)?,
                structure.ap_to_usk_rights(&maximum)?,
                "{source}"
            );
        }
        Ok(())
    }

    #[test]
    fn test_validation_regression_names_share_one_rule() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_anarchy("D".to_string())?;
        let ordinary = QualifiedAttribute::new("D", "A");
        structure.add_attribute(ordinary.clone(), EncryptionHint::Classic, None)?;

        for name in ["R&D", "R|D", "R:D", "R$D", "R*D", "R(D", "R)D", "", " "] {
            assert!(structure.add_anarchy(name.to_string()).is_err(), "{name}");
            assert!(structure.add_hierarchy(name.to_string()).is_err(), "{name}");
            assert!(
                structure
                    .add_attribute(
                        QualifiedAttribute::new("D", name),
                        EncryptionHint::Classic,
                        None,
                    )
                    .is_err(),
                "{name}"
            );
            assert!(
                structure
                    .rename_attribute(&ordinary, name.to_string())
                    .is_err(),
                "{name}"
            );
            for source in [format!("{name}::A"), format!("D::{name}")] {
                assert!(
                    QualifiedAttribute::try_from(source.as_str()).is_err(),
                    "{source}"
                );
                assert!(AccessPolicy::parse(&source).is_err(), "{source}");
            }
        }

        assert_eq!(
            AccessPolicy::parse(" D :: $ ")?,
            AccessPolicy::parse("D::$")?
        );
        assert!(AccessPolicy::parse("$::A").is_err());
        Ok(())
    }

    #[test]
    fn test_validation_regression_valid_names_round_trip() -> Result<(), Error> {
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        for name in ["R-D", "R_D", "R.D", "Research and Development", "部门"] {
            let mut structure = AccessStructure::new();
            structure.add_anarchy(name.to_string())?;
            let attribute = QualifiedAttribute::new(name, name);
            structure.add_attribute(attribute.clone(), EncryptionHint::Classic, None)?;
            let policy = AccessPolicy::parse(&format!("  {name} :: {name}  "))?;
            assert_eq!(policy, AccessPolicy::Term(attribute));

            let restored = AccessStructure::deserialize(&structure.serialize()?)?;
            assert_eq!(restored, structure);
            let x = restored.ap_to_enc_rights(&policy)?;
            let y = restored.ap_to_usk_rights(&policy)?;
            assert_eq!(x.len(), 1);
            assert_eq!(y.len(), 2);
            assert!(!x.is_disjoint(&y));
        }
        Ok(())
    }

    #[test]
    fn test_validation_regression_delimiters_rejected_on_load() -> Result<(), Error> {
        use cosmian_crypto_core::bytes_ser_de::Serializable;

        let mut valid = AccessStructure::new();
        valid.add_anarchy("D".to_string())?;
        valid.add_attribute(
            QualifiedAttribute::new("D", "A"),
            EncryptionHint::Classic,
            None,
        )?;
        for name in ["R&D", "R|D", "R:D"] {
            // Construct old or externally supplied state that bypassed name
            // validation; neither dimension nor attribute names may survive load.
            let mut bad_dimension = valid.clone();
            let dimension = bad_dimension.dimensions.remove("D").unwrap();
            bad_dimension.dimensions.insert(name.to_string(), dimension);
            assert!(AccessStructure::deserialize(&bad_dimension.serialize()?).is_err());

            let mut bad_attribute = valid.clone();
            let Dimension::Anarchy(attributes) = bad_attribute.dimensions.get_mut("D").unwrap()
            else {
                unreachable!()
            };
            let attribute = attributes.remove("A").unwrap();
            attributes.insert(name.to_string(), attribute);
            assert!(AccessStructure::deserialize(&bad_attribute.serialize()?).is_err());
        }
        Ok(())
    }

    #[test]
    fn test_hierarchical_conjunction_reduces_to_stronger_attribute() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;

        let conjunction = AccessPolicy::parse("SEC::LOW && SEC::TOP")?;
        let strongest = AccessPolicy::parse("SEC::TOP")?;
        assert_eq!(
            structure.ap_to_usk_rights(&conjunction)?,
            structure.ap_to_usk_rights(&strongest)?
        );
        assert_eq!(
            structure.ap_to_enc_rights(&conjunction)?,
            structure.ap_to_enc_rights(&strongest)?
        );
        Ok(())
    }

    #[test]
    fn test_ciphertext_subsumption_removes_redundant_clauses() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        gen_structure(&mut structure, false)?;

        let hierarchical = AccessPolicy::parse("SEC::LOW || SEC::TOP")?;
        assert_eq!(
            structure.ap_to_enc_rights(&hierarchical)?,
            structure.ap_to_enc_rights(&AccessPolicy::parse("SEC::LOW")?)?
        );

        let cross_dimension = AccessPolicy::parse("DPT::HR || (DPT::HR && SEC::TOP)")?;
        assert_eq!(
            structure.ap_to_enc_rights(&cross_dimension)?,
            structure.ap_to_enc_rights(&AccessPolicy::parse("DPT::HR")?)?
        );
        Ok(())
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum ModelSec {
        Bottom,
        Low,
        High,
        Maximum,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    enum ModelDpt {
        Bottom,
        Dev,
        Mkg,
        Maximum,
    }

    #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
    struct ModelClause {
        sec: ModelSec,
        dpt: ModelDpt,
    }

    fn model_clause_source(clause: ModelClause) -> String {
        let mut terms = Vec::new();
        match clause.sec {
            ModelSec::Bottom => {}
            ModelSec::Low => terms.push("SEC::LOW"),
            ModelSec::High => terms.push("SEC::HIG"),
            ModelSec::Maximum => terms.push("SEC::$"),
        }
        match clause.dpt {
            ModelDpt::Bottom => {}
            ModelDpt::Dev => terms.push("DPT::DEV"),
            ModelDpt::Mkg => terms.push("DPT::MKG"),
            ModelDpt::Maximum => terms.push("DPT::$"),
        }
        if terms.is_empty() {
            "*".to_string()
        } else {
            terms.join(" && ")
        }
    }

    fn model_sec_dominates(lhs: ModelSec, rhs: ModelSec) -> bool {
        let rank = |value| match value {
            ModelSec::Bottom => 0,
            ModelSec::Low => 1,
            ModelSec::High => 2,
            ModelSec::Maximum => 3,
        };
        rank(lhs) >= rank(rhs)
    }

    fn model_dpt_dominates(lhs: ModelDpt, rhs: ModelDpt) -> bool {
        rhs == ModelDpt::Bottom || lhs == rhs || lhs == ModelDpt::Maximum
    }

    fn model_clause_dominates(lhs: ModelClause, rhs: ModelClause) -> bool {
        model_sec_dominates(lhs.sec, rhs.sec) && model_dpt_dominates(lhs.dpt, rhs.dpt)
    }

    fn model_right(structure: &AccessStructure, clause: ModelClause) -> Result<Right, Error> {
        let mut ids = Vec::new();
        let sec = match clause.sec {
            ModelSec::Bottom => None,
            ModelSec::Low => Some("LOW"),
            ModelSec::High => Some("HIG"),
            ModelSec::Maximum => Some(MAX_ATTRIBUTE_NAME),
        };
        let dpt = match clause.dpt {
            ModelDpt::Bottom => None,
            ModelDpt::Dev => Some("DEV"),
            ModelDpt::Mkg => Some("MKG"),
            ModelDpt::Maximum => Some(MAX_ATTRIBUTE_NAME),
        };
        if let Some(name) = sec {
            ids.push(structure.get_attribute_id(&QualifiedAttribute::new("SEC", name))?);
        }
        if let Some(name) = dpt {
            ids.push(structure.get_attribute_id(&QualifiedAttribute::new("DPT", name))?);
        }
        Right::from_point(ids)
    }

    fn model_ciphertext_rights(
        structure: &AccessStructure,
        clauses: &[ModelClause],
    ) -> Result<HashSet<Right>, Error> {
        let unique = clauses.iter().copied().collect::<HashSet<_>>();
        unique
            .iter()
            .filter(|&&clause| {
                !unique
                    .iter()
                    .any(|other| clause != *other && model_clause_dominates(clause, *other))
            })
            .map(|&clause| model_right(structure, clause))
            .collect()
    }

    fn model_key_rights(
        structure: &AccessStructure,
        clauses: &[ModelClause],
    ) -> Result<HashSet<Right>, Error> {
        let lower_sec = |value| match value {
            ModelSec::Bottom => vec![ModelSec::Bottom],
            ModelSec::Low => vec![ModelSec::Bottom, ModelSec::Low],
            ModelSec::High => vec![ModelSec::Bottom, ModelSec::Low, ModelSec::High],
            ModelSec::Maximum => vec![
                ModelSec::Bottom,
                ModelSec::Low,
                ModelSec::High,
                ModelSec::Maximum,
            ],
        };
        let lower_dpt = |value| match value {
            ModelDpt::Bottom => vec![ModelDpt::Bottom],
            ModelDpt::Dev => vec![ModelDpt::Bottom, ModelDpt::Dev],
            ModelDpt::Mkg => vec![ModelDpt::Bottom, ModelDpt::Mkg],
            ModelDpt::Maximum => vec![
                ModelDpt::Bottom,
                ModelDpt::Dev,
                ModelDpt::Mkg,
                ModelDpt::Maximum,
            ],
        };

        let mut rights = HashSet::new();
        for clause in clauses {
            for sec in lower_sec(clause.sec) {
                for dpt in lower_dpt(clause.dpt) {
                    rights.insert(model_right(structure, ModelClause { sec, dpt })?);
                }
            }
        }
        Ok(rights)
    }

    #[test]
    fn test_exhaustive_small_model_semantics_144_policies() -> Result<(), Error> {
        let mut structure = AccessStructure::new();
        structure.add_hierarchy("SEC".to_string())?;
        structure.add_attribute(
            QualifiedAttribute::new("SEC", "LOW"),
            EncryptionHint::Classic,
            None,
        )?;
        structure.add_attribute(
            QualifiedAttribute::new("SEC", "HIG"),
            EncryptionHint::Classic,
            Some("LOW"),
        )?;
        structure.add_anarchy("DPT".to_string())?;
        structure.add_attribute(
            QualifiedAttribute::new("DPT", "DEV"),
            EncryptionHint::Classic,
            None,
        )?;
        structure.add_attribute(
            QualifiedAttribute::new("DPT", "MKG"),
            EncryptionHint::Classic,
            None,
        )?;

        let mut atomic = Vec::new();
        for sec in [
            ModelSec::Bottom,
            ModelSec::Low,
            ModelSec::High,
            ModelSec::Maximum,
        ] {
            for dpt in [
                ModelDpt::Bottom,
                ModelDpt::Dev,
                ModelDpt::Mkg,
                ModelDpt::Maximum,
            ] {
                if sec != ModelSec::Bottom || dpt != ModelDpt::Bottom {
                    atomic.push(ModelClause { sec, dpt });
                }
            }
        }
        assert_eq!(atomic.len(), 15);

        let mut cases = vec![(
            "*".to_string(),
            vec![ModelClause {
                sec: ModelSec::Bottom,
                dpt: ModelDpt::Bottom,
            }],
        )];
        for clause in &atomic {
            cases.push((model_clause_source(*clause), vec![*clause]));
        }
        for (index, lhs) in atomic.iter().enumerate() {
            for rhs in &atomic[index..] {
                cases.push((
                    format!(
                        "({}) || ({})",
                        model_clause_source(*lhs),
                        model_clause_source(*rhs)
                    ),
                    vec![*lhs, *rhs],
                ));
            }
        }
        cases.extend([
            (
                "(SEC::LOW || SEC::HIG) && (DPT::DEV || DPT::MKG)".to_string(),
                vec![
                    ModelClause {
                        sec: ModelSec::Low,
                        dpt: ModelDpt::Dev,
                    },
                    ModelClause {
                        sec: ModelSec::Low,
                        dpt: ModelDpt::Mkg,
                    },
                    ModelClause {
                        sec: ModelSec::High,
                        dpt: ModelDpt::Dev,
                    },
                    ModelClause {
                        sec: ModelSec::High,
                        dpt: ModelDpt::Mkg,
                    },
                ],
            ),
            (
                "SEC::LOW && SEC::HIG".to_string(),
                vec![ModelClause {
                    sec: ModelSec::High,
                    dpt: ModelDpt::Bottom,
                }],
            ),
            (
                "DPT::DEV || (DPT::DEV && SEC::HIG)".to_string(),
                vec![
                    ModelClause {
                        sec: ModelSec::Bottom,
                        dpt: ModelDpt::Dev,
                    },
                    ModelClause {
                        sec: ModelSec::High,
                        dpt: ModelDpt::Dev,
                    },
                ],
            ),
            (
                "(SEC::LOW || SEC::HIG) && DPT::$".to_string(),
                vec![
                    ModelClause {
                        sec: ModelSec::Low,
                        dpt: ModelDpt::Maximum,
                    },
                    ModelClause {
                        sec: ModelSec::High,
                        dpt: ModelDpt::Maximum,
                    },
                ],
            ),
            (
                "SEC::LOW || *".to_string(),
                vec![
                    ModelClause {
                        sec: ModelSec::Low,
                        dpt: ModelDpt::Bottom,
                    },
                    ModelClause {
                        sec: ModelSec::Bottom,
                        dpt: ModelDpt::Bottom,
                    },
                ],
            ),
            (
                "* || SEC::LOW".to_string(),
                vec![
                    ModelClause {
                        sec: ModelSec::Bottom,
                        dpt: ModelDpt::Bottom,
                    },
                    ModelClause {
                        sec: ModelSec::Low,
                        dpt: ModelDpt::Bottom,
                    },
                ],
            ),
            (
                "SEC::LOW && *".to_string(),
                vec![ModelClause {
                    sec: ModelSec::Low,
                    dpt: ModelDpt::Bottom,
                }],
            ),
            (
                "* && SEC::LOW".to_string(),
                vec![ModelClause {
                    sec: ModelSec::Low,
                    dpt: ModelDpt::Bottom,
                }],
            ),
        ]);
        assert_eq!(cases.len(), 144);

        let mut compiled = Vec::new();
        for (source, clauses) in &cases {
            let policy = AccessPolicy::parse(source)?;
            let expected_x = model_ciphertext_rights(&structure, clauses)?;
            let expected_y = model_key_rights(&structure, clauses)?;
            let actual_x = structure.ap_to_enc_rights(&policy)?;
            let actual_y = structure.ap_to_usk_rights(&policy)?;
            assert_eq!(actual_x, expected_x, "ciphertext policy: {source}");
            assert_eq!(actual_y, expected_y, "key policy: {source}");
            compiled.push((actual_x, actual_y, expected_x, expected_y));
        }

        let mut decisions = 0usize;
        for (actual_x, _, expected_x, _) in &compiled {
            for (_, actual_y, _, expected_y) in &compiled {
                let compiler_authorizes = !actual_x.is_disjoint(actual_y);
                let model_authorizes = !expected_x.is_disjoint(expected_y);
                assert_eq!(compiler_authorizes, model_authorizes);
                decisions += 1;
            }
        }
        assert_eq!(decisions, 20_736);

        for source in ["DPT::DEV && DPT::MKG", "DPT::UNKNOWN", "UNKNOWN::VALUE"] {
            match AccessPolicy::parse(source) {
                Ok(policy) => {
                    assert!(structure.ap_to_enc_rights(&policy).is_err(), "{source}");
                    assert!(structure.ap_to_usk_rights(&policy).is_err(), "{source}");
                }
                Err(_) => {}
            }
        }

        Ok(())
    }

    #[test]
    fn test_missing_dimension_scaling_matches_cartesian_product() -> Result<(), Error> {
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

            let lp = structure.ap_to_usk_rights(&AccessPolicy::parse("D0::V0")?)?;
            let unrestricted_source = std::iter::once("D0::V0".to_string())
                .chain((1..dimension_count).map(|index| format!("D{index}::$")))
                .collect::<Vec<_>>()
                .join(" && ");
            let unrestricted =
                structure.ap_to_usk_rights(&AccessPolicy::parse(&unrestricted_source)?)?;

            assert_eq!(lp.len(), 2);
            assert_eq!(unrestricted.len(), 2 * 5usize.pow(dimension_count - 1));
        }
        Ok(())
    }
}
