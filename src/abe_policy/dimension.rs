use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Debug,
};

use serde::{Deserialize, Serialize};

use super::{attribute::EncryptionHint, AttributeStatus};
use crate::{data_struct::Dict, Error};

type Name = String;

pub(crate) const MAX_ATTRIBUTE_NAME: &str = "$";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct Attribute {
    pub(crate) id: usize,
    pub(crate) encryption_hint: EncryptionHint,
    pub(crate) write_status: AttributeStatus,
}

impl Attribute {
    pub fn new(encryption_hint: EncryptionHint, id: usize) -> Self {
        Self {
            id,
            encryption_hint,
            write_status: AttributeStatus::EncryptDecrypt,
        }
    }

    pub fn get_id(&self) -> usize {
        self.id
    }

    pub fn get_encryption_hint(&self) -> EncryptionHint {
        self.encryption_hint
    }

    pub fn get_status(&self) -> AttributeStatus {
        self.write_status
    }
}

/// A dimension is an object that contains attributes. It can be ordered or unordered.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize, Debug)]
pub enum Dimension {
    Anarchy(HashMap<Name, Attribute>),
    Hierarchy(Dict<Name, Attribute>),
}

impl Default for Dimension {
    fn default() -> Self {
        Self::Anarchy(Default::default())
    }
}

impl Dimension {
    pub(crate) fn anarchy_with_maximum(id: usize) -> Self {
        Self::Anarchy(HashMap::from_iter([(
            MAX_ATTRIBUTE_NAME.to_string(),
            Attribute::new(EncryptionHint::Classic, id),
        )]))
    }

    pub(crate) fn hierarchy_with_maximum(id: usize) -> Self {
        let mut attributes = Dict::new();
        attributes.insert(
            MAX_ATTRIBUTE_NAME.to_string(),
            Attribute::new(EncryptionHint::Classic, id),
        );
        Self::Hierarchy(attributes)
    }

    pub fn nb_attributes(&self) -> usize {
        match self {
            Self::Anarchy(attributes) => attributes.len(),
            Self::Hierarchy(attributes) => attributes.len(),
        }
    }

    pub fn is_ordered(&self) -> bool {
        match self {
            Self::Anarchy(_) => false,
            Self::Hierarchy(_) => true,
        }
    }

    /// Returns an iterator over the attributes name.
    ///
    /// If the dimension is ordered, the names are returned in this order, otherwise they are
    /// returned in arbitrary order.
    pub fn get_attributes_name(&self) -> Box<dyn '_ + Iterator<Item = &Name>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.keys()),
            Self::Hierarchy(attributes) => Box::new(attributes.keys()),
        }
    }

    pub fn get_attribute(&self, attr_name: &Name) -> Option<&Attribute> {
        match self {
            Self::Anarchy(attributes) => attributes.get(attr_name),
            Self::Hierarchy(attributes) => attributes.get(attr_name),
        }
    }

    pub(crate) fn next_attribute_id(&self) -> Option<usize> {
        if self.nb_attributes() == 0 {
            None
        } else {
            self.attributes().map(Attribute::get_id).max()
        }
    }

    /// Restricts the dimension to the attribute that are lower than the given one.
    pub fn restrict(&self, attr_name: Name) -> Result<Self, Error> {
        let params = self
            .get_attribute(&attr_name)
            .ok_or_else(|| Error::AttributeNotFound(attr_name.to_string()))?
            .clone();

        if attr_name == MAX_ATTRIBUTE_NAME {
            match self {
                Self::Hierarchy(attributes) => {
                    return Ok(Self::Hierarchy(attributes.clone()));
                }
                Self::Anarchy(attributes) => {
                    return Ok(Self::Anarchy(attributes.clone()));
                }
            }
        }

        match self {
            Self::Hierarchy(attributes) => {
                let mut attributes = attributes
                    .iter()
                    .take_while(|(name, _)| *name != &attr_name)
                    .map(|(ref_name, ref_params)| (ref_name.clone(), ref_params.clone()))
                    .collect::<Dict<Name, Attribute>>();
                attributes.insert(attr_name, params);
                Ok(Self::Hierarchy(attributes))
            }
            Self::Anarchy(_) => Ok(Self::Anarchy(HashMap::from_iter([(attr_name, params)]))),
        }
    }

    /// Returns whether `lhs` semantically dominates `rhs` in this dimension.
    /// `None` represents the empty (lowest) attribute.
    pub(crate) fn dominates(&self, lhs: Option<&str>, rhs: Option<&str>) -> Result<bool, Error> {
        if let Some(name) = lhs {
            self.get_attribute(&name.to_string())
                .ok_or_else(|| Error::AttributeNotFound(name.to_string()))?;
        }
        if let Some(name) = rhs {
            self.get_attribute(&name.to_string())
                .ok_or_else(|| Error::AttributeNotFound(name.to_string()))?;
        }

        match (lhs, rhs) {
            (_, None) => Ok(true),
            (None, Some(_)) => Ok(false),
            (Some(lhs), Some(rhs)) if lhs == rhs => Ok(true),
            (Some(MAX_ATTRIBUTE_NAME), Some(_)) => Ok(true),
            (Some(_), Some(MAX_ATTRIBUTE_NAME)) => Ok(false),
            (Some(lhs), Some(rhs)) => match self {
                Self::Anarchy(_) => Ok(false),
                Self::Hierarchy(attributes) => {
                    let lhs_rank = attributes
                        .keys()
                        .position(|name| name == lhs)
                        .ok_or_else(|| Error::AttributeNotFound(lhs.to_string()))?;
                    let rhs_rank = attributes
                        .keys()
                        .position(|name| name == rhs)
                        .ok_or_else(|| Error::AttributeNotFound(rhs.to_string()))?;
                    Ok(lhs_rank >= rhs_rank)
                }
            },
        }
    }

    /// Normalizes the conjunction of two attributes from this dimension.
    /// Comparable attributes reduce to the stronger one; incomparable anarchic
    /// attributes make the conjunction invalid.
    pub(crate) fn conjunct(&self, lhs: &str, rhs: &str) -> Result<String, Error> {
        if self.dominates(Some(lhs), Some(rhs))? {
            Ok(lhs.to_string())
        } else if self.dominates(Some(rhs), Some(lhs))? {
            Ok(rhs.to_string())
        } else {
            Err(Error::InvalidBooleanExpression(format!(
                "mutually exclusive attributes '{lhs}' and '{rhs}' cannot be conjoined"
            )))
        }
    }
    /// Adds a new attribute to this dimension with the provided properties.
    ///
    /// # Errors
    /// Returns an error if the operation is not permitted.
    pub fn add_attribute(
        &mut self,
        attribute: Name,
        hint: EncryptionHint,
        after: Option<&str>,
        id: usize,
    ) -> Result<(), Error> {
        if attribute == MAX_ATTRIBUTE_NAME {
            return Err(Error::OperationNotPermitted(format!(
                "the maximum attribute '{MAX_ATTRIBUTE_NAME}' is created automatically"
            )));
        }
        if after == Some(MAX_ATTRIBUTE_NAME) {
            return Err(Error::OperationNotPermitted(format!(
                "no attribute can be ranked above the maximum attribute '{MAX_ATTRIBUTE_NAME}'"
            )));
        }
        if self
            .get_attribute(&MAX_ATTRIBUTE_NAME.to_string())
            .is_none()
        {
            return Err(Error::OperationNotPermitted(format!(
                "dimension has no maximum attribute '{MAX_ATTRIBUTE_NAME}'"
            )));
        }

        let result = match self {
            Self::Anarchy(attributes) => {
                if let Entry::Vacant(entry) = attributes.entry(attribute) {
                    entry.insert(Attribute::new(hint, id));
                    Ok(())
                } else {
                    Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ))
                }
            }
            Self::Hierarchy(attributes) => {
                if attributes.contains_key(&attribute) {
                    return Err(Error::OperationNotPermitted(
                        "Attribute already in dimension".to_string(),
                    ));
                }
                let after = if let Some(after) = after {
                    if !attributes.contains_key(after) {
                        return Err(Error::AttributeNotFound(
                            "the specified `after` attribute {after} does not exist".to_string(),
                        ));
                    }
                    after
                } else {
                    ""
                };
                let higher_attributes = attributes
                    .clone()
                    .into_iter()
                    .rev()
                    .take_while(|(name, _)| name != after)
                    .collect::<Vec<_>>();

                let mut new_attributes = attributes
                    .clone()
                    .into_iter()
                    .take_while(|a| Some(a) != higher_attributes.last())
                    .collect::<Dict<_, _>>();

                new_attributes.insert(attribute, Attribute::new(hint, id));
                higher_attributes.into_iter().rev().for_each(|(name, dim)| {
                    new_attributes.insert(name, dim);
                });
                *attributes = new_attributes;
                Ok(())
            }
        };

        if result.is_ok() && hint == EncryptionHint::Hybridized {
            match self {
                Self::Anarchy(attributes) => {
                    attributes
                        .get_mut(MAX_ATTRIBUTE_NAME)
                        .ok_or_else(|| {
                            Error::OperationNotPermitted(format!(
                                "dimension has no maximum attribute '{MAX_ATTRIBUTE_NAME}'"
                            ))
                        })?
                        .encryption_hint = EncryptionHint::Hybridized
                }
                Self::Hierarchy(attributes) => {
                    attributes
                        .get_mut(MAX_ATTRIBUTE_NAME)
                        .ok_or_else(|| {
                            Error::OperationNotPermitted(format!(
                                "dimension has no maximum attribute '{MAX_ATTRIBUTE_NAME}'"
                            ))
                        })?
                        .encryption_hint = EncryptionHint::Hybridized
                }
            }
        }

        result
    }

    /// Removes the attribute with the given name from this dimension.
    ///
    /// # Errors
    /// Returns an error if no attribute with this name is found.
    pub fn remove_attribute(&mut self, name: &Name) -> Result<(), Error> {
        if name == MAX_ATTRIBUTE_NAME {
            return Err(Error::OperationNotPermitted(format!(
                "the maximum attribute '{MAX_ATTRIBUTE_NAME}' cannot be removed"
            )));
        }
        match self {
            Self::Anarchy(attributes) => attributes
                .remove(name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(name.to_string())),
            Self::Hierarchy(attributes) => attributes
                .remove(name)
                .map(|_| ())
                .ok_or(Error::AttributeNotFound(name.to_string())),
        }
    }

    /// Disables the attribute with the given name.
    ///
    /// # Errors
    /// Returns an error if no attribute with this name is found.
    pub fn disable_attribute(&mut self, name: &Name) -> Result<(), Error> {
        if name == MAX_ATTRIBUTE_NAME {
            return Err(Error::OperationNotPermitted(format!(
                "the maximum attribute '{MAX_ATTRIBUTE_NAME}' cannot be disabled"
            )));
        }
        match self {
            Self::Anarchy(attributes) => attributes
                .get_mut(name)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(name.to_string())),
            Self::Hierarchy(attributes) => attributes
                .get_mut(name)
                .map(|attr| attr.write_status = AttributeStatus::DecryptOnly)
                .ok_or(Error::AttributeNotFound(name.to_string())),
        }
    }

    /// Renames the attribute with the given name.
    ///
    /// # Errors
    /// Returns an error if the new name is already used in the same dimension or if no attribute
    /// with the given old name is found.
    pub fn rename_attribute(&mut self, old_name: &Name, new_name: Name) -> Result<(), Error> {
        if old_name == MAX_ATTRIBUTE_NAME || new_name == MAX_ATTRIBUTE_NAME {
            return Err(Error::OperationNotPermitted(format!(
                "the maximum attribute name '{MAX_ATTRIBUTE_NAME}' is reserved"
            )));
        }
        match self {
            Self::Anarchy(attributes) => {
                if attributes.contains_key(&new_name) {
                    return Err(Error::OperationNotPermitted(
                        "New attribute name is already used in the same dimension".to_string(),
                    ));
                }
                match attributes.remove(old_name) {
                    Some(attr_params) => {
                        attributes.insert(new_name, attr_params);
                        Ok(())
                    }
                    None => Err(Error::AttributeNotFound(old_name.to_string())),
                }
            }
            Self::Hierarchy(attributes) => attributes
                .update_key(old_name, new_name)
                .map_err(|e| Error::OperationNotPermitted(e.to_string())),
        }
    }

    /// Returns an iterator over the `AttributesParameters` and parameters.
    /// If the dimension is ordered, the attributes are returned in order.
    pub fn attributes(&self) -> Box<dyn '_ + Iterator<Item = &Attribute>> {
        match self {
            Self::Anarchy(attributes) => Box::new(attributes.values()),
            Self::Hierarchy(attributes) => Box::new(attributes.values()),
        }
    }
}

mod serialization {
    use cosmian_crypto_core::bytes_ser_de::{
        to_leb128_len, Deserializer, Serializable, Serializer,
    };

    use super::*;

    impl Serializable for Attribute {
        type Error = Error;

        fn length(&self) -> usize {
            2 + to_leb128_len(self.id)
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_leb128_u64(self.id as u64)?;
            n += ser.write_leb128_u64(<bool>::from(self.encryption_hint) as u64)?;
            n += ser.write_leb128_u64(<bool>::from(self.write_status) as u64)?;
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let id = de.read_leb128_u64()?.try_into()?;
            let hint = de.read_leb128_u64()?;
            let encryption_hint = if 0 == hint {
                EncryptionHint::Classic
            } else if 1 == hint {
                EncryptionHint::Hybridized
            } else {
                return Err(Error::ConversionFailed(format!(
                    "erroneous hint value {hint}"
                )));
            };

            let status = de.read_leb128_u64()?;
            let write_status = if 0 == status {
                AttributeStatus::DecryptOnly
            } else if 1 == status {
                AttributeStatus::EncryptDecrypt
            } else {
                return Err(Error::ConversionFailed(format!(
                    "erroneous status value {hint}"
                )));
            };

            Ok(Self {
                id,
                encryption_hint,
                write_status,
            })
        }
    }

    #[test]
    fn test_attribute_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let attribute = Attribute::new(EncryptionHint::Classic, 13);
        test_serialization(&attribute).unwrap();

        let attribute = Attribute::new(EncryptionHint::Hybridized, usize::MAX);
        test_serialization(&attribute).unwrap();
    }

    impl Serializable for Dimension {
        type Error = Error;

        fn length(&self) -> usize {
            let f = |attributes: Box<dyn Iterator<Item = (&String, &Attribute)>>| {
                attributes
                    .map(|(name, attribute)| {
                        let l = name.len();
                        to_leb128_len(l) + l + attribute.length()
                    })
                    .sum::<usize>()
            };
            1 + match self {
                Dimension::Anarchy(attributes) => {
                    to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
                }
                Dimension::Hierarchy(attributes) => {
                    to_leb128_len(attributes.len()) + f(Box::new(attributes.iter()))
                }
            }
        }

        fn write(
            &self,
            ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
        ) -> Result<usize, Self::Error> {
            let write_attributes =
                |mut attributes: Box<dyn Iterator<Item = (&String, &Attribute)>>,
                 ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer|
                 -> Result<usize, Error> {
                    attributes.try_fold(0, |mut n, (name, attribute)| {
                        n += ser.write_vec(name.as_bytes())?;
                        n += ser.write(attribute)?;
                        Ok(n)
                    })
                };

            let mut n = ser.write_leb128_u64(self.is_ordered() as u64)?;
            match self {
                Dimension::Anarchy(attributes) => {
                    n += ser.write_leb128_u64(attributes.len() as u64)?;
                    n += write_attributes(Box::new(attributes.iter()), ser)?;
                }
                Dimension::Hierarchy(attributes) => {
                    n += ser.write_leb128_u64(attributes.len() as u64)?;
                    n += write_attributes(Box::new(attributes.iter()), ser)?;
                }
            };

            Ok(n)
        }

        fn read(
            de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer,
        ) -> Result<Self, Self::Error> {
            let is_ordered = de.read_leb128_u64()?;
            let l = de.read_leb128_u64()?;
            let attributes = (0..l).map(|_| {
                let name = String::from_utf8(de.read_vec()?)
                    .map_err(|e| Error::ConversionFailed(e.to_string()))?;
                let attribute = de.read::<Attribute>()?;
                Ok::<_, Error>((name, attribute))
            });

            if 0 == is_ordered {
                attributes.collect::<Result<_, _>>().map(Self::Anarchy)
            } else if 1 == is_ordered {
                attributes.collect::<Result<_, _>>().map(Self::Hierarchy)
            } else {
                Err(Error::ConversionFailed(format!(
                    "invalid boolean value {is_ordered}"
                )))
            }
        }
    }

    #[test]
    fn test_dimension_serialization() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut d = Dimension::hierarchy_with_maximum(0);
        d.add_attribute("A".to_string(), EncryptionHint::Classic, None, 1)
            .unwrap();
        d.add_attribute("B".to_string(), EncryptionHint::Hybridized, Some("A"), 2)
            .unwrap();
        d.add_attribute("C".to_string(), EncryptionHint::Hybridized, Some("B"), 3)
            .unwrap();
        test_serialization(&d).unwrap();

        let mut d = Dimension::anarchy_with_maximum(0);
        d.add_attribute("A".to_string(), EncryptionHint::Classic, None, 1)
            .unwrap();
        d.add_attribute("B".to_string(), EncryptionHint::Hybridized, None, 2)
            .unwrap();
        d.add_attribute("C".to_string(), EncryptionHint::Hybridized, None, 3)
            .unwrap();
        test_serialization(&d).unwrap();
    }
}
