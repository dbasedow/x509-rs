use std::fmt;

use super::expect_empty;
use crate::{
    der::{
        expect_object_identifier, expect_sequence, expect_set, take_any, AnyRef, DataType,
        ObjectIdentifier, ObjectIdentifierRef, ToDer,
    },
    error::{EncodingError, ParseError},
};

#[derive(Debug)]
pub enum NameRef<'a> {
    DistinguishedNameRef(DistinguishedNameRef<'a>),
}

impl<'a> NameRef<'a> {
    pub fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        // right now there is only one CHOICE
        let (rest, dn) = DistinguishedNameRef::parse(data)?;
        Ok((rest, Self::DistinguishedNameRef(dn)))
    }
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AttributeTypeAndValueRef<'a> {
    attribute_type: ObjectIdentifierRef<'a>,
    value: AnyRef<'a>,
}

impl<'a> AttributeTypeAndValueRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, inner) = expect_sequence(data)?;
        let (inner, attribute_type) = expect_object_identifier(inner)?;
        let (inner, value) = take_any(inner)?;
        expect_empty(inner)?;
        let attribute_type_and_value = Self {
            attribute_type,
            value,
        };
        Ok((rest, attribute_type_and_value))
    }

    pub fn attribute_type(&self) -> &ObjectIdentifierRef<'a> {
        &self.attribute_type
    }
}

pub struct AttributeTypeAndValue {
    typ: ObjectIdentifier,
    value: Box<dyn ToDer>,
}

impl AttributeTypeAndValue {
    pub fn new(typ: ObjectIdentifier, value: Box<dyn ToDer>) -> Self {
        Self { typ, value }
    }
}

impl ToDer for AttributeTypeAndValue {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut inner = self.typ.to_der()?;
        inner.extend_from_slice(&self.value.to_der()?);

        Ok(inner)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.into()
    }
}

#[derive(Default)]
pub struct RelativeDistinguishedName {
    values: Vec<AttributeTypeAndValue>,
}

impl RelativeDistinguishedName {
    pub fn insert(&mut self, inner: AttributeTypeAndValue) {
        if self.values.len() > 0 {
            unimplemented!("this is not supported");
        }
        self.values.push(inner);
    }
}

impl ToDer for RelativeDistinguishedName {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        for value in self.values.iter() {
            res.extend_from_slice(&value.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Set.into()
    }
}

#[derive(Default)]
pub struct DistinguishedName(Vec<RelativeDistinguishedName>);

impl DistinguishedName {
    pub fn push(&mut self, rdn: RelativeDistinguishedName) {
        self.0.push(rdn);
    }
}

impl ToDer for DistinguishedName {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = Vec::new();
        for dn in self.0.iter() {
            res.extend_from_slice(&dn.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.into()
    }
}

pub enum Name {
    DistinguishedName(DistinguishedName),
}

impl ToDer for Name {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        match self {
            Name::DistinguishedName(dn) => dn.encode_inner(),
        }
    }

    fn get_tag(&self) -> u8 {
        match self {
            Name::DistinguishedName(dn) => dn.get_tag(),
        }
    }
}

pub struct RelativeDistinguishedNameRef<'a> {
    data: &'a [u8],
}

impl<'a> RelativeDistinguishedNameRef<'a> {
    pub fn iter(&self) -> RDNIter {
        RDNIter {
            pos: self.data,
            failure: false,
        }
    }
}

impl<'a> fmt::Debug for RelativeDistinguishedNameRef<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for attr in self.iter() {
            if let Ok(attr) = attr {
                write!(f, "{:?}", attr)?;
            } else {
                write!(f, "error in RDN")?;
            }
        }
        writeln!(f, "")
    }
}

pub struct RDNIter<'a> {
    pos: &'a [u8],
    failure: bool,
}

impl<'a> Iterator for RDNIter<'a> {
    type Item = Result<AttributeTypeAndValueRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.is_empty() {
            return None;
        }
        if self.failure {
            //this iterator is in error state, continue returning ParseError
            return Some(Err(ParseError::MalformedData));
        }
        let result = AttributeTypeAndValueRef::parse(self.pos);
        match result {
            Ok((rest, attribute)) => {
                self.pos = rest;
                Some(Ok(attribute))
            }
            Err(e) => {
                self.failure = true;
                Some(Err(e))
            }
        }
    }
}

impl<'a> RelativeDistinguishedNameRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_set(data)?;
        let rdns = RelativeDistinguishedNameRef { data };

        Ok((rest, rdns))
    }
}
#[derive(Debug)]
pub struct DistinguishedNameRef<'a> {
    data: &'a [u8],
}

impl<'a> DistinguishedNameRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        Ok((rest, Self { data }))
    }

    pub fn iter(&self) -> DNIter {
        DNIter {
            pos: self.data,
            failure: false,
        }
    }
}

pub struct DNIter<'a> {
    pos: &'a [u8],
    failure: bool,
}

impl<'a> Iterator for DNIter<'a> {
    type Item = Result<RelativeDistinguishedNameRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.is_empty() {
            return None;
        }
        if self.failure {
            //this iterator is in error state, continue returning ParseError
            return Some(Err(ParseError::MalformedData));
        }
        let result = RelativeDistinguishedNameRef::parse(self.pos);
        match result {
            Ok((rest, attribute)) => {
                self.pos = rest;
                Some(Ok(attribute))
            }
            Err(e) => {
                self.failure = true;
                Some(Err(e))
            }
        }
    }
}
