use std::usize;

use super::expect_empty;
use crate::{
    der::{
        expect_boolean, expect_object_identifier, expect_octet_string, expect_sequence,
        try_get_explicit, Boolean, DataType, ExplicitTag, ObjectIdentifier, ObjectIdentifierRef,
        OctetString, OctetStringRef, ToDer,
    },
    error::ParseError,
};

#[derive(Debug)]
pub struct ExtensionsRef<'a>(&'a [u8]);

impl<'a> ExtensionsRef<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<(&'a [u8], Option<Self>), ParseError> {
        match try_get_explicit(data, ExplicitTag::try_new(3)?) {
            Ok((rest, inner)) => {
                let (inner, extensions) = expect_sequence(inner)?;
                expect_empty(inner)?;
                Ok((rest, Some(Self(extensions))))
            }
            _ => Ok((data, None)),
        }
    }
}

pub struct ExtensionsIter<'a> {
    pos: &'a [u8],
    failure: bool,
}

impl<'a> Iterator for ExtensionsIter<'a> {
    type Item = Result<ExtensionRef<'a>, ParseError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.is_empty() {
            return None;
        }
        if self.failure {
            //this iterator is in error state, continue returning ParseError
            return Some(Err(ParseError::MalformedData));
        }
        let result = ExtensionRef::parse(self.pos);
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

pub struct ExtensionRef<'a> {
    extension_id: ObjectIdentifierRef<'a>,
    critical: bool,
    value: OctetStringRef<'a>,
}

impl<'a> ExtensionRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, extension_id) = expect_object_identifier(data)?;
        let (data, critical) = if let Ok((data, critical)) = expect_boolean(data) {
            (data, critical.to_bool())
        } else {
            (data, false)
        };
        let (data, value) = expect_octet_string(data)?;
        expect_empty(data)?;
        let extension = Self {
            extension_id,
            critical,
            value,
        };
        Ok((rest, extension))
    }
}

pub struct Extension {
    extension_id: ObjectIdentifier,
    critical: Boolean,
    value: OctetString,
}

impl Extension {
    pub fn new(extension_id: ObjectIdentifier, critical: Boolean, value: OctetString) -> Self {
        Self {
            extension_id,
            critical,
            value,
        }
    }
}

impl ToDer for Extension {
    fn encode_inner(&self) -> Result<Vec<u8>, crate::error::EncodingError> {
        let mut res = self.extension_id.to_der()?;
        // CRICITAL is marked DEFAULT FALSE, so we only write it when it's true
        if self.critical.to_bool() {
            res.extend_from_slice(&self.critical.to_der()?);
        }
        res.extend_from_slice(&self.value.to_der()?);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}

#[derive(Default)]
pub struct Extensions(Vec<Extension>);

impl Extensions {
    pub fn add(&mut self, extension: Extension) {
        self.0.push(extension);
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl ToDer for Extensions {
    fn encode_inner(&self) -> Result<Vec<u8>, crate::error::EncodingError> {
        let mut res = Vec::new();
        for ext in self.0.iter() {
            res.extend_from_slice(&ext.to_der()?);
        }

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
