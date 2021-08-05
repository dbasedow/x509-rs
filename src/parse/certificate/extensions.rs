use super::super::der::{
    expect_boolean, expect_object_identifier, expect_octet_string, expect_sequence,
    try_get_explicit, ExplicitTag, ObjectIdentifierRef, OctetStringRef,
};
use super::super::error::ParseError;
use super::expect_empty;

#[derive(Debug, Clone, Copy)]
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

impl<'a> IntoIterator for ExtensionsRef<'a> {
    type Item = Result<ExtensionRef<'a>, ParseError>;

    type IntoIter = ExtensionsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        ExtensionsIter::new(self.0)
    }
}

pub struct ExtensionsIter<'a> {
    pos: &'a [u8],
    failure: bool,
}

impl<'a> ExtensionsIter<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            pos: data,
            failure: false,
        }
    }
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

    pub fn extension_id(&self) -> &ObjectIdentifierRef<'a> {
        &self.extension_id
    }

    pub fn critical(&self) -> bool {
        self.critical
    }

    pub fn value(&self) -> &OctetStringRef<'a> {
        &self.value
    }
}

#[test]
fn test_extensions() {
    let data = include_bytes!("../../../certs/test.crt");
    let r = crate::parse::parsing::CertificateRef::from_slice(data);
    assert!(r.is_ok());
    let cert = r.unwrap();
    let tbs = cert.tbs_cert();
    let extensions = tbs.extensions().unwrap();
    let extensions: Vec<ExtensionRef> = extensions.into_iter().map(Result::unwrap).collect();
    assert_eq!(9, extensions.len());
}
