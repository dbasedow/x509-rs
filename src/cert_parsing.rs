use crate::{
    der::{
        expect_bit_string, expect_boolean, expect_generalized_time, expect_integer,
        expect_object_identifier, expect_octet_string, expect_sequence, expect_set,
        expect_utc_time, take_any, try_get_explicit, Any, BitString, ExplicitTag, GeneralizedTime,
        Integer, ObjectIdentifierRef, OctetString, UTCTime,
    },
    error::ParseError,
};
use std::fmt;

fn expect_empty(data: &[u8]) -> Result<(), ParseError> {
    if !data.is_empty() {
        return Err(ParseError::MalformedData);
    }

    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub enum Version {
    V1,
    V2,
    V3,
}

impl Version {
    fn try_from_i64(v: i64) -> Result<Self, ParseError> {
        match v {
            0 => Ok(Version::V1),
            1 => Ok(Version::V2),
            2 => Ok(Version::V3),
            _ => Err(ParseError::InvalidVersion),
        }
    }
}

#[derive(Debug)]
pub struct TBSCertificateRef<'a> {
    version: Version,
    serial_number: Integer<'a>,
    algorithm_identifier: AlgorithmidentifierRef<'a>,
    issuer: Name<'a>,
    validity: ValidityRef<'a>,
    subject: Name<'a>,
    subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    issuer_unique_id: Option<BitString<'a>>,
    subject_unique_id: Option<BitString<'a>>,
    extensions: Option<ExtensionsRef<'a>>,
}

#[derive(Debug)]
pub struct CertificateRef<'a> {
    tbs_cert: TBSCertificateRef<'a>,
    signature_algorithm: AlgorithmidentifierRef<'a>,
    signature: BitString<'a>,
}

impl<'a> CertificateRef<'a> {
    pub fn from_slice(data: &'a [u8]) -> Result<Self, ParseError> {
        let (left, root) = expect_sequence(data)?;
        // the root sequence should take up all the space in the buffer
        expect_empty(left)?;

        let (data, tbs_data) = expect_sequence(root)?;
        let tbs_cert = parse_tbs(tbs_data)?;
        let (data, signature_algorithm) = parse_algorithm_identifier(data)?;
        let (data, signature) = expect_bit_string(data)?;
        expect_empty(data)?;

        let cert = Self {
            tbs_cert,
            signature_algorithm,
            signature,
        };

        Ok(cert)
    }
}

fn parse_tbs<'a>(data: &'a [u8]) -> Result<TBSCertificateRef<'a>, ParseError> {
    let (data, version) = parse_version(data)?;
    let (data, serial_number) = expect_integer(data)?;
    let (data, algorithm_identifier) = parse_algorithm_identifier(data)?;
    let (data, issuer) = Name::parse(data)?;
    let (data, validity) = ValidityRef::parse(data)?;
    let (data, subject) = Name::parse(data)?;
    let (data, subject_public_key_info) = SubjectPublicKeyInfoRef::parse(data)?;
    let (data, issuer_unique_id) = parse_issuer_unique_id(data)?;
    let (data, subject_unique_id) = parse_subject_unique_id(data)?;
    let (data, extensions) = ExtensionsRef::parse(data)?;
    expect_empty(data)?;

    let tbs = TBSCertificateRef {
        version,
        serial_number,
        algorithm_identifier,
        issuer,
        validity,
        subject,
        subject_public_key_info,
        issuer_unique_id,
        subject_unique_id,
        extensions,
    };

    Ok(tbs)
}

fn parse_version(data: &[u8]) -> Result<(&[u8], Version), ParseError> {
    match try_get_explicit(data, ExplicitTag::try_new(0)?) {
        Ok((rest, inner)) => {
            let (inner, version) = expect_integer(inner)?;
            // the version integer should take up all the space in the buffer
            expect_empty(inner)?;
            Ok((rest, Version::try_from_i64(version.to_i64()?)?))
        }
        _ => Ok((data, Version::V1)),
    }
}

fn parse_issuer_unique_id<'a>(
    data: &'a [u8],
) -> Result<(&[u8], Option<BitString<'a>>), ParseError> {
    match try_get_explicit(data, ExplicitTag::try_new(1)?) {
        Ok((rest, inner)) => {
            let (inner, identifier) = expect_bit_string(inner)?;
            expect_empty(inner)?;
            Ok((rest, Some(identifier)))
        }
        _ => Ok((data, None)),
    }
}

fn parse_subject_unique_id<'a>(
    data: &'a [u8],
) -> Result<(&[u8], Option<BitString<'a>>), ParseError> {
    match try_get_explicit(data, ExplicitTag::try_new(2)?) {
        Ok((rest, inner)) => {
            let (inner, identifier) = expect_bit_string(inner)?;
            expect_empty(inner)?;
            Ok((rest, Some(identifier)))
        }
        _ => Ok((data, None)),
    }
}

#[derive(Debug)]
pub struct AlgorithmidentifierRef<'a> {
    algorithm_identifier: ObjectIdentifierRef<'a>,
    parameters: Any<'a>,
}

fn parse_algorithm_identifier(data: &[u8]) -> Result<(&[u8], AlgorithmidentifierRef), ParseError> {
    let (rest, inner) = expect_sequence(data)?;
    let (inner, algorithm_identifier) = expect_object_identifier(inner)?;
    let (inner, parameters) = take_any(inner)?;
    expect_empty(inner)?;
    Ok((
        rest,
        AlgorithmidentifierRef {
            algorithm_identifier,
            parameters,
        },
    ))
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AttributeTypeAndValueRef<'a> {
    attribute_type: ObjectIdentifierRef<'a>,
    value: Any<'a>,
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

#[derive(Debug)]
enum Name<'a> {
    DistinguishedNameRef(DistinguishedNameRef<'a>),
}

impl<'a> Name<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        // right now there is only one CHOICE
        let (rest, dn) = DistinguishedNameRef::parse(data)?;
        Ok((rest, Self::DistinguishedNameRef(dn)))
    }
}

#[derive(Debug)]
enum TimeRef<'a> {
    UTCTime(UTCTime<'a>),
    GeneralizedTime(GeneralizedTime<'a>),
}

impl<'a> TimeRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        if let Ok((rest, utc)) = expect_utc_time(data) {
            return Ok((rest, Self::UTCTime(utc)));
        }
        if let Ok((rest, generalized)) = expect_generalized_time(data) {
            return Ok((rest, Self::GeneralizedTime(generalized)));
        }

        Err(ParseError::MalformedData)
    }
}

#[derive(Debug)]
pub struct ValidityRef<'a> {
    not_before: TimeRef<'a>,
    not_after: TimeRef<'a>,
}

impl<'a> ValidityRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, not_before) = TimeRef::parse(data)?;
        let (data, not_after) = TimeRef::parse(data)?;
        expect_empty(data)?;
        let validity = Self {
            not_after,
            not_before,
        };

        Ok((rest, validity))
    }
}

#[derive(Debug)]
struct SubjectPublicKeyInfoRef<'a> {
    algorithm: AlgorithmidentifierRef<'a>,
    subject_public_key: BitString<'a>,
}

impl<'a> SubjectPublicKeyInfoRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, algorithm) = parse_algorithm_identifier(data)?;
        let (data, subject_public_key) = expect_bit_string(data)?;
        expect_empty(data)?;
        let spki = Self {
            algorithm,
            subject_public_key,
        };

        Ok((rest, spki))
    }
}

#[derive(Debug)]
pub struct ExtensionsRef<'a>(&'a [u8]);

impl<'a> ExtensionsRef<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Option<Self>), ParseError> {
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
    value: OctetString<'a>,
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

#[test]
fn test_cert() {
    use core::str::FromStr;

    let data = include_bytes!("../certs/test.crt");
    let r = CertificateRef::from_slice(data);
    assert!(r.is_ok());
    let cert = r.unwrap();
    assert_eq!(cert.tbs_cert.version, Version::V3);
    assert_eq!(
        cert.tbs_cert.serial_number.to_big_int(),
        num_bigint::BigInt::from_str("333504890676592408951587385614406537514249").unwrap()
    );
}
