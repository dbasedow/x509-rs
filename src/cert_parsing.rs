use crate::{
    der::{
        expect_bit_string, expect_generalized_time, expect_integer, expect_object_identifier,
        expect_sequence, expect_set, expect_utc_time, take_any, try_get_explicit, Any, BitString,
        ExplicitTag, GeneralizedTime, Integer, ObjectIdentifier, UTCTime,
    },
    error::ParseError,
};
use std::collections::HashSet;

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
pub struct TBSCertificate<'a> {
    version: Version,
    serial_number: Integer<'a>,
    algorithm_identifier: Algorithmidentifier<'a>,
    issuer: Name<'a>,
    validity: Validity<'a>,
    subject: Name<'a>,
    subject_public_key_info: SubjectPublicKeyInfo<'a>,
    issuer_unique_id: Option<BitString<'a>>,
    subject_unique_id: Option<BitString<'a>>,
    extensions: Option<Extensions<'a>>,
}

#[derive(Debug)]
pub struct Certificate<'a> {
    tbs_cert: TBSCertificate<'a>,
    signature_algorithm: Algorithmidentifier<'a>,
    signature: BitString<'a>,
}

impl<'a> Certificate<'a> {
    pub fn from_slice(data: &'a [u8]) -> Result<Self, ParseError> {
        let (left, root) = expect_sequence(data)?;
        // the root sequence should take up all the space in the buffer
        expect_empty(left)?;

        let (data, tbs_data) = expect_sequence(root)?;
        let tbs_cert = parse_tbs(tbs_data)?;
        let (data, signature_algorithm) = parse_algorithm_identifier(data)?;
        let (data, signature) = expect_bit_string(data)?;
        expect_empty(data)?;

        let cert = Certificate {
            tbs_cert,
            signature_algorithm,
            signature,
        };

        Ok(cert)
    }
}

fn parse_tbs<'a>(data: &'a [u8]) -> Result<TBSCertificate<'a>, ParseError> {
    let (data, version) = parse_version(data)?;
    let (data, serial_number) = expect_integer(data)?;
    let (data, algorithm_identifier) = parse_algorithm_identifier(data)?;
    let (data, issuer) = Name::parse(data)?;
    let (data, validity) = Validity::parse(data)?;
    let (data, subject) = Name::parse(data)?;
    let (data, subject_public_key_info) = SubjectPublicKeyInfo::parse(data)?;
    let (data, issuer_unique_id) = parse_issuer_unique_id(data)?;
    let (data, subject_unique_id) = parse_subject_unique_id(data)?;
    let (data, extensions) = Extensions::parse(data)?;
    expect_empty(data)?;

    let tbs = TBSCertificate {
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
pub struct Algorithmidentifier<'a> {
    algorithm_identifier: ObjectIdentifier<'a>,
    parameters: Any<'a>,
}

fn parse_algorithm_identifier(data: &[u8]) -> Result<(&[u8], Algorithmidentifier), ParseError> {
    let (rest, inner) = expect_sequence(data)?;
    let (inner, algorithm_identifier) = expect_object_identifier(inner)?;
    let (inner, parameters) = take_any(inner)?;
    expect_empty(inner)?;
    Ok((
        rest,
        Algorithmidentifier {
            algorithm_identifier,
            parameters,
        },
    ))
}

#[derive(Debug, PartialEq, Eq, Hash)]
pub struct AttributeTypeAndValue<'a> {
    attribute_type: ObjectIdentifier<'a>,
    value: Any<'a>,
}

impl<'a> AttributeTypeAndValue<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, inner) = expect_sequence(data)?;
        let (inner, attribute_type) = expect_object_identifier(inner)?;
        let (inner, value) = take_any(inner)?;
        expect_empty(inner)?;
        let attribute_type_and_value = AttributeTypeAndValue {
            attribute_type,
            value,
        };
        Ok((rest, attribute_type_and_value))
    }
}

#[derive(Debug)]
pub struct RelativeDistinguishedName<'a> {
    key_value_pairs: HashSet<AttributeTypeAndValue<'a>>,
}

impl<'a> RelativeDistinguishedName<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, inner) = expect_set(data)?;
        let mut key_value_pairs = HashSet::new();

        loop {
            let (inner, kv) = AttributeTypeAndValue::parse(inner)?;
            key_value_pairs.insert(kv);
            if inner.is_empty() {
                break;
            }
        }
        if key_value_pairs.len() == 0 {
            // according to ASN.1 there has to be at least one element in the SET
            return Err(ParseError::InvalidLength);
        }
        let rdns = RelativeDistinguishedName { key_value_pairs };

        Ok((rest, rdns))
    }
}
#[derive(Debug)]
pub struct DistinguishedName<'a> {
    rdns: Vec<RelativeDistinguishedName<'a>>,
}

impl<'a> DistinguishedName<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, mut inner) = expect_sequence(data)?;
        let mut rdns = Vec::new();
        loop {
            if inner.is_empty() {
                break;
            }
            let (rest, rdn) = RelativeDistinguishedName::parse(inner)?;
            inner = rest;
            rdns.push(rdn);
        }
        let dn = DistinguishedName { rdns };
        Ok((rest, dn))
    }
}

#[derive(Debug)]
enum Name<'a> {
    DistinguishedName(DistinguishedName<'a>),
}

impl<'a> Name<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        // right now there is only one CHOICE
        let (rest, dn) = DistinguishedName::parse(data)?;
        Ok((rest, Self::DistinguishedName(dn)))
    }
}

#[derive(Debug)]
enum Time<'a> {
    UTCTime(UTCTime<'a>),
    GeneralizedTime(GeneralizedTime<'a>),
}

impl<'a> Time<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        if let Ok((rest, utc)) = expect_utc_time(data) {
            return Ok((rest, Time::UTCTime(utc)));
        }
        if let Ok((rest, generalized)) = expect_generalized_time(data) {
            return Ok((rest, Time::GeneralizedTime(generalized)));
        }

        Err(ParseError::MalformedData)
    }
}

#[derive(Debug)]
pub struct Validity<'a> {
    not_before: Time<'a>,
    not_after: Time<'a>,
}

impl<'a> Validity<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, not_before) = Time::parse(data)?;
        let (data, not_after) = Time::parse(data)?;
        expect_empty(data)?;
        let validity = Validity {
            not_after,
            not_before,
        };

        Ok((rest, validity))
    }
}

#[derive(Debug)]
struct SubjectPublicKeyInfo<'a> {
    algorithm: Algorithmidentifier<'a>,
    subject_public_key: BitString<'a>,
}

impl<'a> SubjectPublicKeyInfo<'a> {
    fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, algorithm) = parse_algorithm_identifier(data)?;
        let (data, subject_public_key) = expect_bit_string(data)?;
        expect_empty(data)?;
        let spki = SubjectPublicKeyInfo {
            algorithm,
            subject_public_key,
        };

        Ok((rest, spki))
    }
}

#[derive(Debug)]
pub struct Extensions<'a>(&'a [u8]);

impl<'a> Extensions<'a> {
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

struct Extension<'a> {
    extension_id: ObjectIdentifier<'a>,
    critical: bool,
    value: &'a [u8],
}

#[test]
fn test_cert() {
    use core::str::FromStr;

    let data = include_bytes!("../certs/test.crt");
    let r = Certificate::from_slice(data);
    assert!(r.is_ok());
    let cert = r.unwrap();
    assert_eq!(cert.tbs_cert.version, Version::V3);
    assert_eq!(
        cert.tbs_cert.serial_number.to_big_int(),
        num_bigint::BigInt::from_str("333504890676592408951587385614406537514249").unwrap()
    );
}
