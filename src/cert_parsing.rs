use crate::{
    certificate::{
        expect_empty, parse_algorithm_identifier, parse_version, AlgorithmidentifierRef, NameRef,
        SubjectPublicKeyInfoRef, ValidityRef, Version,
    },
    der::{
        expect_bit_string, expect_boolean, expect_integer, expect_object_identifier,
        expect_octet_string, expect_sequence, try_get_explicit, BitStringRef, ExplicitTag,
        IntegerRef, ObjectIdentifierRef, OctetStringRef,
    },
    error::ParseError,
};

#[derive(Debug)]
pub struct TBSCertificateRef<'a> {
    version: Version,
    serial_number: IntegerRef<'a>,
    algorithm_identifier: AlgorithmidentifierRef<'a>,
    issuer: NameRef<'a>,
    validity: ValidityRef<'a>,
    subject: NameRef<'a>,
    subject_public_key_info: SubjectPublicKeyInfoRef<'a>,
    issuer_unique_id: Option<BitStringRef<'a>>,
    subject_unique_id: Option<BitStringRef<'a>>,
    extensions: Option<ExtensionsRef<'a>>,
}

#[derive(Debug)]
pub struct CertificateRef<'a> {
    tbs_cert: TBSCertificateRef<'a>,
    signature_algorithm: AlgorithmidentifierRef<'a>,
    signature: BitStringRef<'a>,
}

impl<'a> CertificateRef<'a> {
    pub fn from_slice(data: &'a [u8]) -> Result<Self, ParseError> {
        let (left, root) = expect_sequence(data)?;
        // the root sequence should take up all the space in the buffer
        expect_empty(left)?;

        let (data, tbs_cert) = expect_tbs(root)?;
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

pub(crate) fn expect_tbs<'a>(data: &'a [u8]) -> Result<(&[u8], TBSCertificateRef), ParseError> {
    let (data, tbs_data) = expect_sequence(data)?;
    let tbs_cert = parse_tbs(tbs_data)?;
    Ok((data, tbs_cert))
}

fn parse_tbs<'a>(data: &'a [u8]) -> Result<TBSCertificateRef<'a>, ParseError> {
    let (data, version) = parse_version(data)?;
    let (data, serial_number) = expect_integer(data)?;
    let (data, algorithm_identifier) = parse_algorithm_identifier(data)?;
    let (data, issuer) = NameRef::parse(data)?;
    let (data, validity) = ValidityRef::parse(data)?;
    let (data, subject) = NameRef::parse(data)?;
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

fn parse_issuer_unique_id<'a>(
    data: &'a [u8],
) -> Result<(&[u8], Option<BitStringRef<'a>>), ParseError> {
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
) -> Result<(&[u8], Option<BitStringRef<'a>>), ParseError> {
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
