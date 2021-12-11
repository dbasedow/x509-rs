use super::{
    certificate::{
        expect_empty, parse_algorithm_identifier, parse_version, AlgorithmidentifierRef,
        ExtensionsRef, NameRef, SubjectPublicKeyInfoRef, ValidityRef,
    },
    der::{
        expect_bit_string, expect_integer, expect_sequence, try_get_explicit, BitStringRef,
        ExplicitTag, IntegerRef,
    },
    error::ParseError,
};
use crate::common::certificate::Version;

#[derive(Debug)]
pub struct TBSCertificateRef<'a> {
    raw_data: &'a [u8],

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

impl<'a> TBSCertificateRef<'a> {
    pub fn raw_data(&self) -> &[u8] {
        &self.raw_data
    }

    pub fn serial_number(&self) -> &IntegerRef {
        &self.serial_number
    }

    pub fn extensions(&self) -> Option<ExtensionsRef> {
        self.extensions
    }

    pub fn subject(&self) -> &NameRef {
        &self.subject
    }

    pub fn issuer(&self) -> &NameRef {
        &self.issuer
    }

    pub fn algorithm_identifier(&self) -> &AlgorithmidentifierRef {
        &self.algorithm_identifier
    }

    pub fn subject_public_key_info(&self) -> &SubjectPublicKeyInfoRef {
        &self.subject_public_key_info
    }
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

    pub fn tbs_cert(&self) -> &TBSCertificateRef<'a> {
        &self.tbs_cert
    }

    pub fn signature_algorithm(&self) -> &AlgorithmidentifierRef<'a> {
        &self.signature_algorithm
    }

    pub fn signature(&self) -> &BitStringRef<'a> {
        &self.signature
    }
}

pub(crate) fn expect_tbs<'a>(data: &'a [u8]) -> Result<(&[u8], TBSCertificateRef), ParseError> {
    let (rest, tbs_data) = expect_sequence(data)?;
    let size_of_raw_tbs = data.len() - rest.len();
    let raw_tbs = &data[..size_of_raw_tbs];
    let tbs_cert = parse_tbs(tbs_data, raw_tbs)?;
    Ok((rest, tbs_cert))
}

/// raw_data is the slice containing all of TBS including the sequence wrapper. this is what will be checked in signature verification
fn parse_tbs<'a>(data: &'a [u8], raw_data: &'a [u8]) -> Result<TBSCertificateRef<'a>, ParseError> {
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
        raw_data,

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

#[test]
fn test_cert() {
    use core::str::FromStr;

    let data = include_bytes!("../../certs/test.crt");
    let r = CertificateRef::from_slice(data);
    assert!(r.is_ok());
    let cert = r.unwrap();
    assert_eq!(cert.tbs_cert.version, Version::V3);
    assert_eq!(
        cert.tbs_cert.serial_number.to_big_int(),
        num_bigint::BigInt::from_str("333504890676592408951587385614406537514249").unwrap()
    );
}
