use std::{fs::File, io::Write};

use ::ring::signature::{self, KeyPair, RsaKeyPair};
use x509_core::{
    generate::{
        builder::TBSCertificate,
        certificate::{AlgorithmIdentifier, Certificate, SubjectPublicKeyInfo},
        der::{BitString, Data, Null, ToDer},
        error::EncodingError,
    },
    parse::{
        der::{ObjectIdentifier, ObjectIdentifierRef},
        parsing::CertificateRef,
    },
};
use x509_macros::oid_str_to_bytes;

const RSA_MD5_OID: &[u8] = oid_str_to_bytes!("1.2.840.113549.1.1.4");
const RSA_SHA1_OID: &[u8] = oid_str_to_bytes!("1.2.840.113549.1.1.5");
const RSA_SHA256_OID: &[u8] = oid_str_to_bytes!("1.2.840.113549.1.1.11");
const RSA_SHA384_OID: &[u8] = oid_str_to_bytes!("1.2.840.113549.1.1.12");
const RSA_SHA512_OID: &[u8] = oid_str_to_bytes!("1.2.840.113549.1.1.13");

const ECDSA_SHA256_OID: &[u8] = oid_str_to_bytes!("1.2.840.10045.4.3.2");
const ECDSA_SHA384_OID: &[u8] = oid_str_to_bytes!("1.2.840.10045.4.3.3");
const ECDSA_SHA512_OID: &[u8] = oid_str_to_bytes!("1.2.840.10045.4.3.4");

const ECDSA_P256_OID: &[u8] = oid_str_to_bytes!("1.2.840.10045.3.1.7");
const ECDSA_P384_OID: &[u8] = oid_str_to_bytes!("1.3.132.0.34");
const ECDSA_P521_OID: &[u8] = oid_str_to_bytes!("1.3.132.0.35");

// TODO: only include algorithms supported by underlying crypto lib to move some runtime errors to compile errors
#[derive(Clone, Copy)]
pub enum Algorithm {
    RSA_MD5,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,

    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,
}

pub struct UnsupportedAlgorithmError<'a>(&'a [u8]);

impl<'a> TryFrom<&'a [u8]> for Algorithm {
    type Error = UnsupportedAlgorithmError<'a>;

    fn try_from(oid: &'a [u8]) -> Result<Self, Self::Error> {
        match oid {
            RSA_SHA1_OID => Ok(Algorithm::RSA_SHA1),
            RSA_MD5_OID => Ok(Algorithm::RSA_MD5),
            RSA_SHA256_OID => Ok(Algorithm::RSA_SHA256),
            RSA_SHA384_OID => Ok(Algorithm::RSA_SHA384),
            RSA_SHA512_OID => Ok(Algorithm::RSA_SHA512),
            ECDSA_SHA256_OID => Ok(Algorithm::ECDSA_SHA256),
            ECDSA_SHA384_OID => Ok(Algorithm::ECDSA_SHA384),
            ECDSA_SHA512_OID => Ok(Algorithm::ECDSA_SHA512),
            oid => Err(UnsupportedAlgorithmError(oid)),
        }
    }
}

impl Into<&'static [u8]> for Algorithm {
    fn into(self) -> &'static [u8] {
        match self {
            Algorithm::RSA_MD5 => RSA_MD5_OID,
            Algorithm::RSA_SHA1 => RSA_SHA1_OID,
            Algorithm::RSA_SHA256 => RSA_SHA256_OID,
            Algorithm::RSA_SHA384 => RSA_SHA384_OID,
            Algorithm::RSA_SHA512 => RSA_SHA512_OID,
            Algorithm::ECDSA_SHA256 => ECDSA_SHA256_OID,
            Algorithm::ECDSA_SHA384 => ECDSA_SHA384_OID,
            Algorithm::ECDSA_SHA512 => ECDSA_SHA512_OID,
        }
    }
}

impl Into<AlgorithmIdentifier> for Algorithm {
    fn into(self) -> AlgorithmIdentifier {
        let oid: ObjectIdentifier = ObjectIdentifierRef::new(self.into()).into();

        AlgorithmIdentifier::new(oid, Data::Null(Null()))
    }
}

pub trait VerifySignature {
    fn verify_signature(&self, issuer: &CertificateRef) -> Result<bool, Error>;
}

impl<'a> VerifySignature for CertificateRef<'a> {
    fn verify_signature(&self, issuer: &CertificateRef) -> Result<bool, Error> {
        check_signature(self, issuer)
    }
}

pub trait SignCert {
    fn self_sign(
        self,
        algorithm: Algorithm,
        private_key: &[u8],
    ) -> Result<Certificate, SigningError>;
}

#[derive(Debug)]
pub enum SigningError {
    EncodingError(EncodingError),
    Signature(Error),
    InvalidPrivateKey,
}

impl SignCert for TBSCertificate {
    fn self_sign(
        mut self,
        algorithm: Algorithm,
        private_key: &[u8],
    ) -> Result<Certificate, SigningError> {
        let key_pair =
            RsaKeyPair::from_der(&private_key).map_err(|_| SigningError::InvalidPrivateKey)?;

        self.issuer = self.subject.clone();
        let algo_identifier: AlgorithmIdentifier = algorithm.into();
        // todo set parameters for algorithm if necessary
        self.signature = algo_identifier.clone();

        let public_key = key_pair.public_key().as_ref();
        let public_key = BitString::new(public_key.to_vec(), public_key.len() * 8);
        let rsa_pkcs1_fmt = ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
        let key_algo_id = AlgorithmIdentifier::new(rsa_pkcs1_fmt, Data::Null(Null()));
        let spki = SubjectPublicKeyInfo::new(key_algo_id.clone(), public_key); // todo fix algo identifier, were using the algo oid for the signature not the key
        self.subject_public_key_info = spki;

        let tbs = self
            .to_der()
            .map_err(|e| SigningError::EncodingError(e))?;

        let signature = sign(&tbs, key_pair, algorithm).map_err(|e| SigningError::Signature(e))?;

        let used_bits = signature.len() * 8;
        Ok(Certificate::new(
            self,
            algo_identifier,
            BitString::new(signature, used_bits),
        ))
    }
}

#[cfg(feature = "use-rust-crypto")]
mod rust_crypto;
#[cfg(feature = "use-rust-crypto")]
pub use rust_crypto::{check_signature, Error};

#[cfg(feature = "use-ring")]
mod ring;
#[cfg(feature = "use-ring")]
pub use crate::ring::{check_signature, sign, Error};

#[test]
fn test_tbs_cert_builder() {
    use x509_core::generate::der::Data;
    use x509_core::{
        generate::{
            builder::TBSCertificateBuilder,
            certificate::{
                AlgorithmIdentifier, AttributeTypeAndValue, DistinguishedName, Extension,
                Extensions, Name, RelativeDistinguishedName, SubjectPublicKeyInfo, Validity,
            },
            der::{BitString, Integer, Null, OctetString, ToDer, Utf8String},
        },
        parse::der::ObjectIdentifier,
    };

    let builder = TBSCertificateBuilder::default();
    //ISSUER
    let mut issuer_dn = DistinguishedName::default();
    let mut rdn_cn = RelativeDistinguishedName::default();
    rdn_cn.insert(AttributeTypeAndValue::new(
        ObjectIdentifier::from_str("3.4.5").unwrap(),
        Data::Utf8String(Utf8String::from_str("foo")),
    ));
    issuer_dn.push(rdn_cn);

    //VALIDITY
    let not_before = chrono::DateTime::parse_from_rfc3339("2021-07-31T12:33:53-00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let not_after = chrono::DateTime::parse_from_rfc3339("2022-07-31T12:33:53-00:00")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let validity = Validity::new(not_before, not_after);

    //SUBJECT
    let mut subject_dn = DistinguishedName::default();
    let mut rdn_cn = RelativeDistinguishedName::default();
    rdn_cn.insert(AttributeTypeAndValue::new(
        ObjectIdentifier::from_str("3.4.5").unwrap(),
        Data::Utf8String(Utf8String::from_str("bar")),
    ));
    subject_dn.push(rdn_cn);

    //SUBJECT PUBLIC KEY INFO
    let algo_id_rsa = ObjectIdentifier::from_str("1.2.840.113549.1.1.1").unwrap();
    let algorithm_identifier_subject_key =
        AlgorithmIdentifier::new(algo_id_rsa, Data::Null(Null()));
    let public_key = BitString::new(vec![20; 256], 2048);
    let sub_pub_key_info = SubjectPublicKeyInfo::new(algorithm_identifier_subject_key, public_key);

    //EXTENSION
    let mut extensions = Extensions::default();
    let extension = Extension::new(
        ObjectIdentifier::from_str("3.8.7").unwrap(),
        false.into(),
        OctetString::new(vec![3; 2]),
    );
    extensions.add(extension);

    let tbs = builder
        .serial_number(Integer::from_i64(10))
        .signature(AlgorithmIdentifier::new(
            ObjectIdentifier::from_str("1.2.3").unwrap(),
            Data::Null(Null()),
        ))
        .issuer(Name::DistinguishedName(issuer_dn.clone()))
        .validity(validity)
        .subject(Name::DistinguishedName(issuer_dn))
        .subject_public_key_info(sub_pub_key_info)
        .extensions(None)
        .build()
        .unwrap();

    let key_data = include_bytes!("../../test-key");

    let cert = tbs.self_sign(Algorithm::RSA_SHA256, key_data).unwrap();
    let cert_bytes = cert.to_der().unwrap();
    let cert = CertificateRef::from_slice(&cert_bytes).unwrap();

    let res = cert.verify_signature(&cert);
    assert!(res.is_ok());
    let signature_valid = res.unwrap();
    assert!(signature_valid);
}
