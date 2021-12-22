use crate::{
    Algorithm, ECDSA_P256_OID, ECDSA_P384_OID, ECDSA_SHA256_OID, ECDSA_SHA384_OID, RSA_SHA1_OID,
    RSA_SHA256_OID, RSA_SHA384_OID, RSA_SHA512_OID,
};
use ring::{rand, signature};
use x509_core::parse::{
    der::{AnyRef, ObjectIdentifierRef},
    parsing::CertificateRef,
};

#[derive(Debug)]
pub enum Error {
    UnsupportedAlgorithm(String),
    UnsupportedPublicKey(String),
    VerifyFailed,
    InvalidPrivateKey,
    OOM,
}


fn oid_bytes_to_string(oid: &[u8]) -> String {
    ObjectIdentifierRef::new(oid).to_string()
}

pub fn check_signature(subject: &CertificateRef, issuer: &CertificateRef) -> Result<bool, Error> {
    let sig_algo = subject.signature_algorithm().algorithm_identifier();

    let pub_key = issuer.tbs_cert().subject_public_key_info();
    let raw_tbs = subject.tbs_cert().raw_data();
    let (_, signature) = subject.signature().data();

    match sig_algo.as_bytes() {
        RSA_SHA1_OID => {
            let (_, key_data) = pub_key.subject_public_key().data();
            let pub_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
                key_data,
            );
            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        RSA_SHA256_OID => {
            let (_, key_data) = pub_key.subject_public_key().data();
            let pub_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_1024_8192_SHA256_FOR_LEGACY_USE_ONLY,
                key_data,
            );
            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        RSA_SHA384_OID => {
            let (_, key_data) = pub_key.subject_public_key().data();
            let pub_key =
                signature::UnparsedPublicKey::new(&signature::RSA_PKCS1_2048_8192_SHA384, key_data);
            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        RSA_SHA512_OID => {
            let (_, key_data) = pub_key.subject_public_key().data();
            let pub_key = signature::UnparsedPublicKey::new(
                &signature::RSA_PKCS1_1024_8192_SHA512_FOR_LEGACY_USE_ONLY,
                key_data,
            );
            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        ECDSA_SHA256_OID => {
            let (_padding, key) = pub_key.subject_public_key().data();

            let pub_key = match pub_key.algorithm_identifier().parameters() {
                Some(AnyRef::ObjectIdentifier(oid)) if oid.as_bytes() == ECDSA_P256_OID => {
                    ring::signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key)
                }
                Some(AnyRef::ObjectIdentifier(oid)) if oid.as_bytes() == ECDSA_P384_OID => {
                    ring::signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA256_ASN1, key)
                }
                Some(AnyRef::ObjectIdentifier(oid)) => {
                    return Err(Error::UnsupportedPublicKey(oid_bytes_to_string(
                        oid.as_bytes(),
                    )));
                }
                p => unimplemented!("{:?}", p),
            };
            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        ECDSA_SHA384_OID => {
            let (_padding, key) = pub_key.subject_public_key().data();

            let pub_key = match pub_key.algorithm_identifier().parameters() {
                Some(AnyRef::ObjectIdentifier(oid)) if oid.as_bytes() == ECDSA_P384_OID => {
                    ring::signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, key)
                }
                Some(AnyRef::ObjectIdentifier(oid)) => {
                    return Err(Error::UnsupportedPublicKey(oid_bytes_to_string(
                        oid.as_bytes(),
                    )));
                }
                p => unimplemented!("{:?}", p),
            };

            match pub_key.verify(raw_tbs, signature) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false), // we don't know why the verify call failed. We assume it's due to a wrong signature
            }
        }
        oid => Err(Error::UnsupportedAlgorithm(oid_bytes_to_string(oid))),
    }
}

pub fn sign(tbs: &[u8], key_pair: signature::RsaKeyPair, algorithm: Algorithm) -> Result<Vec<u8>, Error> {
    match algorithm {
        Algorithm::RSA_SHA256 => {
            let rng = rand::SystemRandom::new();
            let mut signature = vec![0; key_pair.public_modulus_len()];
            key_pair
                .sign(&signature::RSA_PKCS1_SHA256, &rng, tbs, &mut signature)
                .map_err(|_| Error::OOM)?;
            Ok(signature)
        }
        algo => unimplemented!(),
    }
}
