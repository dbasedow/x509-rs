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

pub enum Algorithm {
    RSA_MD5,
    RSA_SHA1,
    RSA_SHA256,
    RSA_SHA384,
    RSA_SHA512,

    ECDSA_SHA256,
    ECDSA_SHA384,
    ECDSA_SHA512,

    ECDSA_P256,
    ECDSA_P384,
    ECDSA_P521,
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
            ECDSA_P256_OID => Ok(Algorithm::ECDSA_P256),
            ECDSA_P384_OID => Ok(Algorithm::ECDSA_P384),
            ECDSA_P521_OID => Ok(Algorithm::ECDSA_P521),
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
            Algorithm::ECDSA_P256 => ECDSA_P256_OID,
            Algorithm::ECDSA_P384 => ECDSA_P384_OID,
            Algorithm::ECDSA_P521 => ECDSA_P521_OID,
        }
    }
}

#[cfg(feature = "use-rust-crypto")]
mod rust_crypto;
#[cfg(feature = "use-rust-crypto")]
pub use rust_crypto::{check_signature, Error};

#[cfg(feature = "use-ring")]
mod ring;
#[cfg(feature = "use-ring")]
pub use crate::ring::{check_signature, Error};
