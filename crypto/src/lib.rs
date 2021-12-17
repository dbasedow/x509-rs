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

#[cfg(feature = "use-rust-crypto")]
mod rust_crypto;
#[cfg(feature = "use-rust-crypto")]
pub use rust_crypto::{check_signature, Error};

#[cfg(feature = "use-ring")]
mod ring;
#[cfg(feature = "use-ring")]
pub use crate::ring::{check_signature, Error};
