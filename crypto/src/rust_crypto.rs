use crate::{
    ECDSA_SHA256_OID, RSA_MD5_OID, RSA_SHA1_OID, RSA_SHA256_OID, RSA_SHA384_OID, RSA_SHA512_OID,
};
use p256::ecdsa::Signature;
use rsa::{pkcs1::FromRsaPublicKey, Hash, PublicKey, RsaPublicKey};
use sha2::Digest;
use x509_core::parse::{
    certificate::SubjectPublicKeyInfoRef, der::ObjectIdentifierRef, parsing::CertificateRef,
};

#[derive(Debug)]
pub enum Error {
    UnsupportedAlgorighm(String),
    Pkcs1(rsa::pkcs1::Error),
    Signature(ecdsa::signature::Error),
}

pub fn check_signature(subject: &CertificateRef, issuer: &CertificateRef) -> Result<bool, Error> {
    let sig_algo = subject.signature_algorithm().algorithm_identifier();

    let pub_key = issuer.tbs_cert().subject_public_key_info();
    let raw_tbs = subject.tbs_cert().raw_data();
    let (_, signature) = subject.signature().data();

    match sig_algo.as_bytes() {
        RSA_MD5_OID => validate_rsa(
            pub_key,
            Hash::MD5,
            &md5::Md5::digest(raw_tbs).to_vec(),
            signature,
        ),
        RSA_SHA1_OID => validate_rsa(
            pub_key,
            Hash::SHA1,
            &sha1::Sha1::digest(raw_tbs).to_vec(),
            signature,
        ),
        RSA_SHA256_OID => validate_rsa(
            pub_key,
            Hash::SHA2_256,
            &sha2::Sha256::digest(raw_tbs).to_vec(),
            signature,
        ),
        RSA_SHA384_OID => validate_rsa(
            pub_key,
            Hash::SHA2_384,
            &sha2::Sha384::digest(raw_tbs).to_vec(),
            signature,
        ),
        RSA_SHA512_OID => validate_rsa(
            pub_key,
            Hash::SHA2_512,
            &sha2::Sha512::digest(raw_tbs).to_vec(),
            signature,
        ),
        ECDSA_SHA256_OID => {
            use p256::ecdsa::signature::Verifier;

            let (_padding, key) = pub_key.subject_public_key().data();
            let sig = Signature::from_der(signature).map_err(|e| Error::Signature(e))?;
            let verify_key =
                p256::ecdsa::VerifyingKey::from_sec1_bytes(key).map_err(|e| Error::Signature(e))?;
            Ok(verify_key.verify(raw_tbs, &sig).is_ok())
        }
        s => Err(Error::UnsupportedAlgorighm(
            ObjectIdentifierRef::new(s).to_string(),
        )),
    }
}

fn validate_rsa(
    pub_key: &SubjectPublicKeyInfoRef,
    hash_method: Hash,
    hashed: &[u8],
    signature: &[u8],
) -> Result<bool, Error> {
    let (padding_bits, key_data) = pub_key.subject_public_key().data();
    assert!(padding_bits == 0);

    let public_key = RsaPublicKey::from_pkcs1_der(key_data).map_err(|e| Error::Pkcs1(e))?;

    if let Ok(_) = public_key.verify(
        rsa::PaddingScheme::new_pkcs1v15_sign(Some(hash_method)),
        hashed,
        signature,
    ) {
        Ok(true)
    } else {
        Ok(false)
    }
}
