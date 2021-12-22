mod algorithm_identifier;
mod extensions;
mod name;
mod subject_public_key_info;
mod validity;
mod version;

pub use algorithm_identifier::AlgorithmIdentifier;
pub use extensions::{Extension, Extensions};
pub use name::{AttributeTypeAndValue, DistinguishedName, Name, RelativeDistinguishedName};
pub use subject_public_key_info::SubjectPublicKeyInfo;
pub use validity::Validity;

use crate::parse::parsing::CertificateRef;

use super::{
    builder::TBSCertificate,
    der::{BitString, DataType, ToDer},
};

pub struct Certificate {
    tbs_cert: TBSCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature: BitString,
}

impl Certificate {
    pub fn new(
        tbs_cert: TBSCertificate,
        signature_algorithm: AlgorithmIdentifier,
        signature: BitString,
    ) -> Self {
        Self {
            tbs_cert,
            signature_algorithm,
            signature,
        }
    }
}

impl ToDer for Certificate {
    fn encode_inner(&self) -> Result<Vec<u8>, super::error::EncodingError> {
        let mut cert = Vec::new();
        cert.extend_from_slice(&self.tbs_cert.to_der()?);
        cert.extend_from_slice(&self.signature_algorithm.to_der()?);
        cert.extend_from_slice(&self.signature.to_der()?);

        Ok(cert)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
