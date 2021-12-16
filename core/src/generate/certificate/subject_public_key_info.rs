use crate::generate::error::EncodingError;
use super::AlgorithmIdentifier;
use super::super::der::{BitString, DataType, ToDer};

pub struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

impl SubjectPublicKeyInfo {
    pub fn new(algorithm: AlgorithmIdentifier, subject_public_key: BitString) -> Self {
        Self {
            algorithm,
            subject_public_key,
        }
    }
}

impl ToDer for SubjectPublicKeyInfo {
    fn encode_inner(&self) -> Result<Vec<u8>, EncodingError> {
        let mut res = self.algorithm.to_der()?;
        res.extend_from_slice(&self.subject_public_key.to_der()?);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
