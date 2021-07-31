use super::{
    expect_empty, parse_algorithm_identifier, AlgorithmIdentifier, AlgorithmidentifierRef,
};
use crate::{
    der::{expect_bit_string, expect_sequence, BitString, BitStringRef, DataType, ToDer},
    error::ParseError,
};

#[derive(Debug)]
pub struct SubjectPublicKeyInfoRef<'a> {
    algorithm: AlgorithmidentifierRef<'a>,
    subject_public_key: BitStringRef<'a>,
}

impl<'a> SubjectPublicKeyInfoRef<'a> {
    pub(crate) fn parse(data: &'a [u8]) -> Result<(&'a [u8], Self), ParseError> {
        let (rest, data) = expect_sequence(data)?;
        let (data, algorithm) = parse_algorithm_identifier(data)?;
        let (data, subject_public_key) = expect_bit_string(data)?;
        expect_empty(data)?;
        let spki = Self {
            algorithm,
            subject_public_key,
        };

        Ok((rest, spki))
    }
}

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
    fn encode_inner(&self) -> Result<Vec<u8>, crate::error::EncodingError> {
        let mut res = self.algorithm.to_der()?;
        res.extend_from_slice(&self.subject_public_key.to_der()?);

        Ok(res)
    }

    fn get_tag(&self) -> u8 {
        DataType::Sequence.constructed()
    }
}
